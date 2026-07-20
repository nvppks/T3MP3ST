import { randomUUID } from 'node:crypto';
import { evaluateProgramScope, normalizePath, type ProgramScope } from '../bounty/index.js';
import { redactString } from '../redact.js';
import {
  HarnessArtifactStore,
  type CreateHarnessEvidenceBundleInput,
  type PutHarnessArtifactInput,
  type ReadHarnessArtifactOptions,
} from './artifacts.js';
import {
  bodyBytes,
  boundedInteger,
  normalizeIdentifier,
  redactHeaders,
  safeDisplayUrl,
  sha256,
} from './helpers.js';
import {
  HarnessJobQueue,
  type CompleteHarnessJobInput,
  type EnqueueHarnessJobInput,
  type FailHarnessJobInput,
  type LeaseHarnessJobInput,
} from './job-queue.js';
import { cloneValue, HarnessStateRepository } from './state.js';
import type {
  HarnessArtifactMetadata,
  HarnessAuthCapsule,
  HarnessBundleMode,
  HarnessEvent,
  HarnessEvidenceBundle,
  HarnessGlobalState,
  HarnessJob,
  HarnessJobStatus,
  HarnessNormalizedRequest,
  HarnessProgram,
  HarnessSnapshot,
} from './types.js';

const DEFAULT_MAX_CONCURRENCY = 2;
const DEFAULT_MAX_RPS = 3;

export interface HarnessControlPlaneOptions {
  rootDir: string;
  maxArtifactBytes?: number;
  apiToken?: string;
  now?: () => number;
}

export interface UpsertHarnessProgramInput {
  id: string;
  label?: string;
  scope: ProgramScope;
  maxConcurrency?: number;
  maxRequestsPerSecond?: number;
}

export interface UpsertHarnessAuthCapsuleInput {
  id?: string;
  programId: string;
  owner: HarnessAuthCapsule['owner'];
  label: string;
  role: string;
  tenant?: string;
  expiresAt?: number;
  replayReference?: string;
}

export type PutControlPlaneArtifactInput = PutHarnessArtifactInput;

export interface IngestHarnessRequestInput {
  programId: string;
  source: HarnessNormalizedRequest['source'];
  method: string;
  url: string;
  headers?: Record<string, string | string[]>;
  bodyBase64?: string;
  authCapsuleId?: string;
  capturedAt?: number;
}

export interface CreateEvidenceBundleInput {
  programId: string;
  findingId: string;
  mode: HarnessBundleMode;
  reportMarkdown: string;
  artifactIds: string[];
}

export type {
  CompleteHarnessJobInput,
  EnqueueHarnessJobInput,
  FailHarnessJobInput,
  LeaseHarnessJobInput,
};

export class HarnessControlPlane {
  readonly rootDir: string;
  readonly statePath: string;
  readonly eventsPath: string;
  readonly apiTokenPath: string;
  readonly artifacts: HarnessArtifactStore;

  private constructor(
    private readonly repository: HarnessStateRepository,
    private readonly jobs: HarnessJobQueue,
    artifacts: HarnessArtifactStore,
  ) {
    this.rootDir = repository.rootDir;
    this.statePath = repository.statePath;
    this.eventsPath = repository.eventsPath;
    this.apiTokenPath = repository.apiTokenPath;
    this.artifacts = artifacts;
  }

  static async open(options: HarnessControlPlaneOptions): Promise<HarnessControlPlane> {
    const repository = await HarnessStateRepository.open({
      rootDir: options.rootDir,
      apiToken: options.apiToken,
      now: options.now,
    });
    try {
      const artifacts = new HarnessArtifactStore(options.rootDir, options.maxArtifactBytes);
      await artifacts.initialize();
      const jobs = new HarnessJobQueue(repository, artifacts);
      const plane = new HarnessControlPlane(repository, jobs, artifacts);
      await jobs.reclaimExpired();
      return plane;
    } catch (error) {
      await repository.close().catch(() => undefined);
      throw error;
    }
  }

  verifyApiToken(candidate: string | undefined): boolean {
    return this.repository.verifyApiToken(candidate);
  }

  close(): Promise<void> {
    return this.repository.close();
  }

  snapshot(): Promise<HarnessSnapshot> {
    return this.repository.snapshot();
  }

  readEvents(cursor = 0, limit = 200): Promise<{ events: HarnessEvent[]; nextCursor: number }> {
    return this.repository.readEvents(cursor, limit);
  }

  async upsertProgram(input: UpsertHarnessProgramInput): Promise<HarnessProgram> {
    const id = normalizeIdentifier(input.id, 'program id');
    if (!input.scope?.included?.length) throw new Error('program scope requires at least one included rule');
    const now = this.repository.now();
    return this.repository.mutate((state, emit) => {
      const existing = state.programs[id];
      const program: HarnessProgram = {
        id,
        label: input.label?.trim().slice(0, 200) || existing?.label || id,
        state: existing?.state ?? 'active',
        scope: { ...cloneValue(input.scope), program: id },
        maxConcurrency: boundedInteger(
          input.maxConcurrency,
          existing?.maxConcurrency ?? DEFAULT_MAX_CONCURRENCY,
          1,
          64,
        ),
        maxRequestsPerSecond: boundedInteger(
          input.maxRequestsPerSecond,
          existing?.maxRequestsPerSecond ?? DEFAULT_MAX_RPS,
          1,
          1_000,
        ),
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      state.programs[id] = program;
      state.rateBuckets[id] ??= {
        tokens: program.maxRequestsPerSecond,
        updatedAt: now,
      };
      emit('program.upserted', {
        programId: id,
        at: now,
        data: {
          state: program.state,
          maxConcurrency: program.maxConcurrency,
          maxRequestsPerSecond: program.maxRequestsPerSecond,
        },
      });
      return cloneValue(program);
    });
  }

  async listPrograms(): Promise<HarnessProgram[]> {
    const state = await this.repository.snapshot();
    return Object.values(state.programs)
      .sort((a, b) => a.id.localeCompare(b.id))
      .map((program) => cloneValue(program));
  }

  setProgramState(programId: string, next: HarnessProgram['state']): Promise<HarnessProgram> {
    return this.jobs.setProgramState(programId, next);
  }

  setGlobalState(next: HarnessGlobalState): Promise<HarnessGlobalState> {
    return this.jobs.setGlobalState(next);
  }

  async upsertAuthCapsule(input: UpsertHarnessAuthCapsuleInput): Promise<HarnessAuthCapsule> {
    const programId = normalizeIdentifier(input.programId, 'program id');
    const id = normalizeIdentifier(input.id ?? `auth_${randomUUID()}`, 'auth capsule id');
    if (!['burp', 'local-secret-store', 'external'].includes(input.owner)) {
      throw new Error(`invalid auth capsule owner: ${String(input.owner)}`);
    }
    const now = this.repository.now();
    return this.repository.mutate((state, emit) => {
      requireProgram(state, programId);
      const existing = state.authCapsules[id];
      if (existing && existing.programId !== programId) {
        throw new Error('auth capsule cannot move between programs');
      }
      const capsule: HarnessAuthCapsule = {
        id,
        programId,
        owner: input.owner,
        label: input.label.trim().slice(0, 200) || id,
        role: input.role.trim().slice(0, 100) || 'unknown',
        tenant: input.tenant?.trim().slice(0, 200) || undefined,
        expiresAt: input.expiresAt,
        replayReference: input.replayReference
          ? redactString(input.replayReference).trim().slice(0, 500) || undefined
          : undefined,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      state.authCapsules[id] = capsule;
      emit('auth-capsule.upserted', {
        programId,
        at: now,
        data: {
          capsuleId: id,
          owner: capsule.owner,
          role: capsule.role,
          tenant: capsule.tenant,
        },
      });
      return cloneValue(capsule);
    });
  }

  async putArtifact(input: PutControlPlaneArtifactInput): Promise<HarnessArtifactMetadata> {
    const programId = normalizeIdentifier(input.programId, 'program id');
    await this.assertProgramExists(programId);
    const metadata = await this.artifacts.put({ ...input, programId });
    return this.repository.mutate((state, emit) => {
      requireProgram(state, programId);
      const existing = state.artifacts[metadata.id];
      if (existing) return cloneValue(existing);
      state.artifacts[metadata.id] = metadata;
      emit('artifact.stored', {
        programId,
        at: metadata.createdAt,
        data: {
          artifactId: metadata.id,
          tier: metadata.tier,
          mediaType: metadata.mediaType,
          size: metadata.size,
          sha256: metadata.sha256,
        },
      });
      return cloneValue(metadata);
    });
  }

  async getArtifactMetadata(artifactId: string): Promise<HarnessArtifactMetadata> {
    const state = await this.repository.snapshot();
    const metadata = state.artifacts[artifactId];
    if (!metadata) throw new Error(`unknown artifact: ${artifactId}`);
    return cloneValue(metadata);
  }

  async readArtifact(
    artifactId: string,
    options: ReadHarnessArtifactOptions = {},
  ): Promise<Buffer> {
    const metadata = await this.getArtifactMetadata(artifactId);
    return this.artifacts.read(metadata, options);
  }

  async createEvidenceBundle(input: CreateEvidenceBundleInput): Promise<HarnessEvidenceBundle> {
    if (!['report-safe', 'operator-review', 'private-full'].includes(input.mode)) {
      throw new Error(`invalid evidence bundle mode: ${String(input.mode)}`);
    }
    const programId = normalizeIdentifier(input.programId, 'program id');
    const state = await this.repository.snapshot();
    requireProgram(state, programId);
    const artifacts = [...new Set(input.artifactIds)].map((id) => {
      const artifact = state.artifacts[id];
      if (!artifact) throw new Error(`unknown artifact: ${id}`);
      if (artifact.programId !== programId) throw new Error(`artifact belongs to another program: ${id}`);
      return artifact;
    });
    const bundleInput: CreateHarnessEvidenceBundleInput = {
      programId,
      findingId: input.findingId,
      mode: input.mode,
      reportMarkdown: input.reportMarkdown,
      artifacts,
      createdAt: this.repository.now(),
    };
    const bundle = await this.artifacts.createEvidenceBundle(bundleInput);
    return this.repository.mutate((current, emit) => {
      current.bundles[bundle.id] = bundle;
      emit('evidence-bundle.created', {
        programId,
        at: bundle.createdAt,
        data: {
          bundleId: bundle.id,
          findingId: bundle.findingId,
          mode: bundle.mode,
          includedArtifacts: bundle.entries.filter((entry) => entry.included).length,
        },
      });
      return cloneValue(bundle);
    });
  }

  async ingestRequest(input: IngestHarnessRequestInput): Promise<HarnessNormalizedRequest> {
    const programId = normalizeIdentifier(input.programId, 'program id');
    const method = input.method.trim().toUpperCase();
    if (!method) throw new Error('request method is required');
    if (!['burp', 'mitmproxy', 'openapi', 'manual', 'other'].includes(input.source)) {
      throw new Error(`invalid request source: ${String(input.source)}`);
    }
    const state = await this.repository.snapshot();
    const program = requireProgram(state, programId);
    const decision = evaluateProgramScope(program.scope, input.url, method);
    if (!decision.allowed) throw new Error(`scope denied: ${decision.reason}`);
    if (input.authCapsuleId) requireAuthCapsule(state, programId, input.authCapsuleId);

    const url = new URL(input.url);
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error('only HTTP(S) requests can be ingested');
    }
    const capturedAt = input.capturedAt ?? this.repository.now();
    const body = bodyBytes(input.bodyBase64);
    const rawEnvelope = {
      method,
      url: input.url,
      headers: input.headers ?? {},
      bodyBase64: input.bodyBase64 ?? '',
      capturedAt,
      source: input.source,
    };
    const reportEnvelope = {
      method,
      url: safeDisplayUrl(input.url),
      headers: redactHeaders(input.headers),
      bodySha256: sha256(body),
      bodySize: body.length,
      capturedAt,
      source: input.source,
    };

    const sealed = await this.artifacts.put({
      programId,
      content: `${JSON.stringify(rawEnvelope)}\n`,
      mediaType: 'application/json',
      tier: 'sealed',
      fileName: 'request.raw.json',
      source: 'normalized-request',
      createdAt: capturedAt,
    });
    const report = await this.artifacts.put({
      programId,
      content: `${JSON.stringify(reportEnvelope, null, 2)}\n`,
      mediaType: 'application/json',
      tier: 'report',
      fileName: 'request.report.json',
      source: 'normalized-request',
      createdAt: capturedAt,
    });

    const request: HarnessNormalizedRequest = {
      id: `req_${randomUUID()}`,
      programId,
      source: input.source,
      method,
      scheme: url.protocol === 'https:' ? 'https' : 'http',
      host: url.hostname.toLowerCase(),
      port: url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80,
      path: url.pathname || '/',
      pathTemplate: normalizePath(url.pathname || '/'),
      displayUrl: safeDisplayUrl(input.url),
      queryParameters: [...new Set(url.searchParams.keys())].sort(),
      bodySha256: sha256(body),
      authCapsuleId: input.authCapsuleId,
      sealedRequestArtifactId: sealed.id,
      reportRequestArtifactId: report.id,
      capturedAt,
    };

    return this.repository.mutate((current, emit) => {
      const currentProgram = requireProgram(current, programId);
      if (currentProgram.state === 'killed' || current.globalState === 'killed') {
        throw new Error('control plane or program was killed before request ingestion completed');
      }
      current.artifacts[sealed.id] ??= sealed;
      current.artifacts[report.id] ??= report;
      current.requests[request.id] = request;
      emit('request.ingested', {
        programId,
        at: capturedAt,
        data: {
          requestId: request.id,
          source: request.source,
          method: request.method,
          host: request.host,
          pathTemplate: request.pathTemplate,
          sealedArtifactId: sealed.id,
          reportArtifactId: report.id,
        },
      });
      return cloneValue(request);
    });
  }

  enqueueJob(input: EnqueueHarnessJobInput): Promise<HarnessJob> {
    return this.jobs.enqueue(input);
  }

  leaseNext(input: LeaseHarnessJobInput): Promise<HarnessJob | null> {
    return this.jobs.leaseNext(input);
  }

  markRunning(jobId: string, workerId: string, now?: number): Promise<HarnessJob> {
    return this.jobs.markRunning(jobId, workerId, now);
  }

  heartbeat(jobId: string, workerId: string, leaseMs?: number, now?: number): Promise<HarnessJob> {
    return this.jobs.heartbeat(jobId, workerId, leaseMs, now);
  }

  completeJob(input: CompleteHarnessJobInput): Promise<HarnessJob> {
    return this.jobs.complete(input);
  }

  failJob(input: FailHarnessJobInput): Promise<HarnessJob> {
    return this.jobs.fail(input);
  }

  releaseJob(jobId: string, workerId: string, delayMs?: number, now?: number): Promise<HarnessJob> {
    return this.jobs.release(jobId, workerId, delayMs, now);
  }

  pauseJob(jobId: string): Promise<HarnessJob> {
    return this.jobs.pause(jobId);
  }

  resumeJob(jobId: string): Promise<HarnessJob> {
    return this.jobs.resume(jobId);
  }

  killJob(jobId: string, reason?: string): Promise<HarnessJob> {
    return this.jobs.kill(jobId, reason);
  }

  registerAbortController(
    jobId: string,
    workerId: string,
    controller: AbortController,
  ): Promise<void> {
    return this.jobs.registerAbortController(jobId, workerId, controller);
  }

  getJob(jobId: string): Promise<HarnessJob> {
    return this.jobs.get(jobId);
  }

  listJobs(filter: { programId?: string; status?: HarnessJobStatus; kind?: string } = {}): Promise<HarnessJob[]> {
    return this.jobs.list(filter);
  }

  private async assertProgramExists(programId: string): Promise<void> {
    const state = await this.repository.snapshot();
    requireProgram(state, programId);
  }
}

function requireProgram(state: HarnessSnapshot, programId: string): HarnessProgram {
  const program = state.programs[programId];
  if (!program) throw new Error(`unknown program: ${programId}`);
  return program;
}

function requireAuthCapsule(
  state: HarnessSnapshot,
  programId: string,
  capsuleId: string,
): HarnessAuthCapsule {
  const capsule = state.authCapsules[capsuleId];
  if (!capsule) throw new Error(`unknown auth capsule: ${capsuleId}`);
  if (capsule.programId !== programId) throw new Error('auth capsule belongs to another program');
  return capsule;
}
