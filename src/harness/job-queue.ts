import { randomUUID } from 'node:crypto';
import { evaluateProgramScope } from '../bounty/index.js';
import { redactString } from '../redact.js';
import { HarnessArtifactStore } from './artifacts.js';
import {
  boundedInteger,
  containsInlineSecret,
  isTerminal,
  normalizeIdentifier,
  safeDisplayUrl,
} from './helpers.js';
import { cloneValue, type EmitHarnessEvent, HarnessStateRepository } from './state.js';
import type {
  HarnessArtifactMetadata,
  HarnessGlobalState,
  HarnessJob,
  HarnessJobStatus,
  HarnessProgram,
  HarnessSnapshot,
} from './types.js';

const DEFAULT_LEASE_MS = 30_000;
const MIN_LEASE_MS = 1_000;
const MAX_LEASE_MS = 15 * 60_000;
const DEFAULT_MAX_ATTEMPTS = 3;
const MAX_RESULT_SUMMARY = 4_000;

export interface EnqueueHarnessJobInput {
  programId: string;
  kind: string;
  target?: {
    url: string;
    method?: string;
  };
  requestId?: string;
  authCapsuleId?: string;
  payloadArtifactId?: string;
  config?: Record<string, unknown>;
  priority?: number;
  maxAttempts?: number;
  availableAt?: number;
}

export interface LeaseHarnessJobInput {
  workerId: string;
  kinds?: string[];
  leaseMs?: number;
  now?: number;
}

export interface CompleteHarnessJobInput {
  jobId: string;
  workerId: string;
  resultArtifactIds?: string[];
  resultSummary?: string;
  now?: number;
}

export interface FailHarnessJobInput {
  jobId: string;
  workerId: string;
  error: string;
  retryable?: boolean;
  retryDelayMs?: number;
  now?: number;
}

export class HarnessJobQueue {
  private readonly abortControllers = new Map<string, AbortController>();

  constructor(
    private readonly repository: HarnessStateRepository,
    private readonly artifacts: HarnessArtifactStore,
  ) {}

  async reclaimExpired(now = this.repository.now()): Promise<void> {
    await this.repository.mutate((state, emit) => {
      this.reclaimExpiredLeases(state, emit, now);
    });
  }

  async setProgramState(programId: string, next: HarnessProgram['state']): Promise<HarnessProgram> {
    const id = normalizeIdentifier(programId, 'program id');
    const now = this.repository.now();
    return this.repository.mutate((state, emit) => {
      const program = requireProgram(state, id);
      program.state = next;
      program.updatedAt = now;
      if (next === 'killed') {
        for (const job of Object.values(state.jobs)) {
          if (job.programId === id && !isTerminal(job.status)) {
            this.markKilled(job, now, 'program killed');
            emit('job.killed', {
              programId: id,
              jobId: job.id,
              at: now,
              data: { reason: 'program killed' },
            });
          }
        }
        this.abortMatching((job) => job.programId === id, state, 'program killed');
      }
      emit(`program.${next}`, { programId: id, at: now });
      return cloneValue(program);
    });
  }

  async setGlobalState(next: HarnessGlobalState): Promise<HarnessGlobalState> {
    const now = this.repository.now();
    return this.repository.mutate((state, emit) => {
      state.globalState = next;
      if (next === 'killed') {
        for (const job of Object.values(state.jobs)) {
          if (!isTerminal(job.status)) {
            this.markKilled(job, now, 'global kill switch');
            emit('job.killed', {
              programId: job.programId,
              jobId: job.id,
              at: now,
              data: { reason: 'global kill switch' },
            });
          }
        }
        this.abortMatching(() => true, state, 'global kill switch');
      }
      emit(`control.${next}`, { at: now });
      return state.globalState;
    });
  }

  async enqueue(input: EnqueueHarnessJobInput): Promise<HarnessJob> {
    const programId = normalizeIdentifier(input.programId, 'program id');
    const kind = normalizeIdentifier(input.kind, 'job kind');
    const config = cloneValue(input.config ?? {});
    const inlineSecret = containsInlineSecret(config);
    const serializedConfig = JSON.stringify(config);
    if (inlineSecret) {
      throw new Error(`inline secret-like value at ${inlineSecret}; use an auth capsule or sealed artifact reference`);
    }
    if (redactString(serializedConfig) !== serializedConfig) {
      throw new Error('job config contains credential material; use an auth capsule or sealed artifact reference');
    }

    const snapshot = await this.repository.snapshot();
    const program = requireProgram(snapshot, programId);
    if (snapshot.globalState === 'killed') throw new Error('global control plane is killed');
    if (program.state === 'killed') throw new Error(`program is killed: ${programId}`);
    if (input.requestId) requireRequest(snapshot, programId, input.requestId);
    if (input.authCapsuleId) requireAuthCapsule(snapshot, programId, input.authCapsuleId);
    if (input.payloadArtifactId) requireArtifact(snapshot, programId, input.payloadArtifactId);

    let targetMetadata: HarnessArtifactMetadata | undefined;
    let target: HarnessJob['target'];
    if (input.target) {
      const method = (input.target.method ?? 'GET').trim().toUpperCase();
      const decision = evaluateProgramScope(program.scope, input.target.url, method);
      if (!decision.allowed) throw new Error(`scope denied: ${decision.reason}`);
      targetMetadata = await this.artifacts.put({
        programId,
        content: `${input.target.url}\n`,
        mediaType: 'text/uri-list',
        tier: 'sealed',
        fileName: 'job-target.txt',
        source: 'job-target',
      });
      target = {
        displayUrl: safeDisplayUrl(input.target.url),
        method,
        sealedUrlArtifactId: targetMetadata.id,
      };
    }

    const now = this.repository.now();
    const job: HarnessJob = {
      id: `job_${randomUUID()}`,
      programId,
      kind,
      status: 'queued',
      target,
      requestId: input.requestId,
      authCapsuleId: input.authCapsuleId,
      payloadArtifactId: input.payloadArtifactId,
      config,
      priority: boundedInteger(input.priority, 0, -100, 100),
      attempts: 0,
      maxAttempts: boundedInteger(input.maxAttempts, DEFAULT_MAX_ATTEMPTS, 1, 20),
      availableAt: Math.max(now, input.availableAt ?? now),
      resultArtifactIds: [],
      createdAt: now,
      updatedAt: now,
    };

    return this.repository.mutate((state, emit) => {
      const currentProgram = requireProgram(state, programId);
      if (state.globalState === 'killed' || currentProgram.state === 'killed') {
        throw new Error('control plane or program was killed before enqueue completed');
      }
      if (targetMetadata) state.artifacts[targetMetadata.id] ??= targetMetadata;
      state.jobs[job.id] = job;
      emit('job.enqueued', {
        programId,
        jobId: job.id,
        at: now,
        data: {
          kind,
          priority: job.priority,
          availableAt: job.availableAt,
          requestId: job.requestId,
          target: job.target?.displayUrl,
        },
      });
      return cloneValue(job);
    });
  }

  async leaseNext(input: LeaseHarnessJobInput): Promise<HarnessJob | null> {
    const workerId = normalizeIdentifier(input.workerId, 'worker id');
    const leaseMs = boundedInteger(input.leaseMs, DEFAULT_LEASE_MS, MIN_LEASE_MS, MAX_LEASE_MS);
    const now = input.now ?? this.repository.now();
    const kinds = input.kinds?.length
      ? new Set(input.kinds.map((kind) => normalizeIdentifier(kind, 'job kind')))
      : undefined;

    return this.repository.mutate((state, emit) => {
      this.reclaimExpiredLeases(state, emit, now);
      if (state.globalState !== 'active') return null;

      const activeByProgram = new Map<string, number>();
      for (const job of Object.values(state.jobs)) {
        if (job.status === 'leased' || job.status === 'running') {
          activeByProgram.set(job.programId, (activeByProgram.get(job.programId) ?? 0) + 1);
        }
      }

      const candidates = Object.values(state.jobs)
        .filter((job) => job.status === 'queued' && job.availableAt <= now)
        .filter((job) => !kinds || kinds.has(job.kind))
        .sort((a, b) => b.priority - a.priority || a.availableAt - b.availableAt || a.createdAt - b.createdAt);

      for (const job of candidates) {
        const program = state.programs[job.programId];
        if (!program || program.state !== 'active') continue;
        if ((activeByProgram.get(program.id) ?? 0) >= program.maxConcurrency) continue;
        if (!consumeRateToken(state, program, now)) continue;

        job.status = 'leased';
        job.attempts += 1;
        job.updatedAt = now;
        job.lease = {
          workerId,
          leasedAt: now,
          heartbeatAt: now,
          expiresAt: now + leaseMs,
        };
        emit('job.leased', {
          programId: job.programId,
          jobId: job.id,
          at: now,
          data: {
            workerId,
            attempt: job.attempts,
            leaseExpiresAt: job.lease.expiresAt,
          },
        });
        return cloneValue(job);
      }
      return null;
    });
  }

  async markRunning(jobId: string, workerId: string, now = this.repository.now()): Promise<HarnessJob> {
    return this.repository.mutate((state, emit) => {
      const job = requireWorkerLease(state, jobId, workerId);
      if (job.status !== 'leased' && job.status !== 'running') {
        throw new Error(`job cannot enter running state from ${job.status}`);
      }
      job.status = 'running';
      job.updatedAt = now;
      emit('job.running', { programId: job.programId, jobId, at: now, data: { workerId } });
      return cloneValue(job);
    });
  }

  async heartbeat(
    jobId: string,
    workerId: string,
    leaseMs = DEFAULT_LEASE_MS,
    now = this.repository.now(),
  ): Promise<HarnessJob> {
    const boundedLease = boundedInteger(leaseMs, DEFAULT_LEASE_MS, MIN_LEASE_MS, MAX_LEASE_MS);
    return this.repository.mutate((state, emit) => {
      const job = requireWorkerLease(state, jobId, workerId);
      if (job.status !== 'leased' && job.status !== 'running') {
        throw new Error(`job cannot heartbeat from ${job.status}`);
      }
      if (!job.lease) throw new Error('job has no active lease');
      job.lease.heartbeatAt = now;
      job.lease.expiresAt = now + boundedLease;
      job.updatedAt = now;
      emit('job.heartbeat', {
        programId: job.programId,
        jobId,
        at: now,
        data: { workerId, leaseExpiresAt: job.lease.expiresAt },
      });
      return cloneValue(job);
    });
  }

  async complete(input: CompleteHarnessJobInput): Promise<HarnessJob> {
    const now = input.now ?? this.repository.now();
    return this.repository.mutate((state, emit) => {
      const job = requireWorkerLease(state, input.jobId, input.workerId);
      for (const artifactId of input.resultArtifactIds ?? []) {
        requireArtifact(state, job.programId, artifactId);
      }
      job.status = 'completed';
      job.lease = undefined;
      job.resultArtifactIds = [...new Set(input.resultArtifactIds ?? [])];
      job.resultSummary = input.resultSummary
        ? redactString(input.resultSummary).slice(0, MAX_RESULT_SUMMARY)
        : undefined;
      job.completedAt = now;
      job.updatedAt = now;
      this.abortControllers.delete(job.id);
      emit('job.completed', {
        programId: job.programId,
        jobId: job.id,
        at: now,
        data: { workerId: input.workerId, resultArtifactIds: job.resultArtifactIds },
      });
      return cloneValue(job);
    });
  }

  async fail(input: FailHarnessJobInput): Promise<HarnessJob> {
    const now = input.now ?? this.repository.now();
    return this.repository.mutate((state, emit) => {
      const job = requireWorkerLease(state, input.jobId, input.workerId);
      const retryable = input.retryable === true && job.attempts < job.maxAttempts;
      job.error = redactString(input.error).slice(0, MAX_RESULT_SUMMARY);
      job.lease = undefined;
      job.updatedAt = now;
      this.abortControllers.delete(job.id);
      if (retryable) {
        const delay = boundedInteger(input.retryDelayMs, 1_000, 0, 10 * 60_000);
        job.status = 'queued';
        job.availableAt = now + delay;
        emit('job.retry-scheduled', {
          programId: job.programId,
          jobId: job.id,
          at: now,
          data: { workerId: input.workerId, availableAt: job.availableAt, attempt: job.attempts },
        });
      } else {
        job.status = 'failed';
        job.completedAt = now;
        emit('job.failed', {
          programId: job.programId,
          jobId: job.id,
          at: now,
          data: { workerId: input.workerId, attempt: job.attempts, error: job.error },
        });
      }
      return cloneValue(job);
    });
  }

  async release(
    jobId: string,
    workerId: string,
    delayMs = 0,
    now = this.repository.now(),
  ): Promise<HarnessJob> {
    return this.repository.mutate((state, emit) => {
      const job = requireWorkerLease(state, jobId, workerId);
      job.status = 'queued';
      job.lease = undefined;
      job.availableAt = now + boundedInteger(delayMs, 0, 0, 10 * 60_000);
      job.updatedAt = now;
      this.abortControllers.delete(job.id);
      emit('job.released', {
        programId: job.programId,
        jobId,
        at: now,
        data: { workerId, availableAt: job.availableAt },
      });
      return cloneValue(job);
    });
  }

  async pause(jobId: string): Promise<HarnessJob> {
    const now = this.repository.now();
    return this.repository.mutate((state, emit) => {
      const job = requireJob(state, jobId);
      if (isTerminal(job.status)) throw new Error(`terminal job cannot be paused: ${job.status}`);
      job.status = 'paused';
      job.lease = undefined;
      job.updatedAt = now;
      this.abortControllers.get(job.id)?.abort(new Error('job paused'));
      this.abortControllers.delete(job.id);
      emit('job.paused', { programId: job.programId, jobId, at: now });
      return cloneValue(job);
    });
  }

  async resume(jobId: string): Promise<HarnessJob> {
    const now = this.repository.now();
    return this.repository.mutate((state, emit) => {
      const job = requireJob(state, jobId);
      if (job.status !== 'paused') throw new Error(`job is not paused: ${job.status}`);
      const program = requireProgram(state, job.programId);
      if (program.state === 'killed' || state.globalState === 'killed') {
        throw new Error('killed program or control plane must be reactivated before resuming jobs');
      }
      job.status = 'queued';
      job.availableAt = now;
      job.updatedAt = now;
      emit('job.resumed', { programId: job.programId, jobId, at: now });
      return cloneValue(job);
    });
  }

  async kill(jobId: string, reason = 'operator kill'): Promise<HarnessJob> {
    const now = this.repository.now();
    return this.repository.mutate((state, emit) => {
      const job = requireJob(state, jobId);
      if (job.status === 'completed' || job.status === 'failed') {
        throw new Error(`terminal job cannot be killed: ${job.status}`);
      }
      if (job.status !== 'killed') this.markKilled(job, now, reason);
      this.abortControllers.get(job.id)?.abort(new Error(reason));
      this.abortControllers.delete(job.id);
      emit('job.killed', {
        programId: job.programId,
        jobId,
        at: now,
        data: { reason: redactString(reason).slice(0, 500) },
      });
      return cloneValue(job);
    });
  }

  async registerAbortController(
    jobId: string,
    workerId: string,
    controller: AbortController,
  ): Promise<void> {
    await this.repository.mutate((state, emit) => {
      const job = requireWorkerLease(state, jobId, workerId);
      if (job.status !== 'leased' && job.status !== 'running') {
        throw new Error(`cannot register cancellation for ${job.status} job`);
      }
      this.abortControllers.set(jobId, controller);
      emit('job.cancellation-registered', {
        programId: job.programId,
        jobId,
        data: { workerId },
      });
    });
  }

  async get(jobId: string): Promise<HarnessJob> {
    const state = await this.repository.snapshot();
    return cloneValue(requireJob(state, jobId));
  }

  async list(filter: { programId?: string; status?: HarnessJobStatus; kind?: string } = {}): Promise<HarnessJob[]> {
    const state = await this.repository.snapshot();
    return Object.values(state.jobs)
      .filter((job) => !filter.programId || job.programId === filter.programId)
      .filter((job) => !filter.status || job.status === filter.status)
      .filter((job) => !filter.kind || job.kind === filter.kind)
      .sort((a, b) => b.createdAt - a.createdAt)
      .map((job) => cloneValue(job));
  }

  private reclaimExpiredLeases(
    state: HarnessSnapshot,
    emit: EmitHarnessEvent,
    now: number,
  ): void {
    for (const job of Object.values(state.jobs)) {
      if ((job.status !== 'leased' && job.status !== 'running') || !job.lease) continue;
      if (job.lease.expiresAt > now) continue;

      const workerId = job.lease.workerId;
      this.abortControllers.get(job.id)?.abort(new Error('job lease expired'));
      this.abortControllers.delete(job.id);
      job.lease = undefined;
      job.updatedAt = now;
      const program = state.programs[job.programId];
      if (state.globalState === 'killed' || program?.state === 'killed') {
        this.markKilled(job, now, 'lease expired after kill switch');
        emit('job.killed', {
          programId: job.programId,
          jobId: job.id,
          at: now,
          data: { reason: 'lease expired after kill switch' },
        });
      } else if (job.attempts < job.maxAttempts) {
        job.status = 'queued';
        job.availableAt = now + Math.min(30_000, 1_000 * 2 ** Math.max(0, job.attempts - 1));
        emit('job.lease-expired', {
          programId: job.programId,
          jobId: job.id,
          at: now,
          data: { workerId, requeued: true, availableAt: job.availableAt },
        });
      } else {
        job.status = 'failed';
        job.error = 'lease expired and max attempts were exhausted';
        job.completedAt = now;
        emit('job.lease-expired', {
          programId: job.programId,
          jobId: job.id,
          at: now,
          data: { workerId, requeued: false },
        });
      }
    }
  }

  private markKilled(job: HarnessJob, now: number, reason: string): void {
    job.status = 'killed';
    job.lease = undefined;
    job.error = redactString(reason).slice(0, 500);
    job.killedAt = now;
    job.completedAt = now;
    job.updatedAt = now;
  }

  private abortMatching(
    predicate: (job: HarnessJob) => boolean,
    state: HarnessSnapshot,
    reason: string,
  ): void {
    for (const [jobId, controller] of this.abortControllers) {
      const job = state.jobs[jobId];
      if (job && predicate(job)) {
        controller.abort(new Error(reason));
        this.abortControllers.delete(jobId);
      }
    }
  }
}

function consumeRateToken(state: HarnessSnapshot, program: HarnessProgram, now: number): boolean {
  const capacity = program.maxRequestsPerSecond;
  const current = state.rateBuckets[program.id] ?? { tokens: capacity, updatedAt: now };
  const elapsedSeconds = Math.max(0, now - current.updatedAt) / 1_000;
  current.tokens = Math.min(capacity, current.tokens + elapsedSeconds * capacity);
  current.updatedAt = now;
  if (current.tokens < 1) {
    state.rateBuckets[program.id] = current;
    return false;
  }
  current.tokens -= 1;
  state.rateBuckets[program.id] = current;
  return true;
}

function requireProgram(state: HarnessSnapshot, programId: string): HarnessProgram {
  const program = state.programs[programId];
  if (!program) throw new Error(`unknown program: ${programId}`);
  return program;
}

function requireAuthCapsule(state: HarnessSnapshot, programId: string, capsuleId: string): void {
  const capsule = state.authCapsules[capsuleId];
  if (!capsule) throw new Error(`unknown auth capsule: ${capsuleId}`);
  if (capsule.programId !== programId) throw new Error('auth capsule belongs to another program');
}

function requireArtifact(
  state: HarnessSnapshot,
  programId: string,
  artifactId: string,
): HarnessArtifactMetadata {
  const artifact = state.artifacts[artifactId];
  if (!artifact) throw new Error(`unknown artifact: ${artifactId}`);
  if (artifact.programId !== programId) throw new Error('artifact belongs to another program');
  return artifact;
}

function requireRequest(state: HarnessSnapshot, programId: string, requestId: string): void {
  const request = state.requests[requestId];
  if (!request) throw new Error(`unknown request: ${requestId}`);
  if (request.programId !== programId) throw new Error('request belongs to another program');
}

function requireJob(state: HarnessSnapshot, jobId: string): HarnessJob {
  const job = state.jobs[jobId];
  if (!job) throw new Error(`unknown job: ${jobId}`);
  return job;
}

function requireWorkerLease(state: HarnessSnapshot, jobId: string, workerId: string): HarnessJob {
  const job = requireJob(state, jobId);
  if (!job.lease || job.lease.workerId !== workerId) {
    throw new Error(`job is not leased by worker ${workerId}`);
  }
  return job;
}
