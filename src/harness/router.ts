import express, {
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from 'express';
import { redactString } from '../redact.js';
import {
  HarnessControlPlane,
  type CompleteHarnessJobInput,
  type CreateEvidenceBundleInput,
  type EnqueueHarnessJobInput,
  type FailHarnessJobInput,
  type IngestHarnessRequestInput,
  type LeaseHarnessJobInput,
  type PutControlPlaneArtifactInput,
  type UpsertHarnessAuthCapsuleInput,
  type UpsertHarnessProgramInput,
} from './control-plane.js';
import type { HarnessJobStatus } from './types.js';

const JOB_STATUSES = new Set<HarnessJobStatus>([
  'queued',
  'leased',
  'running',
  'completed',
  'failed',
  'paused',
  'killed',
]);

function bearerToken(req: Request): string | undefined {
  const value = req.get('authorization');
  const match = value?.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim();
}

function sendError(res: Response, error: unknown): void {
  const message = redactString(error instanceof Error ? error.message : String(error));
  const status = /unknown|not found/i.test(message) ? 404
    : /authorization|token|required|confirm/i.test(message) ? 403
      : /scope denied|invalid|cannot|must|belongs|disabled|killed|paused/i.test(message) ? 400
        : 500;
  res.status(status).json({ ok: false, error: message });
}

function asyncRoute(
  handler: (req: Request, res: Response) => Promise<void>,
): RequestHandler {
  return (req, res) => {
    void handler(req, res).catch((error) => sendError(res, error));
  };
}

function requireConfirmation(body: unknown, expected: string): void {
  const value = body && typeof body === 'object'
    ? (body as Record<string, unknown>).confirm
    : undefined;
  if (value !== expected) throw new Error(`confirm must equal ${expected}`);
}

function parseStatus(value: unknown): HarnessJobStatus | undefined {
  if (typeof value !== 'string' || !value) return undefined;
  if (!JOB_STATUSES.has(value as HarnessJobStatus)) throw new Error(`invalid job status: ${value}`);
  return value as HarnessJobStatus;
}

export function createHarnessRouter(plane: HarnessControlPlane): Router {
  const router = express.Router();

  router.get('/health', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      service: 't3mp3st-harness-control-plane',
      auth: 'bearer',
      stateVersion: 1,
    });
  });

  router.use((req: Request, res: Response, next: NextFunction) => {
    if (!plane.verifyApiToken(bearerToken(req))) {
      res.status(401).json({ ok: false, error: 'valid harness bearer token required' });
      return;
    }
    next();
  });
  router.use(express.json({ limit: '90mb' }));

  router.get('/config', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      apiTokenPath: plane.apiTokenPath,
      statePath: plane.statePath,
      eventsPath: plane.eventsPath,
    });
  });

  router.get('/state', asyncRoute(async (_req, res) => {
    res.json({ ok: true, state: await plane.snapshot() });
  }));

  router.post('/programs', asyncRoute(async (req, res) => {
    const program = await plane.upsertProgram(req.body as UpsertHarnessProgramInput);
    res.status(201).json({ ok: true, program });
  }));

  router.get('/programs', asyncRoute(async (_req, res) => {
    res.json({ ok: true, programs: await plane.listPrograms() });
  }));

  router.post('/programs/:id/pause', asyncRoute(async (req, res) => {
    res.json({ ok: true, program: await plane.setProgramState(req.params.id, 'paused') });
  }));

  router.post('/programs/:id/resume', asyncRoute(async (req, res) => {
    res.json({ ok: true, program: await plane.setProgramState(req.params.id, 'active') });
  }));

  router.post('/programs/:id/kill', asyncRoute(async (req, res) => {
    requireConfirmation(req.body, 'KILL_PROGRAM');
    res.json({ ok: true, program: await plane.setProgramState(req.params.id, 'killed') });
  }));

  router.post('/control/pause-all', asyncRoute(async (_req, res) => {
    res.json({ ok: true, state: await plane.setGlobalState('paused') });
  }));

  router.post('/control/resume-all', asyncRoute(async (_req, res) => {
    res.json({ ok: true, state: await plane.setGlobalState('active') });
  }));

  router.post('/control/kill-all', asyncRoute(async (req, res) => {
    requireConfirmation(req.body, 'KILL_ALL');
    res.json({ ok: true, state: await plane.setGlobalState('killed') });
  }));

  router.post('/auth-capsules', asyncRoute(async (req, res) => {
    const capsule = await plane.upsertAuthCapsule(req.body as UpsertHarnessAuthCapsuleInput);
    res.status(201).json({ ok: true, capsule });
  }));

  router.post('/artifacts', asyncRoute(async (req, res) => {
    const body = req.body as Record<string, unknown>;
    if (typeof body.contentBase64 !== 'string') throw new Error('contentBase64 is required');
    const input: PutControlPlaneArtifactInput = {
      programId: String(body.programId ?? ''),
      content: Buffer.from(body.contentBase64, 'base64'),
      mediaType: typeof body.mediaType === 'string' ? body.mediaType : undefined,
      tier: body.tier === 'sealed' || body.tier === 'operator' || body.tier === 'report'
        ? body.tier
        : undefined,
      fileName: typeof body.fileName === 'string' ? body.fileName : undefined,
      source: typeof body.source === 'string' ? body.source : undefined,
    };
    const artifact = await plane.putArtifact(input);
    res.status(201).json({ ok: true, artifact });
  }));

  router.get('/artifacts/:id', asyncRoute(async (req, res) => {
    res.json({ ok: true, artifact: await plane.getArtifactMetadata(req.params.id) });
  }));

  router.post('/artifacts/:id/reveal', asyncRoute(async (req, res) => {
    requireConfirmation(req.body, 'REVEAL_LOCAL_EVIDENCE');
    const artifact = await plane.getArtifactMetadata(req.params.id);
    const content = await plane.readArtifact(req.params.id, {
      allowOperator: true,
      allowSealed: true,
    });
    res.json({
      ok: true,
      artifact,
      contentBase64: content.toString('base64'),
    });
  }));

  router.post('/requests', asyncRoute(async (req, res) => {
    const request = await plane.ingestRequest(req.body as IngestHarnessRequestInput);
    res.status(201).json({ ok: true, request });
  }));

  router.post('/jobs', asyncRoute(async (req, res) => {
    const job = await plane.enqueueJob(req.body as EnqueueHarnessJobInput);
    res.status(201).json({ ok: true, job });
  }));

  router.get('/jobs', asyncRoute(async (req, res) => {
    const jobs = await plane.listJobs({
      programId: typeof req.query.programId === 'string' ? req.query.programId : undefined,
      status: parseStatus(req.query.status),
      kind: typeof req.query.kind === 'string' ? req.query.kind : undefined,
    });
    res.json({ ok: true, jobs });
  }));

  router.get('/jobs/:id', asyncRoute(async (req, res) => {
    res.json({ ok: true, job: await plane.getJob(req.params.id) });
  }));

  router.post('/jobs/lease', asyncRoute(async (req, res) => {
    const job = await plane.leaseNext(req.body as LeaseHarnessJobInput);
    res.json({ ok: true, job });
  }));

  router.post('/jobs/:id/running', asyncRoute(async (req, res) => {
    const workerId = String((req.body as Record<string, unknown>).workerId ?? '');
    res.json({ ok: true, job: await plane.markRunning(req.params.id, workerId) });
  }));

  router.post('/jobs/:id/heartbeat', asyncRoute(async (req, res) => {
    const body = req.body as Record<string, unknown>;
    const workerId = String(body.workerId ?? '');
    const leaseMs = typeof body.leaseMs === 'number' ? body.leaseMs : undefined;
    res.json({
      ok: true,
      job: await plane.heartbeat(req.params.id, workerId, leaseMs),
    });
  }));

  router.post('/jobs/:id/complete', asyncRoute(async (req, res) => {
    const input = { ...(req.body as CompleteHarnessJobInput), jobId: req.params.id };
    res.json({ ok: true, job: await plane.completeJob(input) });
  }));

  router.post('/jobs/:id/fail', asyncRoute(async (req, res) => {
    const input = { ...(req.body as FailHarnessJobInput), jobId: req.params.id };
    res.json({ ok: true, job: await plane.failJob(input) });
  }));

  router.post('/jobs/:id/release', asyncRoute(async (req, res) => {
    const body = req.body as Record<string, unknown>;
    const workerId = String(body.workerId ?? '');
    const delayMs = typeof body.delayMs === 'number' ? body.delayMs : 0;
    res.json({ ok: true, job: await plane.releaseJob(req.params.id, workerId, delayMs) });
  }));

  router.post('/jobs/:id/pause', asyncRoute(async (req, res) => {
    res.json({ ok: true, job: await plane.pauseJob(req.params.id) });
  }));

  router.post('/jobs/:id/resume', asyncRoute(async (req, res) => {
    res.json({ ok: true, job: await plane.resumeJob(req.params.id) });
  }));

  router.post('/jobs/:id/kill', asyncRoute(async (req, res) => {
    requireConfirmation(req.body, 'KILL_JOB');
    const reason = typeof (req.body as Record<string, unknown>).reason === 'string'
      ? String((req.body as Record<string, unknown>).reason)
      : 'operator kill';
    res.json({ ok: true, job: await plane.killJob(req.params.id, reason) });
  }));

  router.post('/bundles', asyncRoute(async (req, res) => {
    const input = req.body as CreateEvidenceBundleInput & { confirm?: string };
    if (input.mode === 'private-full') {
      requireConfirmation(req.body, 'INCLUDE_SEALED_EVIDENCE');
    }
    const bundle = await plane.createEvidenceBundle(input);
    res.status(201).json({ ok: true, bundle });
  }));

  router.get('/events', asyncRoute(async (req, res) => {
    const cursor = typeof req.query.cursor === 'string' ? Number(req.query.cursor) : 0;
    const limit = typeof req.query.limit === 'string' ? Number(req.query.limit) : 200;
    res.json({ ok: true, ...await plane.readEvents(cursor, limit) });
  }));

  return router;
}
