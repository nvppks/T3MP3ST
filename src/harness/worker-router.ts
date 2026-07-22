import express, {
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from 'express';
import { redactString } from '../redact.js';
import type { HarnessControlPlane } from './control-plane.js';
import {
  HarnessApprovalStore,
  type HarnessApprovalStatus,
} from './approval-store.js';
import type { HarnessRunnerRegistry } from './runner-contract.js';
import type { HarnessWorker } from './worker.js';

const APPROVAL_STATUSES = new Set<HarnessApprovalStatus>(['pending', 'approved', 'denied']);

function bearerToken(req: Request): string | undefined {
  const match = req.get('authorization')?.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim();
}

function asyncRoute(handler: (req: Request, res: Response) => Promise<void>): RequestHandler {
  return (req, res) => {
    void handler(req, res).catch((error) => {
      const message = redactString(error instanceof Error ? error.message : String(error));
      const status = /unknown|not found/i.test(message) ? 404
        : /token|required|approval/i.test(message) ? 403
          : /invalid|cannot|must|belongs|sealed|killed|paused/i.test(message) ? 400
            : 500;
      res.status(status).json({ ok: false, error: message });
    });
  };
}

function approvalStatus(value: unknown): HarnessApprovalStatus | undefined {
  if (typeof value !== 'string' || !value) return undefined;
  if (!APPROVAL_STATUSES.has(value as HarnessApprovalStatus)) {
    throw new Error(`invalid approval status: ${value}`);
  }
  return value as HarnessApprovalStatus;
}

function decisionNote(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const value = (body as Record<string, unknown>).note;
  return typeof value === 'string' ? value : undefined;
}

export function createHarnessWorkerRouter(
  plane: HarnessControlPlane,
  worker: HarnessWorker,
  approvals: HarnessApprovalStore,
  registry: HarnessRunnerRegistry,
): Router {
  const router = express.Router();

  router.get('/worker/health', (_req, res) => {
    res.json({
      ok: true,
      service: 't3mp3st-harness-worker',
      worker: worker.status(),
      runners: registry.list().map((runner) => runner.kind),
    });
  });

  router.use((req: Request, res: Response, next: NextFunction) => {
    if (!plane.verifyApiToken(bearerToken(req))) {
      res.status(401).json({ ok: false, error: 'valid harness bearer token required' });
      return;
    }
    next();
  });
  router.use(express.json({ limit: '1mb' }));

  router.get('/runners', (_req, res) => {
    res.json({ ok: true, runners: registry.list() });
  });

  router.get('/approvals', (req, res) => {
    res.json({
      ok: true,
      approvals: approvals.list({
        programId: typeof req.query.programId === 'string' ? req.query.programId : undefined,
        status: approvalStatus(req.query.status),
      }),
    });
  });

  router.get('/approvals/:id', (req, res) => {
    res.json({ ok: true, approval: approvals.get(req.params.id) });
  });

  router.post('/approvals/:id/approve', asyncRoute(async (req, res) => {
    const approval = await approvals.approve(req.params.id, plane, decisionNote(req.body));
    res.json({ ok: true, approval, resumedJobId: approval.jobId });
  }));

  router.post('/approvals/:id/deny', asyncRoute(async (req, res) => {
    const approval = await approvals.deny(req.params.id, plane, decisionNote(req.body));
    res.json({ ok: true, approval, killedJobId: approval.jobId });
  }));

  router.get('/worker/status', (_req, res) => {
    res.json({ ok: true, worker: worker.status() });
  });

  router.post('/worker/start', (_req, res) => {
    worker.start();
    res.json({ ok: true, worker: worker.status() });
  });

  router.post('/worker/stop', asyncRoute(async (_req, res) => {
    await worker.stop();
    res.json({ ok: true, worker: worker.status() });
  }));

  router.post('/worker/run-once', asyncRoute(async (_req, res) => {
    const handled = await worker.runOnce();
    res.json({ ok: true, handled, worker: worker.status() });
  }));

  return router;
}
