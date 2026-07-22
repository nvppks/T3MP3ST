import express, { type Request, type Response } from 'express';
import { join } from 'node:path';
import { HarnessControlPlane } from './control-plane.js';
import { createHarnessRouter } from './router.js';
import { HarnessApprovalStore } from './approval-store.js';
import { createDefaultHarnessRunnerRegistry } from './default-runners.js';
import { HarnessWorker } from './worker.js';
import { createHarnessWorkerRouter } from './worker-router.js';

const host = process.env.T3MP3ST_HARNESS_HOST ?? '127.0.0.1';
const port = Number(process.env.T3MP3ST_HARNESS_PORT ?? 3444);
const rootDir = process.env.T3MP3ST_HARNESS_DIR
  ?? join(process.cwd(), '.t3mp3st-harness');

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error(`invalid T3MP3ST_HARNESS_PORT: ${process.env.T3MP3ST_HARNESS_PORT}`);
}

const plane = await HarnessControlPlane.open({
  rootDir,
  apiToken: process.env.T3MP3ST_HARNESS_TOKEN,
});
const approvals = await HarnessApprovalStore.open(rootDir);
const registry = createDefaultHarnessRunnerRegistry();
const worker = new HarnessWorker(plane, registry, approvals, {
  workerId: process.env.T3MP3ST_HARNESS_WORKER_ID,
  pollMs: Number(process.env.T3MP3ST_HARNESS_WORKER_POLL_MS ?? 500),
  leaseMs: Number(process.env.T3MP3ST_HARNESS_WORKER_LEASE_MS ?? 60_000),
});
const autoWorker = !/^(0|false|off)$/i.test(process.env.T3MP3ST_HARNESS_WORKER_AUTO ?? '1');
if (autoWorker) worker.start();

const app = express();
app.disable('x-powered-by');
app.use('/api/harness', createHarnessRouter(plane));
app.use('/api/harness', createHarnessWorkerRouter(plane, worker, approvals, registry));
app.get('/healthz', (_req: Request, res: Response) => res.json({
  ok: true,
  services: ['t3mp3st-harness-control-plane', 't3mp3st-harness-worker'],
  worker: worker.status(),
}));

const server = app.listen(port, host, () => {
  console.log(`[t3mp3st-harness] listening on http://${host}:${port}`);
  console.log(`[t3mp3st-harness] bearer token file: ${plane.apiTokenPath}`);
  console.log(`[t3mp3st-harness] worker: ${autoWorker ? 'running' : 'manual'}`);
});

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[t3mp3st-harness] received ${signal}; closing`);
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await worker.stop();
  await plane.close();
}

process.once('SIGINT', () => { void shutdown('SIGINT'); });
process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
