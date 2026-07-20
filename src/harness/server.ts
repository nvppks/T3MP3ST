import express, { type Request, type Response } from 'express';
import { join } from 'node:path';
import { HarnessControlPlane } from './control-plane.js';
import { createHarnessRouter } from './router.js';

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
const app = express();
app.disable('x-powered-by');
app.use('/api/harness', createHarnessRouter(plane));
app.get('/healthz', (_req: Request, res: Response) => res.json({
  ok: true,
  services: ['t3mp3st-harness-control-plane'],
}));

const server = app.listen(port, host, () => {
  console.log(`[t3mp3st-harness] listening on http://${host}:${port}`);
  console.log(`[t3mp3st-harness] bearer token file: ${plane.apiTokenPath}`);
});

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[t3mp3st-harness] received ${signal}; closing`);
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await plane.close();
}

process.once('SIGINT', () => { void shutdown('SIGINT'); });
process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
