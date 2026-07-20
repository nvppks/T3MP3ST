import express, { type Request, type Response } from 'express';
import { join } from 'node:path';
import { createBurpBridgeRouter } from './index.js';
import { createLeakLensRouter } from '../leaklens/router.js';
import { HarnessControlPlane } from '../../harness/control-plane.js';
import { createHarnessRouter } from '../../harness/router.js';

const host = process.env.T3MP3ST_BURP_HOST ?? '127.0.0.1';
const port = Number(process.env.T3MP3ST_BURP_PORT ?? 3000);
const harnessRoot = process.env.T3MP3ST_HARNESS_DIR
  ?? join(process.cwd(), '.t3mp3st-harness');

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error(`invalid T3MP3ST_BURP_PORT: ${process.env.T3MP3ST_BURP_PORT}`);
}

const harness = await HarnessControlPlane.open({
  rootDir: harnessRoot,
  apiToken: process.env.T3MP3ST_HARNESS_TOKEN,
});
const app = express();
app.disable('x-powered-by');
app.use('/api/burp', createBurpBridgeRouter());
app.use('/api/leaklens', createLeakLensRouter());
app.use('/api/harness', createHarnessRouter(harness));
app.get('/healthz', (_req: Request, res: Response) => res.json({
  ok: true,
  services: [
    't3mp3st-burp-bridge',
    't3mp3st-leaklens-bridge',
    't3mp3st-harness-control-plane',
  ],
}));

const server = app.listen(port, host, () => {
  console.log(`[t3mp3st-burp] listening on http://${host}:${port}`);
  console.log(`[t3mp3st-harness] bearer token file: ${harness.apiTokenPath}`);
});

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[t3mp3st-burp] received ${signal}; closing`);
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await harness.close();
}

process.once('SIGINT', () => { void shutdown('SIGINT'); });
process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
