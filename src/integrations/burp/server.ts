import express from 'express';
import { createBurpBridgeRouter } from './index.js';
import { createLeakLensRouter } from '../leaklens/router.js';

const host = process.env.T3MP3ST_BURP_HOST ?? '127.0.0.1';
const port = Number(process.env.T3MP3ST_BURP_PORT ?? 3000);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error(`invalid T3MP3ST_BURP_PORT: ${process.env.T3MP3ST_BURP_PORT}`);
}

const app = express();
app.disable('x-powered-by');
app.use('/api/burp', createBurpBridgeRouter());
app.use('/api/leaklens', createLeakLensRouter());
app.get('/healthz', (_req, res) => res.json({
  ok: true,
  services: ['t3mp3st-burp-bridge', 't3mp3st-leaklens-bridge'],
}));

app.listen(port, host, () => {
  console.log(`[t3mp3st-burp] listening on http://${host}:${port}`);
});
