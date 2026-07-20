import express, {
  type Request,
  type Response,
  type Router,
} from 'express';
import {
  runLeakLensScan,
  type LeakLensRunOptions,
  type LeakLensScanRequest,
  type LeakLensScanResult,
} from './index.js';

export interface LeakLensRouterOptions extends LeakLensRunOptions {
  allowValidation?: boolean;
}

function validationEnabled(options: LeakLensRouterOptions): boolean {
  if (options.allowValidation !== undefined) return options.allowValidation;
  return /^(1|true|on)$/i.test(process.env.T3MP3ST_LEAKLENS_ALLOW_VALIDATE ?? '');
}

export function redactLeakLensSource(value: string): string {
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    url.hash = '';
    const keys = [...new Set(url.searchParams.keys())];
    url.search = '';
    for (const key of keys) url.searchParams.append(key, '[REDACTED]');
    return url.toString();
  } catch {
    return value;
  }
}

function sanitizeResult(result: LeakLensScanResult): LeakLensScanResult {
  return {
    ...result,
    source: redactLeakLensSource(result.source),
    findings: result.findings.map((finding) => ({
      ...finding,
      source: redactLeakLensSource(finding.source),
    })),
  };
}

function sendError(res: Response, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  res.status(400).json({ ok: false, error: message });
}

export function createLeakLensRouter(options: LeakLensRouterOptions = {}): Router {
  const router = express.Router();
  router.use(express.json({ limit: '28mb' }));

  router.get('/health', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      service: 't3mp3st-leaklens-bridge',
      binary: options.binary ?? 'leaklens',
      validationEnabled: validationEnabled(options),
    });
  });

  router.post('/scan', async (req: Request, res: Response) => {
    try {
      const result = await runLeakLensScan(req.body as LeakLensScanRequest, {
        ...options,
        allowValidation: validationEnabled(options),
      });
      res.json({ ok: true, ...sanitizeResult(result) });
    } catch (error) {
      sendError(res, error);
    }
  });

  return router;
}
