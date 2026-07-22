import { createHash } from 'node:crypto';
import { redactString } from '../../redact.js';
import { redactHeaders } from '../helpers.js';
import type { HarnessRunnerDefinition } from '../runner-contract.js';

function numberValue(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? Math.trunc(value) : fallback;
}

async function readLimitedBody(response: Response, maxBytes: number): Promise<Buffer> {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    const remaining = maxBytes - total;
    if (remaining <= 0) {
      await reader.cancel('response body limit reached');
      break;
    }
    chunks.push(chunk.subarray(0, remaining));
    total += Math.min(chunk.length, remaining);
    if (total >= maxBytes) {
      await reader.cancel('response body limit reached');
      break;
    }
  }
  return Buffer.concat(chunks, total);
}

function responseHeaders(response: Response): Record<string, string> {
  return Object.fromEntries(response.headers.entries());
}

export const httpProbeRunner: HarnessRunnerDefinition = {
  kind: 'http_probe',
  description: 'Send one scoped HTTP request through the configured upstream SOCKS/direct egress profile.',
  riskTier: 'active',
  networked: true,
  parameters: [
    {
      name: 'timeoutMs',
      type: 'number',
      description: 'Request timeout in milliseconds.',
      required: false,
      default: 15_000,
    },
    {
      name: 'maxBodyBytes',
      type: 'number',
      description: 'Maximum response bytes retained as evidence.',
      required: false,
      default: 2_000_000,
    },
    {
      name: 'egress',
      type: 'object',
      description: 'Per-job egress selection. SOCKS URLs must live in a sealed artifact.',
      required: false,
      additionalProperties: false,
      properties: {
        mode: {
          name: 'mode',
          type: 'string',
          description: 'Use inherited, direct, or sealed SOCKS egress.',
          required: true,
          enum: ['inherit', 'direct', 'socks'],
        },
        proxyArtifactId: {
          name: 'proxyArtifactId',
          type: 'string',
          description: 'Sealed artifact containing a SOCKS URL.',
          required: false,
        },
      },
    },
  ],
  async run(context) {
    if (!context.job.target) throw new Error('http_probe requires a scoped job target');
    const target = (await context.plane.readArtifact(
      context.job.target.sealedUrlArtifactId,
      { allowSealed: true },
    )).toString('utf8').trim();
    const timeoutMs = Math.min(120_000, Math.max(1_000, numberValue(context.config.timeoutMs, 15_000)));
    const maxBodyBytes = Math.min(
      10_000_000,
      Math.max(0, numberValue(context.config.maxBodyBytes, 2_000_000)),
    );
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = AbortSignal.any([context.signal, timeout]);
    const startedAt = Date.now();
    const response = await fetch(target, {
      method: context.job.target.method,
      redirect: 'manual',
      signal,
      headers: {
        'User-Agent': 'T3MP3ST-Harness/1.0',
        Accept: '*/*',
      },
    });
    const body = await readLimitedBody(response, maxBodyBytes);
    const headers = responseHeaders(response);
    const durationMs = Date.now() - startedAt;
    const digest = createHash('sha256').update(body).digest('hex');

    const sealed = await context.plane.putArtifact({
      programId: context.job.programId,
      content: `${JSON.stringify({
        url: target,
        method: context.job.target.method,
        status: response.status,
        headers,
        bodyBase64: body.toString('base64'),
        bodySha256: digest,
        durationMs,
      }, null, 2)}\n`,
      mediaType: 'application/json',
      tier: 'sealed',
      fileName: 'http-probe.sealed.json',
      source: `harness:${context.job.id}`,
    });
    const preview = redactString(body.toString('utf8', 0, Math.min(body.length, 1_000)));
    const report = await context.plane.putArtifact({
      programId: context.job.programId,
      content: `${JSON.stringify({
        url: context.job.target.displayUrl,
        method: context.job.target.method,
        status: response.status,
        headers: redactHeaders(headers),
        bodySize: body.length,
        bodySha256: digest,
        durationMs,
        preview,
      }, null, 2)}\n`,
      mediaType: 'application/json',
      tier: 'report',
      fileName: 'http-probe.report.json',
      source: `harness:${context.job.id}`,
    });

    return {
      artifacts: [sealed, report],
      summary: `HTTP ${response.status}; ${body.length} byte(s); ${durationMs} ms`,
    };
  },
};
