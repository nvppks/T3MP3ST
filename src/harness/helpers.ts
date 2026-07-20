import { createHash } from 'node:crypto';
import { redactString } from '../redact.js';
import type { HarnessJobStatus } from './types.js';

export function normalizeIdentifier(value: string, field: string): string {
  const normalized = value.trim();
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(normalized)) {
    throw new Error(`${field} must match [A-Za-z0-9._:-] and be 1-128 characters`);
  }
  return normalized;
}

export function boundedInteger(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

export function safeDisplayUrl(value: string): string {
  const url = new URL(value);
  url.username = '';
  url.password = '';
  url.hash = '';
  const names = [...new Set(url.searchParams.keys())].sort();
  url.search = '';
  for (const name of names) url.searchParams.append(name, '[redacted]');
  return url.toString();
}

export function bodyBytes(bodyBase64: string | undefined): Buffer {
  if (!bodyBase64) return Buffer.alloc(0);
  return Buffer.from(bodyBase64, 'base64');
}

export function sha256(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function redactHeaders(
  headers: Record<string, string | string[]> | undefined,
): Record<string, string | string[]> {
  const output: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (/(authorization|cookie|set-cookie|api[_-]?key|token|secret|password|credential)/i.test(name)) {
      output[name] = '[redacted]';
    } else {
      output[name] = Array.isArray(value)
        ? value.map((entry) => redactString(entry))
        : redactString(value);
    }
  }
  return output;
}

export function containsInlineSecret(value: unknown, path = 'config'): string | null {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      const nested = containsInlineSecret(value[index], `${path}[${index}]`);
      if (nested) return nested;
    }
    return null;
  }
  if (!value || typeof value !== 'object') return null;

  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    const nextPath = `${path}.${key}`;
    const sensitive = /(authorization|cookie|api[_-]?key|password|credential|secret|token)/i.test(key);
    const reference = /(artifact|reference|ref|fingerprint|sha|hash|id)$/i.test(key);
    if (sensitive && !reference && nested !== null && nested !== undefined && nested !== '') {
      return nextPath;
    }
    const nestedPath = containsInlineSecret(nested, nextPath);
    if (nestedPath) return nestedPath;
  }
  return null;
}

export function isTerminal(status: HarnessJobStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'killed';
}
