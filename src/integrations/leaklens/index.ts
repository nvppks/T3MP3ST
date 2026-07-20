import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, extname, join } from 'node:path';
import {
  evaluateProgramScope,
  type ProgramScope,
} from '../../bounty/index.js';

export type LeakLensValidationState = 'valid' | 'invalid' | 'unknown' | 'not_run';

export interface LeakLensContentRequest {
  kind: 'content';
  contentBase64: string;
  sourceUrl?: string;
  sourceMethod?: string;
  fileName?: string;
  jsIntel?: boolean;
  scope?: ProgramScope;
  validate?: boolean;
  approvalId?: string;
}

export interface LeakLensUrlRequest {
  kind: 'url';
  targetUrl: string;
  scope: ProgramScope;
  crawl?: boolean;
  jsIntel?: boolean;
  rateLimit?: number;
  concurrency?: number;
  validate?: boolean;
  approvalId?: string;
}

export interface LeakLensPathRequest {
  kind: 'path';
  targetPath: string;
  jsIntel?: boolean;
  validate?: boolean;
  approvalId?: string;
}

export type LeakLensScanRequest = LeakLensContentRequest | LeakLensUrlRequest | LeakLensPathRequest;

export interface LeakLensFinding {
  findingId: string;
  ruleId: string;
  ruleName: string;
  source: string;
  line?: number;
  maskedValue: string;
  secretSha256: string;
  validation: LeakLensValidationState;
  evidenceArtifact: string;
  matchCount: number;
}

export interface LeakLensScanResult {
  success: boolean;
  source: string;
  findingCount: number;
  findings: LeakLensFinding[];
  durationMs: number;
  diagnostic?: string;
}

export interface LeakLensProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface LeakLensProcessOptions {
  timeoutMs: number;
  maxOutputBytes: number;
}

export type LeakLensRunner = (
  command: string,
  args: string[],
  options: LeakLensProcessOptions,
) => Promise<LeakLensProcessResult>;

export interface LeakLensRunOptions {
  binary?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  maxContentBytes?: number;
  allowValidation?: boolean;
  runner?: LeakLensRunner;
}

const DEFAULT_TIMEOUT_MS = 180_000;
const DEFAULT_MAX_OUTPUT = 32 * 1024 * 1024;
const DEFAULT_MAX_CONTENT = 20 * 1024 * 1024;
const SAFE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.json', '.map', '.txt']);
const PREFERRED_GROUPS = ['token', 'secret', 'key', 'api_key', 'apikey', 'password', 'credential', 'value'];

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function boundedInteger(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function isHttpUrl(value: string): boolean {
  try {
    return ['http:', 'https:'].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

function requireInScope(scope: ProgramScope | undefined, target: string, method: string): void {
  if (!scope) throw new Error('program scope is required for URL-backed LeakLens scans');
  const decision = evaluateProgramScope(scope, target, method);
  if (!decision.allowed) throw new Error(`scope denied: ${decision.reason}`);
}

function requireValidationApproval(request: LeakLensScanRequest, allowValidation: boolean): void {
  if (!request.validate) return;
  if (!allowValidation) {
    throw new Error('LeakLens live validation is disabled; set explicit bridge approval to enable it');
  }
  if (!request.approvalId?.trim()) {
    throw new Error('LeakLens live validation requires a non-empty approvalId');
  }
}

function validateRequest(request: LeakLensScanRequest, allowValidation: boolean): void {
  requireValidationApproval(request, allowValidation);

  if (request.kind === 'url') {
    if (!isHttpUrl(request.targetUrl)) throw new Error('targetUrl must be an absolute HTTP(S) URL');
    requireInScope(request.scope, request.targetUrl, 'GET');
    return;
  }

  if (request.kind === 'content') {
    if (!request.contentBase64.trim()) throw new Error('contentBase64 is required');
    if (request.sourceUrl) {
      if (!isHttpUrl(request.sourceUrl)) throw new Error('sourceUrl must be an absolute HTTP(S) URL');
      requireInScope(request.scope, request.sourceUrl, request.sourceMethod ?? 'GET');
    }
    return;
  }

  if (!request.targetPath.trim()) throw new Error('targetPath is required');
  if (request.targetPath.includes('\0') || request.targetPath.trim().startsWith('-')) {
    throw new Error('targetPath is not a safe filesystem target');
  }
}

function resolvedTarget(request: LeakLensScanRequest, contentPath?: string): string {
  if (request.kind === 'content') {
    if (!contentPath) throw new Error('resolved content path is required');
    return contentPath;
  }
  return request.kind === 'url' ? request.targetUrl : request.targetPath;
}

export function buildLeakLensArgs(
  request: LeakLensScanRequest,
  contentPath?: string,
  allowValidation = false,
): string[] {
  validateRequest(request, allowValidation);
  const args = ['scan', '--no-update-check', '--format', 'json', '--output', ':memory:'];

  if (request.kind === 'url' && request.crawl) {
    args.push(
      '--crawl',
      '--crawl-scope', 'fqdn',
      '--crawl-concurrency', String(boundedInteger(request.concurrency, 2, 1, 4)),
      '--crawl-rate-limit', String(boundedInteger(request.rateLimit, 3, 1, 10)),
      '--crawl-timeout', '2m',
      '--crawl-extensions', 'js,json,map',
    );
  }

  if (request.jsIntel) args.push('--js-intel');
  if (request.validate) args.push('--validate', '--validate-workers', '2');
  args.push(resolvedTarget(request, contentPath));
  return args;
}

function printableRatio(value: Buffer): number {
  if (value.length === 0) return 0;
  let printable = 0;
  for (const byte of value) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable++;
  }
  return printable / value.length;
}

function decodeGoBytes(value: unknown): string {
  const text = asString(value).trim();
  if (!text) return '';
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0) {
    try {
      const decoded = Buffer.from(text, 'base64');
      if (decoded.length > 0 && printableRatio(decoded) >= 0.85) return decoded.toString('utf8');
    } catch {
      // Fall back to the original string when it is not valid base64.
    }
  }
  return text;
}

function candidateStrings(finding: Record<string, unknown>, match: Record<string, unknown>): string[] {
  const candidates: string[] = [];
  const named = asRecord(match.NamedGroups ?? match.namedGroups ?? finding.NamedGroups ?? finding.namedGroups);

  for (const key of PREFERRED_GROUPS) {
    const exact = Object.entries(named).find(([name]) => name.toLowerCase() === key);
    if (exact) candidates.push(decodeGoBytes(exact[1]));
  }
  for (const value of Object.values(named)) candidates.push(decodeGoBytes(value));

  for (const value of asArray(match.Groups ?? match.groups)) candidates.push(decodeGoBytes(value));
  for (const value of asArray(finding.Groups ?? finding.groups)) candidates.push(decodeGoBytes(value));

  return [...new Set(candidates.map((value) => value.trim()).filter((value) => value.length > 0 && value.length <= 4096))]
    .sort((left, right) => right.length - left.length);
}

export function maskSecret(value: string): string {
  const text = value.trim();
  if (!text) return '[MASKED]';
  if (text.length < 8) return '***';
  if (text.length < 12) return `${text.slice(0, 2)}…${text.slice(-2)}`;
  return `${text.slice(0, 4)}…${text.slice(-4)}`;
}

export function secretFingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function nestedLine(match: Record<string, unknown>): number | undefined {
  const location = asRecord(match.Location ?? match.location);
  const source = asRecord(location.Source ?? location.source);
  const start = asRecord(source.Start ?? source.start);
  const line = Number(start.Line ?? start.line);
  return Number.isInteger(line) && line > 0 ? line : undefined;
}

function matchSource(match: Record<string, unknown>, fallback: string): string {
  const direct = asString(match.Path ?? match.path ?? match.URL ?? match.url ?? match.Source ?? match.source);
  if (direct) return direct;
  const location = asRecord(match.Location ?? match.location);
  const source = asRecord(location.Source ?? location.source);
  const nested = asString(source.Path ?? source.path ?? source.Name ?? source.name);
  return nested || fallback;
}

function validationState(match: Record<string, unknown>): LeakLensValidationState {
  const raw = match.ValidationResult ?? match.validationResult ?? match.validation_result;
  if (raw === undefined || raw === null) return 'not_run';
  const record = asRecord(raw);
  const valid = record.Valid ?? record.valid ?? record.IsValid ?? record.isValid;
  if (typeof valid === 'boolean') return valid ? 'valid' : 'invalid';
  const status = asString(record.Status ?? record.status).toLowerCase();
  if (['valid', 'verified', 'active'].includes(status)) return 'valid';
  if (['invalid', 'revoked', 'inactive'].includes(status)) return 'invalid';
  return 'unknown';
}

function parseJsonDocument(raw: string): unknown {
  const text = raw.trim();
  if (!text) return [];
  try {
    return JSON.parse(text) as unknown;
  } catch {
    const arrayStart = text.indexOf('[');
    const arrayEnd = text.lastIndexOf(']');
    if (arrayStart >= 0 && arrayEnd > arrayStart) {
      return JSON.parse(text.slice(arrayStart, arrayEnd + 1)) as unknown;
    }
    const objectStart = text.indexOf('{');
    const objectEnd = text.lastIndexOf('}');
    if (objectStart >= 0 && objectEnd > objectStart) {
      return JSON.parse(text.slice(objectStart, objectEnd + 1)) as unknown;
    }
    throw new Error('LeakLens did not return parseable JSON');
  }
}

export function parseLeakLensJson(raw: string, fallbackSource = 'unknown'): LeakLensFinding[] {
  const document = parseJsonDocument(raw);
  const root = asRecord(document);
  const findings = Array.isArray(document)
    ? document
    : asArray(root.findings ?? root.Findings ?? root.results ?? root.Results);

  return findings.map((value, index) => {
    const finding = asRecord(value);
    const matches = asArray(finding.Matches ?? finding.matches).map(asRecord);
    const representative = matches[0] ?? {};
    const candidate = candidateStrings(finding, representative)[0] ?? '';
    const findingId = asString(finding.ID ?? finding.id) || `leaklens-finding-${index + 1}`;
    const ruleId = asString(finding.RuleID ?? finding.ruleId ?? finding.rule_id) || 'leaklens.unknown';
    const ruleName = asString(representative.RuleName ?? representative.ruleName ?? finding.RuleName ?? finding.ruleName) || ruleId;
    const structuralId = asString(representative.StructuralID ?? representative.structuralId ?? representative.structural_id) || 'aggregate';
    const fingerprintInput = candidate || `${findingId}\0${ruleId}`;

    return {
      findingId,
      ruleId,
      ruleName,
      source: matchSource(representative, fallbackSource),
      line: nestedLine(representative),
      maskedValue: maskSecret(candidate),
      secretSha256: secretFingerprint(fingerprintInput),
      validation: validationState(representative),
      evidenceArtifact: `leaklens:${findingId}:${structuralId}`,
      matchCount: matches.length || 1,
    };
  });
}

function redactDiagnostic(value: string): string {
  return value
    .slice(0, 4000)
    .replace(/\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
    .replace(/[A-Za-z0-9+/_=-]{20,}/g, '[REDACTED]')
    .trim();
}

function safeContentName(request: LeakLensContentRequest): string {
  let candidate = request.fileName?.trim() || '';
  if (!candidate && request.sourceUrl) {
    try {
      candidate = basename(new URL(request.sourceUrl).pathname);
    } catch {
      candidate = '';
    }
  }
  const base = basename(candidate || 'burp-response.js').replace(/[^A-Za-z0-9._-]/g, '_');
  const extension = extname(base).toLowerCase();
  return SAFE_EXTENSIONS.has(extension) ? base : `${base || 'burp-response'}.txt`;
}

const defaultRunner: LeakLensRunner = async (command, args, options) => new Promise((resolve) => {
  execFile(command, args, {
    encoding: 'utf8',
    timeout: options.timeoutMs,
    maxBuffer: options.maxOutputBytes,
  }, (error, stdout, stderr) => {
    const errorCode = error as (NodeJS.ErrnoException & { code?: number | string }) | null;
    const exitCode = typeof errorCode?.code === 'number' ? errorCode.code : error ? 1 : 0;
    resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), exitCode });
  });
});

async function executeRequest(
  request: LeakLensScanRequest,
  contentPath: string | undefined,
  options: Required<Pick<LeakLensRunOptions, 'binary' | 'timeoutMs' | 'maxOutputBytes' | 'allowValidation'>> & { runner: LeakLensRunner },
): Promise<LeakLensProcessResult> {
  const args = buildLeakLensArgs(request, contentPath, options.allowValidation);
  return options.runner(options.binary, args, {
    timeoutMs: options.timeoutMs,
    maxOutputBytes: options.maxOutputBytes,
  });
}

function requestSource(request: LeakLensScanRequest): string {
  if (request.kind === 'url') return request.targetUrl;
  if (request.kind === 'path') return request.targetPath;
  return request.sourceUrl || request.fileName || 'burp-response';
}

export async function runLeakLensScan(
  request: LeakLensScanRequest,
  runOptions: LeakLensRunOptions = {},
): Promise<LeakLensScanResult> {
  const options = {
    binary: runOptions.binary ?? 'leaklens',
    timeoutMs: runOptions.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxOutputBytes: runOptions.maxOutputBytes ?? DEFAULT_MAX_OUTPUT,
    maxContentBytes: runOptions.maxContentBytes ?? DEFAULT_MAX_CONTENT,
    allowValidation: runOptions.allowValidation ?? false,
    runner: runOptions.runner ?? defaultRunner,
  };
  validateRequest(request, options.allowValidation);
  const started = Date.now();
  let temporaryDirectory: string | undefined;

  try {
    let contentPath: string | undefined;
    if (request.kind === 'content') {
      const content = Buffer.from(request.contentBase64, 'base64');
      if (content.length === 0) throw new Error('contentBase64 decoded to an empty body');
      if (content.length > options.maxContentBytes) {
        throw new Error(`response body exceeds LeakLens bridge limit (${options.maxContentBytes} bytes)`);
      }
      temporaryDirectory = await mkdtemp(join(tmpdir(), 't3mp3st-leaklens-'));
      contentPath = join(temporaryDirectory, safeContentName(request));
      await writeFile(contentPath, content, { mode: 0o600 });
    }

    const processResult = await executeRequest(request, contentPath, options);
    const diagnostic = redactDiagnostic(processResult.stderr);
    if (processResult.exitCode !== 0 && !processResult.stdout.trim()) {
      throw new Error(`LeakLens exited with code ${processResult.exitCode}${diagnostic ? `: ${diagnostic}` : ''}`);
    }

    const findings = parseLeakLensJson(processResult.stdout, requestSource(request));
    return {
      success: processResult.exitCode === 0,
      source: requestSource(request),
      findingCount: findings.length,
      findings,
      durationMs: Date.now() - started,
      diagnostic: diagnostic || undefined,
    };
  } finally {
    if (temporaryDirectory) await rm(temporaryDirectory, { recursive: true, force: true });
  }
}
