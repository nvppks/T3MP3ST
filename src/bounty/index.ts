import { createHash } from 'node:crypto';

export type BountyVulnerabilityClass =
  | 'IDOR'
  | 'BOLA'
  | 'BFLA'
  | 'CROSS_TENANT'
  | 'ROLE_BYPASS'
  | 'AUTH_BYPASS'
  | 'BUSINESS_LOGIC';

export type EvidenceStage =
  | 'discovered'
  | 'reproduced'
  | 'controlled'
  | 'impact_confirmed'
  | 'report_ready'
  | 'retested';

export interface ScopeRule {
  host: string;
  includeSubdomains?: boolean;
  paths?: string[];
  methods?: string[];
}

export interface ProgramScope {
  program: string;
  included: ScopeRule[];
  excluded?: ScopeRule[];
  forbiddenTechniques?: string[];
  maxRequestsPerSecond?: number;
  maxConcurrency?: number;
  allowAccountCreation?: boolean;
  allowFileUpload?: boolean;
  allowOast?: boolean;
  dataHandling?: {
    pii: 'none' | 'minimal' | 'allowed';
    redactEvidence: boolean;
  };
}

export interface ScopeDecision {
  allowed: boolean;
  reason: string;
  matchedRule?: ScopeRule;
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

function hostMatches(host: string, rule: ScopeRule): boolean {
  const actual = normalizeHost(host);
  const allowed = normalizeHost(rule.host);
  return actual === allowed || (!!rule.includeSubdomains && actual.endsWith(`.${allowed}`));
}

function pathMatches(pathname: string, patterns?: string[]): boolean {
  if (!patterns?.length) return true;
  return patterns.some((pattern) => {
    if (pattern.endsWith('*')) return pathname.startsWith(pattern.slice(0, -1));
    return pathname === pattern;
  });
}

function ruleMatches(url: URL, method: string, rule: ScopeRule): boolean {
  const methods = rule.methods?.map((entry) => entry.toUpperCase());
  return hostMatches(url.hostname, rule)
    && pathMatches(url.pathname, rule.paths)
    && (!methods?.length || methods.includes(method.toUpperCase()));
}

export function evaluateProgramScope(scope: ProgramScope, target: string, method = 'GET'): ScopeDecision {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return { allowed: false, reason: 'target is not a valid absolute URL' };
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    return { allowed: false, reason: `protocol ${url.protocol} is not allowed` };
  }

  const excluded = (scope.excluded ?? []).find((rule) => ruleMatches(url, method, rule));
  if (excluded) return { allowed: false, reason: 'target matches an excluded scope rule', matchedRule: excluded };

  const included = scope.included.find((rule) => ruleMatches(url, method, rule));
  if (!included) return { allowed: false, reason: 'target does not match an included scope rule' };

  return { allowed: true, reason: 'target is in scope', matchedRule: included };
}

export interface IdentityContext {
  id: string;
  role: string;
  tenant?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
}

export interface HttpObservation {
  identityId: string;
  method: string;
  url: string;
  status: number;
  requestBody?: unknown;
  responseBody?: unknown;
  responseHeaders?: Record<string, string>;
  durationMs?: number;
  evidenceIds: string[];
  capturedAt?: number;
}

export interface EndpointNode {
  key: string;
  origin: string;
  host: string;
  method: string;
  normalizedPath: string;
  contentType?: string;
  parameters: string[];
  identities: string[];
  observations: HttpObservation[];
}

export interface AssetNode {
  key: string;
  origin: string;
  host: string;
  endpoints: Map<string, EndpointNode>;
}

const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_SEGMENT = /^[0-9a-f]{16,}$/i;
const INTEGER_SEGMENT = /^\d+$/;
const BASE64ISH_SEGMENT = /^[A-Za-z0-9_-]{24,}={0,2}$/;

export function normalizePath(pathname: string): string {
  const raw = pathname.split('?')[0] || '/';
  const normalized = raw.split('/').map((segment) => {
    if (!segment) return segment;
    if (UUID_SEGMENT.test(segment)) return '{uuid}';
    if (INTEGER_SEGMENT.test(segment)) return '{int}';
    if (HEX_SEGMENT.test(segment)) return '{hex}';
    if (BASE64ISH_SEGMENT.test(segment)) return '{token}';
    return segment;
  }).join('/');
  return normalized || '/';
}

export function endpointKey(method: string, target: string, contentType = ''): string {
  const url = new URL(target);
  return `${url.origin}|${method.toUpperCase()}|${normalizePath(url.pathname)}|${contentType.toLowerCase()}`;
}

export class AssetGraph {
  private readonly assets = new Map<string, AssetNode>();

  addObservation(observation: HttpObservation): EndpointNode {
    const url = new URL(observation.url);
    const origin = url.origin.toLowerCase();
    let asset = this.assets.get(origin);
    if (!asset) {
      asset = { key: origin, origin, host: normalizeHost(url.hostname), endpoints: new Map() };
      this.assets.set(origin, asset);
    }

    const contentType = Object.entries(observation.responseHeaders ?? {})
      .find(([name]) => name.toLowerCase() === 'content-type')?.[1]?.split(';')[0]?.trim();
    const key = endpointKey(observation.method, observation.url, contentType);
    let endpoint = asset.endpoints.get(key);
    if (!endpoint) {
      endpoint = {
        key,
        origin,
        host: asset.host,
        method: observation.method.toUpperCase(),
        normalizedPath: normalizePath(url.pathname),
        contentType,
        parameters: [...new Set(url.searchParams.keys())].sort(),
        identities: [],
        observations: [],
      };
      asset.endpoints.set(key, endpoint);
    }

    endpoint.observations.push(observation);
    endpoint.identities = [...new Set([...endpoint.identities, observation.identityId])].sort();
    endpoint.parameters = [...new Set([...endpoint.parameters, ...url.searchParams.keys()])].sort();
    return endpoint;
  }

  listAssets(): AssetNode[] {
    return [...this.assets.values()];
  }

  listEndpoints(): EndpointNode[] {
    return this.listAssets().flatMap((asset) => [...asset.endpoints.values()]);
  }
}

const VOLATILE_KEYS = new Set([
  'timestamp', 'time', 'createdat', 'updatedat', 'requestid', 'request_id',
  'traceid', 'trace_id', 'nonce', 'csrf', 'csrftoken', 'expires', 'expiry',
]);

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => !VOLATILE_KEYS.has(key.toLowerCase()))
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, nested]) => [key, canonicalize(nested)]),
    );
  }
  if (typeof value === 'string') {
    return value
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, '{uuid}')
      .replace(/\b\d{10,13}\b/g, '{timestamp}');
  }
  return value;
}

export function semanticHash(body: unknown): string {
  const canonical = canonicalize(body);
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

export function semanticSimilarity(a: unknown, b: unknown): number {
  if (semanticHash(a) === semanticHash(b)) return 1;
  const left = JSON.stringify(canonicalize(a));
  const right = JSON.stringify(canonicalize(b));
  if (!left.length && !right.length) return 1;
  const leftTokens = new Set(left.toLowerCase().split(/[^a-z0-9_{}]+/).filter(Boolean));
  const rightTokens = new Set(right.toLowerCase().split(/[^a-z0-9_{}]+/).filter(Boolean));
  const intersection = [...leftTokens].filter((token) => rightTokens.has(token)).length;
  const union = new Set([...leftTokens, ...rightTokens]).size;
  return union ? intersection / union : 0;
}

export interface AuthzCandidate {
  vulnerabilityClass: BountyVulnerabilityClass;
  endpoint: string;
  ownerIdentity: string;
  attackerIdentity: string;
  baseline: HttpObservation;
  exploit: HttpObservation;
  negativeControl?: HttpObservation;
  confidence: number;
  reasons: string[];
  evidenceIds: string[];
}

export interface AuthzDiffInput {
  owner: IdentityContext;
  attacker: IdentityContext;
  baseline: HttpObservation;
  exploit: HttpObservation;
  negativeControl?: HttpObservation;
  expectedDeniedStatuses?: number[];
}

export function analyzeAuthzDifferential(input: AuthzDiffInput): AuthzCandidate | null {
  const denied = new Set(input.expectedDeniedStatuses ?? [401, 403, 404]);
  const reasons: string[] = [];

  if (input.baseline.status < 200 || input.baseline.status >= 300) return null;
  if (denied.has(input.exploit.status) || input.exploit.status >= 500) return null;

  const similarity = semanticSimilarity(input.baseline.responseBody, input.exploit.responseBody);
  if (similarity >= 0.75) reasons.push(`attacker response is semantically similar to owner response (${similarity.toFixed(2)})`);
  if (input.exploit.status === input.baseline.status) reasons.push(`attacker received the same HTTP status (${input.exploit.status})`);

  let controlStrength = 0;
  if (input.negativeControl) {
    if (denied.has(input.negativeControl.status)) {
      controlStrength = 1;
      reasons.push(`negative control was denied (${input.negativeControl.status})`);
    } else if (input.negativeControl.status !== input.exploit.status) {
      controlStrength = 0.5;
      reasons.push('negative control behaved differently from exploit request');
    }
  }

  if (similarity < 0.45 && controlStrength === 0) return null;

  const crossTenant = !!input.owner.tenant && !!input.attacker.tenant && input.owner.tenant !== input.attacker.tenant;
  const roleBypass = input.owner.role !== input.attacker.role;
  const vulnerabilityClass: BountyVulnerabilityClass = crossTenant
    ? 'CROSS_TENANT'
    : roleBypass
      ? 'BFLA'
      : 'BOLA';

  const confidence = Math.min(1,
    0.25
    + similarity * 0.45
    + (input.exploit.status === input.baseline.status ? 0.1 : 0)
    + controlStrength * 0.2,
  );

  return {
    vulnerabilityClass,
    endpoint: `${input.exploit.method.toUpperCase()} ${normalizePath(new URL(input.exploit.url).pathname)}`,
    ownerIdentity: input.owner.id,
    attackerIdentity: input.attacker.id,
    baseline: input.baseline,
    exploit: input.exploit,
    negativeControl: input.negativeControl,
    confidence: Number(confidence.toFixed(3)),
    reasons,
    evidenceIds: [...new Set([
      ...input.baseline.evidenceIds,
      ...input.exploit.evidenceIds,
      ...(input.negativeControl?.evidenceIds ?? []),
    ])],
  };
}

export interface EvidenceRecord {
  kind: 'request' | 'response' | 'screenshot' | 'log' | 'scope_receipt' | 'cleanup' | 'retest';
  id: string;
  role?: 'baseline' | 'exploit' | 'negative_control' | 'impact';
  redacted?: boolean;
  reproduction?: number;
}

export interface EvidenceAssessment {
  stage: EvidenceStage;
  reportReady: boolean;
  missing: string[];
}

export function assessBlackBoxEvidence(records: EvidenceRecord[]): EvidenceAssessment {
  const missing: string[] = [];
  const has = (kind: EvidenceRecord['kind'], role?: EvidenceRecord['role']) =>
    records.some((record) => record.kind === kind && (!role || record.role === role));

  const discovered = has('request') && has('response');
  const reproduced = discovered && records.some((record) => (record.reproduction ?? 0) >= 2);
  const controlled = reproduced
    && has('request', 'baseline') && has('response', 'baseline')
    && has('request', 'exploit') && has('response', 'exploit')
    && has('request', 'negative_control') && has('response', 'negative_control');
  const impact = controlled && (has('response', 'impact') || has('screenshot', 'impact') || has('log', 'impact'));
  const scope = has('scope_receipt');
  const redacted = records.filter((record) => ['request', 'response', 'screenshot', 'log'].includes(record.kind))
    .every((record) => record.redacted === true);
  const ready = impact && scope && redacted;
  const retested = ready && has('retest');

  if (!discovered) missing.push('request and response evidence');
  if (!reproduced) missing.push('at least two successful reproductions');
  if (!controlled) missing.push('baseline, exploit, and negative-control request/response pairs');
  if (!impact) missing.push('impact evidence');
  if (!scope) missing.push('scope receipt');
  if (!redacted) missing.push('redacted evidence');

  const stage: EvidenceStage = retested ? 'retested'
    : ready ? 'report_ready'
      : impact ? 'impact_confirmed'
        : controlled ? 'controlled'
          : reproduced ? 'reproduced'
            : 'discovered';

  return { stage, reportReady: ready, missing };
}

export interface BountyFinding {
  program: string;
  asset: string;
  method: string;
  path: string;
  vulnerabilityClass: BountyVulnerabilityClass;
  violatedBoundary: string;
  primitive: string;
  title: string;
  summary: string;
  prerequisites?: string[];
  steps: string[];
  expected: string;
  actual: string;
  impact: string;
  remediation?: string;
  evidenceIds: string[];
  confidence?: number;
}

export function findingFingerprint(finding: BountyFinding): string {
  const input = [
    finding.program.trim().toLowerCase(),
    normalizeHost(new URL(finding.asset).hostname),
    finding.method.toUpperCase(),
    normalizePath(finding.path),
    finding.vulnerabilityClass,
    finding.violatedBoundary.trim().toLowerCase(),
    finding.primitive.trim().toLowerCase(),
  ].join('|');
  return createHash('sha256').update(input).digest('hex');
}

export function deduplicateFindings(findings: BountyFinding[]): BountyFinding[] {
  const best = new Map<string, BountyFinding>();
  for (const finding of findings) {
    const key = findingFingerprint(finding);
    const existing = best.get(key);
    if (!existing || (finding.confidence ?? 0) > (existing.confidence ?? 0)) best.set(key, finding);
  }
  return [...best.values()];
}

export function renderBountyReport(finding: BountyFinding): string {
  const lines = [
    `# ${finding.title}`,
    '',
    `**Program:** ${finding.program}`,
    `**Asset:** ${finding.asset}`,
    `**Endpoint:** ${finding.method.toUpperCase()} ${normalizePath(finding.path)}`,
    `**Weakness:** ${finding.vulnerabilityClass}`,
    `**Fingerprint:** \`${findingFingerprint(finding)}\``,
    '',
    '## Summary',
    '',
    finding.summary,
    '',
  ];

  if (finding.prerequisites?.length) {
    lines.push('## Prerequisites', '', ...finding.prerequisites.map((item) => `- ${item}`), '');
  }

  lines.push(
    '## Steps to reproduce',
    '',
    ...finding.steps.map((step, index) => `${index + 1}. ${step}`),
    '',
    '## Expected result',
    '',
    finding.expected,
    '',
    '## Actual result',
    '',
    finding.actual,
    '',
    '## Impact',
    '',
    finding.impact,
    '',
    '## Supporting evidence',
    '',
    ...finding.evidenceIds.map((id) => `- \`${id}\``),
  );

  if (finding.remediation) lines.push('', '## Suggested remediation', '', finding.remediation);
  return `${lines.join('\n')}\n`;
}
