import { describe, expect, it } from 'vitest';
import {
  AssetGraph,
  analyzeAuthzDifferential,
  assessBlackBoxEvidence,
  deduplicateFindings,
  endpointKey,
  evaluateProgramScope,
  findingFingerprint,
  normalizePath,
  renderBountyReport,
  semanticHash,
  type BountyFinding,
  type HttpObservation,
} from '../bounty/index.js';

const observation = (overrides: Partial<HttpObservation>): HttpObservation => ({
  identityId: 'user-a',
  method: 'GET',
  url: 'https://api.example.com/orders/1001',
  status: 200,
  responseBody: { id: 1001, owner: 'user-a', requestId: 'volatile' },
  evidenceIds: ['ev-default'],
  ...overrides,
});

describe('bug bounty P0 core', () => {
  it('enforces host, path, method, and exclusions', () => {
    const scope = {
      program: 'Example',
      included: [{ host: 'example.com', includeSubdomains: true, paths: ['/api/*'], methods: ['GET'] }],
      excluded: [{ host: 'admin.example.com', includeSubdomains: false }],
    };

    expect(evaluateProgramScope(scope, 'https://api.example.com/api/users/1', 'GET').allowed).toBe(true);
    expect(evaluateProgramScope(scope, 'https://api.example.com/private', 'GET').allowed).toBe(false);
    expect(evaluateProgramScope(scope, 'https://api.example.com/api/users/1', 'POST').allowed).toBe(false);
    expect(evaluateProgramScope(scope, 'https://admin.example.com/api/users/1', 'GET').allowed).toBe(false);
  });

  it('normalizes dynamic endpoint identifiers', () => {
    expect(normalizePath('/users/123/orders/550e8400-e29b-41d4-a716-446655440000')).toBe('/users/{int}/orders/{uuid}');
    expect(endpointKey('get', 'https://api.example.com/users/123')).toContain('GET|/users/{int}|');
  });

  it('correlates observations into one endpoint graph node', () => {
    const graph = new AssetGraph();
    graph.addObservation(observation({ url: 'https://api.example.com/orders/1001?expand=user' }));
    graph.addObservation(observation({ identityId: 'user-b', url: 'https://api.example.com/orders/1002?expand=user' }));

    expect(graph.listAssets()).toHaveLength(1);
    expect(graph.listEndpoints()).toHaveLength(1);
    expect(graph.listEndpoints()[0].identities).toEqual(['user-a', 'user-b']);
    expect(graph.listEndpoints()[0].parameters).toEqual(['expand']);
  });

  it('removes volatile fields from semantic hashes', () => {
    expect(semanticHash({ id: 1, requestId: 'a', timestamp: 1111111111 }))
      .toBe(semanticHash({ id: 1, requestId: 'b', timestamp: 2222222222 }));
  });

  it('detects a cross-tenant authorization differential with a control', () => {
    const result = analyzeAuthzDifferential({
      owner: { id: 'user-a', role: 'user', tenant: 'tenant-a' },
      attacker: { id: 'user-b', role: 'user', tenant: 'tenant-b' },
      baseline: observation({ evidenceIds: ['baseline'] }),
      exploit: observation({ identityId: 'user-b', evidenceIds: ['exploit'], responseBody: { id: 1001, owner: 'user-a' } }),
      negativeControl: observation({
        identityId: 'user-b',
        url: 'https://api.example.com/orders/999999',
        status: 404,
        responseBody: { error: 'not found' },
        evidenceIds: ['control'],
      }),
    });

    expect(result?.vulnerabilityClass).toBe('CROSS_TENANT');
    expect(result?.confidence).toBeGreaterThanOrEqual(0.8);
    expect(result?.evidenceIds).toEqual(['baseline', 'exploit', 'control']);
  });

  it('rejects an authorization candidate when attacker is denied', () => {
    const result = analyzeAuthzDifferential({
      owner: { id: 'user-a', role: 'user' },
      attacker: { id: 'user-b', role: 'user' },
      baseline: observation({}),
      exploit: observation({ identityId: 'user-b', status: 403, responseBody: { error: 'forbidden' } }),
    });
    expect(result).toBeNull();
  });

  it('requires controls, impact, scope, and redaction for report readiness', () => {
    const records = [
      { id: 'bq', kind: 'request' as const, role: 'baseline' as const, redacted: true, reproduction: 2 },
      { id: 'bs', kind: 'response' as const, role: 'baseline' as const, redacted: true },
      { id: 'eq', kind: 'request' as const, role: 'exploit' as const, redacted: true, reproduction: 2 },
      { id: 'es', kind: 'response' as const, role: 'exploit' as const, redacted: true },
      { id: 'cq', kind: 'request' as const, role: 'negative_control' as const, redacted: true },
      { id: 'cs', kind: 'response' as const, role: 'negative_control' as const, redacted: true },
      { id: 'impact', kind: 'screenshot' as const, role: 'impact' as const, redacted: true },
      { id: 'scope', kind: 'scope_receipt' as const },
    ];

    expect(assessBlackBoxEvidence(records)).toEqual({ stage: 'report_ready', reportReady: true, missing: [] });
  });

  it('deduplicates normalized findings and keeps the strongest candidate', () => {
    const base: BountyFinding = {
      program: 'Example',
      asset: 'https://api.example.com',
      method: 'GET',
      path: '/orders/1001',
      vulnerabilityClass: 'BOLA',
      violatedBoundary: 'object owner',
      primitive: 'replace order id',
      title: 'Order IDOR',
      summary: 'Another user can access an order.',
      steps: ['Login as another user', 'Request the owner order ID'],
      expected: 'Access denied.',
      actual: 'Order returned.',
      impact: 'Cross-account data exposure.',
      evidenceIds: ['one'],
      confidence: 0.6,
    };
    const stronger = { ...base, path: '/orders/2002', evidenceIds: ['two'], confidence: 0.95 };

    expect(findingFingerprint(base)).toBe(findingFingerprint(stronger));
    expect(deduplicateFindings([base, stronger])).toEqual([stronger]);
    expect(renderBountyReport(stronger)).toContain('## Steps to reproduce');
  });
});
