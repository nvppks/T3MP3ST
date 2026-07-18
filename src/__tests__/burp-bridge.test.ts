import { describe, expect, it } from 'vitest';
import { BurpBridgeStore } from '../integrations/burp/index.js';
import type { BurpCapture } from '../integrations/burp/index.js';

const scope = {
  program: 'Example Bounty',
  included: [{ host: 'api.example.com', paths: ['/api/*'], methods: ['GET'] }],
  excluded: [{ host: 'api.example.com', paths: ['/api/logout'] }],
};

function capture(identityId: string, role: string, tenant: string, objectId: string, status: number, responseBody: unknown): BurpCapture {
  return {
    scope,
    identity: { id: identityId, role, tenant },
    observation: {
      identityId,
      method: 'GET',
      url: `https://api.example.com/api/orders/${objectId}`,
      status,
      responseBody,
      responseHeaders: { 'content-type': 'application/json' },
      evidenceIds: [`${identityId}-${objectId}`],
    },
  };
}

describe('BurpBridgeStore', () => {
  it('imports scoped captures into the endpoint graph', () => {
    const store = new BurpBridgeStore();
    store.importCapture(capture('user-a', 'user', 'tenant-a', '1001', 200, { id: 1001 }));
    store.importCapture(capture('user-b', 'user', 'tenant-b', '1001', 200, { id: 1001 }));

    const endpoints = store.graph.listEndpoints();
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].normalizedPath).toBe('/api/orders/{int}');
    expect(endpoints[0].identities).toEqual(['user-a', 'user-b']);
  });

  it('rejects out-of-scope captures before storage', () => {
    const store = new BurpBridgeStore();
    const item = capture('user-a', 'user', 'tenant-a', '1001', 200, { id: 1001 });
    item.observation.url = 'https://evil.example.net/api/orders/1001';
    expect(() => store.importCapture(item)).toThrow(/scope denied/);
    expect(store.listObservations()).toHaveLength(0);
  });

  it('creates a cross-tenant authorization candidate', () => {
    const store = new BurpBridgeStore();
    store.importCapture(capture('user-a', 'user', 'tenant-a', '1001', 200, { id: 1001, owner: 'A' }));
    store.importCapture(capture('user-b', 'user', 'tenant-b', '1001', 200, { id: 1001, owner: 'A' }));
    store.importCapture(capture('user-b', 'user', 'tenant-b', '999999', 404, { error: 'not found' }));

    const candidate = store.analyze({
      ownerIdentityId: 'user-a',
      attackerIdentityId: 'user-b',
      baselineEvidenceId: 'user-a-1001',
      exploitEvidenceId: 'user-b-1001',
      negativeControlEvidenceId: 'user-b-999999',
    });

    expect(candidate?.vulnerabilityClass).toBe('CROSS_TENANT');
    expect(candidate?.confidence).toBeGreaterThan(0.8);
  });
});
