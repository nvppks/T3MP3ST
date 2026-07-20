import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { HarnessControlPlane } from '../harness/control-plane.js';

let rootDir = '';
let plane: HarnessControlPlane | undefined;
let clock = 1_000;

beforeEach(async () => {
  rootDir = await mkdtemp(join(tmpdir(), 't3mp3st-harness-'));
  clock = 1_000;
  plane = await HarnessControlPlane.open({ rootDir, now: () => clock });
});

afterEach(async () => {
  await plane?.close();
  plane = undefined;
  await rm(rootDir, { recursive: true, force: true });
});

async function addProgram(options: { maxConcurrency?: number; maxRequestsPerSecond?: number } = {}): Promise<void> {
  await plane!.upsertProgram({
    id: 'acme-bounty',
    label: 'ACME bounty',
    scope: {
      program: 'placeholder',
      included: [{
        host: 'app.example.test',
        includeSubdomains: true,
        methods: ['GET', 'POST'],
      }],
      excluded: [{ host: 'admin.app.example.test' }],
    },
    maxConcurrency: options.maxConcurrency,
    maxRequestsPerSecond: options.maxRequestsPerSecond,
  });
}

describe('HarnessControlPlane', () => {
  it('persists queue lifecycle and append-only events', async () => {
    await addProgram({ maxRequestsPerSecond: 100 });
    const job = await plane!.enqueueJob({
      programId: 'acme-bounty',
      kind: 'replay',
      target: { url: 'https://app.example.test/api/orders/123?view=full', method: 'GET' },
      config: { requestArtifactId: 'future-ref' },
    });

    const leased = await plane!.leaseNext({ workerId: 'burp-worker', now: clock, leaseMs: 5_000 });
    expect(leased?.id).toBe(job.id);
    await plane!.markRunning(job.id, 'burp-worker', clock);

    const result = await plane!.putArtifact({
      programId: 'acme-bounty',
      content: '{"status":200}',
      mediaType: 'application/json',
      tier: 'report',
      fileName: 'result.json',
    });
    await plane!.completeJob({
      jobId: job.id,
      workerId: 'burp-worker',
      resultArtifactIds: [result.id],
      resultSummary: 'HTTP 200 reproduced',
      now: clock,
    });

    const tokenPath = plane!.apiTokenPath;
    const token = (await readFile(tokenPath, 'utf8')).trim();
    await plane!.close();
    plane = await HarnessControlPlane.open({ rootDir, now: () => clock });

    expect(plane!.verifyApiToken(token)).toBe(true);
    expect((await plane!.getJob(job.id)).status).toBe('completed');
    const { events } = await plane!.readEvents();
    expect(events.map((event) => event.type)).toEqual(expect.arrayContaining([
      'program.upserted',
      'job.enqueued',
      'job.leased',
      'job.running',
      'job.completed',
    ]));
  });

  it('keeps raw requests sealed while preserving report-safe evidence', async () => {
    await addProgram();
    await plane!.upsertAuthCapsule({
      id: 'user-a',
      programId: 'acme-bounty',
      owner: 'burp',
      label: 'User A',
      role: 'user',
      replayReference: 'burp:user-a',
    });

    const rawToken = 'Bearer test-token-1234567890abcdef';
    const pathToken = 'abcdef0123456789abcdef0123456789';
    const request = await plane!.ingestRequest({
      programId: 'acme-bounty',
      source: 'burp',
      method: 'GET',
      url: `https://app.example.test/api/orders/123/${pathToken}?access_token=abc123&view=full`,
      headers: {
        Authorization: rawToken,
        Cookie: 'session=operator-secret',
        Accept: 'application/json',
      },
      bodyBase64: Buffer.from('hello').toString('base64'),
      authCapsuleId: 'user-a',
      capturedAt: clock,
    });

    expect(request.pathTemplate).toBe('/api/orders/{int}/{hex}');
    expect(request.path).toBe('/api/orders/123/redacted');
    expect(request.displayUrl).not.toContain('abc123');
    expect(request.displayUrl).not.toContain(pathToken);
    await expect(plane!.readArtifact(request.sealedRequestArtifactId)).rejects.toThrow(/sealed artifact/);

    const sealed = await plane!.readArtifact(request.sealedRequestArtifactId, { allowSealed: true });
    expect(sealed.toString()).toContain(rawToken);
    expect(sealed.toString()).toContain(pathToken);
    const report = await plane!.readArtifact(request.reportRequestArtifactId);
    expect(report.toString()).not.toContain(rawToken);
    expect(report.toString()).not.toContain(pathToken);
    expect(report.toString()).toContain('[redacted]');

    const state = await readFile(plane!.statePath, 'utf8');
    expect(state).not.toContain(rawToken);
    expect(state).not.toContain('operator-secret');
    expect(state).not.toContain(pathToken);
  });

  it('rejects off-scope work and inline secret-like job config', async () => {
    await addProgram();
    await expect(plane!.ingestRequest({
      programId: 'acme-bounty',
      source: 'manual',
      method: 'GET',
      url: 'https://evil.example.test/private',
    })).rejects.toThrow(/scope denied/);

    await expect(plane!.enqueueJob({
      programId: 'acme-bounty',
      kind: 'nuclei',
      target: { url: 'https://app.example.test/' },
      config: { authorization: 'Bearer abcdefghijklmnop' },
    })).rejects.toThrow(/inline secret-like value/);
  });

  it('enforces program concurrency', async () => {
    await addProgram({ maxConcurrency: 1, maxRequestsPerSecond: 100 });
    const first = await plane!.enqueueJob({ programId: 'acme-bounty', kind: 'replay' });
    const second = await plane!.enqueueJob({ programId: 'acme-bounty', kind: 'replay' });

    expect((await plane!.leaseNext({ workerId: 'worker-a', now: 1_000, leaseMs: 5_000 }))?.id).toBe(first.id);
    expect(await plane!.leaseNext({ workerId: 'worker-b', now: 1_000, leaseMs: 5_000 })).toBeNull();
    await plane!.completeJob({ jobId: first.id, workerId: 'worker-a', now: 1_000 });
    expect((await plane!.leaseNext({ workerId: 'worker-b', now: 1_000, leaseMs: 5_000 }))?.id).toBe(second.id);
  });

  it('requeues expired leases and fails them after max attempts', async () => {
    await addProgram({ maxConcurrency: 1, maxRequestsPerSecond: 100 });
    const job = await plane!.enqueueJob({
      programId: 'acme-bounty',
      kind: 'replay',
      maxAttempts: 2,
    });

    expect((await plane!.leaseNext({ workerId: 'worker-a', now: 1_000, leaseMs: 1_000 }))?.id).toBe(job.id);
    expect(await plane!.leaseNext({ workerId: 'worker-b', now: 2_500, leaseMs: 1_000 })).toBeNull();
    expect((await plane!.getJob(job.id)).status).toBe('queued');

    expect((await plane!.leaseNext({ workerId: 'worker-b', now: 3_500, leaseMs: 1_000 }))?.id).toBe(job.id);
    expect(await plane!.leaseNext({ workerId: 'worker-c', now: 5_000, leaseMs: 1_000 })).toBeNull();
    expect((await plane!.getJob(job.id)).status).toBe('failed');
  });

  it('aborts a registered runner when a job is killed', async () => {
    await addProgram({ maxRequestsPerSecond: 100 });
    const job = await plane!.enqueueJob({ programId: 'acme-bounty', kind: 'leaklens' });
    await plane!.leaseNext({ workerId: 'worker-a', now: clock });
    await plane!.markRunning(job.id, 'worker-a', clock);

    const controller = new AbortController();
    await plane!.registerAbortController(job.id, 'worker-a', controller);
    await plane!.killJob(job.id, 'operator stop');

    expect(controller.signal.aborted).toBe(true);
    expect((await plane!.getJob(job.id)).status).toBe('killed');
    await expect(plane!.completeJob({
      jobId: job.id,
      workerId: 'worker-a',
    })).rejects.toThrow(/not leased/);
  });

  it('exports report-safe and private-full evidence bundles by tier', async () => {
    await addProgram();
    const sealed = await plane!.putArtifact({
      programId: 'acme-bounty',
      content: 'FULL_SECRET_VALUE',
      mediaType: 'text/plain',
      tier: 'sealed',
      fileName: 'secret.txt',
    });
    const operator = await plane!.putArtifact({
      programId: 'acme-bounty',
      content: 'raw response evidence',
      mediaType: 'text/plain',
      tier: 'operator',
      fileName: 'response.txt',
    });
    const report = await plane!.putArtifact({
      programId: 'acme-bounty',
      content: 'masked: FULL…ALUE',
      mediaType: 'text/plain',
      tier: 'report',
      fileName: 'report-evidence.txt',
    });

    const safeBundle = await plane!.createEvidenceBundle({
      programId: 'acme-bounty',
      findingId: 'finding-1',
      mode: 'report-safe',
      reportMarkdown: '# Finding\n\nBearer abcdefghijklmnopqrstuvwxyz',
      artifactIds: [sealed.id, operator.id, report.id],
    });
    expect(safeBundle.entries.filter((entry) => entry.included).map((entry) => entry.tier)).toEqual(['report']);
    const safeReadme = await readFile(join(rootDir, safeBundle.relativePath, 'README.md'), 'utf8');
    expect(safeReadme).toContain('Bearer [redacted]');

    const privateBundle = await plane!.createEvidenceBundle({
      programId: 'acme-bounty',
      findingId: 'finding-1',
      mode: 'private-full',
      reportMarkdown: '# Private finding',
      artifactIds: [sealed.id, operator.id, report.id],
    });
    expect(privateBundle.entries.every((entry) => entry.included)).toBe(true);
    const sealedEntry = privateBundle.entries.find((entry) => entry.artifactId === sealed.id);
    expect(sealedEntry?.relativePath).toBeTruthy();
    expect(await readFile(join(rootDir, privateBundle.relativePath, sealedEntry!.relativePath!), 'utf8'))
      .toBe('FULL_SECRET_VALUE');
  });
});
