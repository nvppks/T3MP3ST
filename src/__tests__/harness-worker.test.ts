import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { HarnessApprovalStore } from '../harness/approval-store.js';
import { HarnessControlPlane } from '../harness/control-plane.js';
import { createDefaultHarnessRunnerRegistry } from '../harness/default-runners.js';
import { harnessEgressProfile } from '../harness/egress.js';
import { HarnessRunnerRegistry } from '../harness/runner-contract.js';
import { HarnessWorker } from '../harness/worker.js';

const scope = {
  program: 'worker-tests',
  included: [{ host: 'app.example.test', includeSubdomains: false }],
};

describe('harness worker integration', () => {
  let rootDir: string;
  let plane: HarnessControlPlane;
  let approvals: HarnessApprovalStore;

  beforeEach(async () => {
    rootDir = await mkdtemp(join(tmpdir(), 't3mp3st-worker-'));
    plane = await HarnessControlPlane.open({ rootDir, apiToken: 'test-token' });
    approvals = await HarnessApprovalStore.open(rootDir);
    await plane.upsertProgram({ id: 'worker-tests', scope });
  });

  afterEach(async () => {
    await plane.close();
    await rm(rootDir, { recursive: true, force: true });
  });

  it('pauses an intrusive job, then resumes the exact job after receipt approval', async () => {
    let executions = 0;
    const registry = new HarnessRunnerRegistry();
    registry.register({
      kind: 'intrusive_demo',
      description: 'Test exact-job approval resume.',
      riskTier: 'intrusive',
      networked: false,
      parameters: [{
        name: 'count',
        type: 'number',
        description: 'Execution count.',
        required: true,
      }],
      run: async ({ config }) => {
        executions += Number(config.count);
        return { summary: 'approved execution completed' };
      },
    });
    const worker = new HarnessWorker(plane, registry, approvals, { workerId: 'worker-approval' });
    const job = await plane.enqueueJob({
      programId: 'worker-tests',
      kind: 'intrusive_demo',
      config: { count: '1' },
    });

    expect(await worker.runOnce()).toBe(true);
    expect((await plane.getJob(job.id)).status).toBe('paused');
    const receipt = approvals.list({ status: 'pending' })[0];
    expect(receipt).toMatchObject({ jobId: job.id, runnerKind: 'intrusive_demo' });

    await approvals.approve(receipt.id, plane, 'approved for this exact job');
    expect((await plane.getJob(job.id)).status).toBe('queued');
    expect(await worker.runOnce()).toBe(true);
    expect((await plane.getJob(job.id)).status).toBe('completed');
    expect(executions).toBe(1);
  });

  it('fails invalid job configuration before runner execution', async () => {
    const registry = createDefaultHarnessRunnerRegistry();
    const worker = new HarnessWorker(plane, registry, approvals, { workerId: 'worker-validation' });
    const job = await plane.enqueueJob({
      programId: 'worker-tests',
      kind: 'whitebox_ingest',
      config: {},
    });

    await worker.runOnce();
    const failed = await plane.getJob(job.id);
    expect(failed.status).toBe('failed');
    expect(failed.error).toContain('validation_error');
    expect(failed.error).toContain('repoPath');
  });

  it('runs upstream multi-language ingest and emits sealed plus report evidence', async () => {
    const repoPath = join(rootDir, 'sample-repo');
    await mkdir(repoPath, { recursive: true });
    await writeFile(join(repoPath, 'app.js'), `
      export async function fetchUser(userId) {
        return fetch('/api/users/' + userId);
      }
    `);

    const registry = createDefaultHarnessRunnerRegistry();
    const worker = new HarnessWorker(plane, registry, approvals, { workerId: 'worker-whitebox' });
    const job = await plane.enqueueJob({
      programId: 'worker-tests',
      kind: 'whitebox_ingest',
      config: { repoPath, maxFiles: 10, maxUnits: 20, reportUnits: 10 },
    });

    await worker.runOnce();
    const completed = await plane.getJob(job.id);
    expect(completed.status).toBe('completed');
    expect(completed.resultArtifactIds).toHaveLength(2);

    const metadata = await Promise.all(
      completed.resultArtifactIds.map((artifactId) => plane.getArtifactMetadata(artifactId)),
    );
    expect(metadata.map((artifact) => artifact.tier).sort()).toEqual(['report', 'sealed']);
    const report = metadata.find((artifact) => artifact.tier === 'report');
    expect(report).toBeDefined();
    const body = JSON.parse((await plane.readArtifact(report!.id)).toString('utf8')) as Record<string, unknown>;
    expect(body.runner).toBe('whitebox_ingest');
    expect(body).toHaveProperty('stats');
    expect(JSON.stringify(body)).not.toContain('return fetch');
  });

  it('parses explicit per-job egress profiles without accepting inline proxy URLs', () => {
    expect(harnessEgressProfile({})).toEqual({ mode: 'inherit' });
    expect(harnessEgressProfile({ egress: 'direct' })).toEqual({ mode: 'direct' });
    expect(harnessEgressProfile({
      egress: { mode: 'socks', proxyArtifactId: 'art_proxy' },
    })).toEqual({ mode: 'socks', proxyArtifactId: 'art_proxy' });
    expect(() => harnessEgressProfile({ egress: { mode: 'socks', proxyUrl: 'socks5://127.0.0.1:9050' } }))
      .not.toThrow();
  });
});
