import { randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { isGatedRisk } from '../arsenal/approval.js';
import { redactString } from '../redact.js';
import type { RiskTier } from '../types/index.js';
import type { HarnessControlPlane } from './control-plane.js';
import type { HarnessRunnerDefinition } from './runner-contract.js';
import type { HarnessJob } from './types.js';

export type HarnessApprovalStatus = 'pending' | 'approved' | 'denied';

export interface HarnessApprovalReceipt {
  id: string;
  programId: string;
  jobId: string;
  runnerKind: string;
  riskTier: RiskTier;
  action: string;
  target?: string;
  status: HarnessApprovalStatus;
  createdAt: number;
  decidedAt?: number;
  decisionNote?: string;
}

interface HarnessApprovalState {
  version: 1;
  receipts: Record<string, HarnessApprovalReceipt>;
}

export interface HarnessApprovalDecision {
  allowed: boolean;
  receipt?: HarnessApprovalReceipt;
  reason: string;
}

function cloneReceipt(receipt: HarnessApprovalReceipt): HarnessApprovalReceipt {
  return JSON.parse(JSON.stringify(receipt)) as HarnessApprovalReceipt;
}

export class HarnessApprovalStore {
  readonly path: string;
  private readonly state: HarnessApprovalState;
  private tail: Promise<void> = Promise.resolve();

  private constructor(
    rootDir: string,
    state: HarnessApprovalState,
    private readonly now: () => number,
  ) {
    this.path = join(rootDir, 'approvals.json');
    this.state = state;
  }

  static async open(rootDir: string, now: () => number = Date.now): Promise<HarnessApprovalStore> {
    await mkdir(rootDir, { recursive: true, mode: 0o700 });
    const path = join(rootDir, 'approvals.json');
    let state: HarnessApprovalState = { version: 1, receipts: {} };
    try {
      const parsed = JSON.parse(await readFile(path, 'utf8')) as Partial<HarnessApprovalState>;
      if (parsed.version === 1 && parsed.receipts && typeof parsed.receipts === 'object') {
        state = { version: 1, receipts: parsed.receipts };
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const store = new HarnessApprovalStore(rootDir, state, now);
    await store.persist();
    return store;
  }

  async ensure(job: HarnessJob, runner: HarnessRunnerDefinition): Promise<HarnessApprovalDecision> {
    if (!isGatedRisk(runner.riskTier)) {
      return { allowed: true, reason: `runner risk ${runner.riskTier} is not approval-gated` };
    }

    return this.exclusive(async () => {
      const existing = Object.values(this.state.receipts)
        .find((receipt) => receipt.jobId === job.id && receipt.runnerKind === runner.kind);
      if (existing) {
        return {
          allowed: existing.status === 'approved',
          receipt: cloneReceipt(existing),
          reason: existing.status === 'approved'
            ? `approval receipt ${existing.id} approved`
            : `approval receipt ${existing.id} is ${existing.status}`,
        };
      }

      const receipt: HarnessApprovalReceipt = {
        id: `approval_${randomUUID()}`,
        programId: job.programId,
        jobId: job.id,
        runnerKind: runner.kind,
        riskTier: runner.riskTier,
        action: redactString(`${runner.kind}: ${runner.description}`).slice(0, 500),
        target: job.target?.displayUrl,
        status: 'pending',
        createdAt: this.now(),
      };
      this.state.receipts[receipt.id] = receipt;
      await this.persist();
      return {
        allowed: false,
        receipt: cloneReceipt(receipt),
        reason: `approval required: ${receipt.id}`,
      };
    });
  }

  list(filter: { programId?: string; status?: HarnessApprovalStatus } = {}): HarnessApprovalReceipt[] {
    return Object.values(this.state.receipts)
      .filter((receipt) => !filter.programId || receipt.programId === filter.programId)
      .filter((receipt) => !filter.status || receipt.status === filter.status)
      .sort((a, b) => b.createdAt - a.createdAt)
      .map(cloneReceipt);
  }

  get(id: string): HarnessApprovalReceipt {
    const receipt = this.state.receipts[id];
    if (!receipt) throw new Error(`unknown approval receipt: ${id}`);
    return cloneReceipt(receipt);
  }

  async approve(
    id: string,
    plane: HarnessControlPlane,
    decisionNote?: string,
  ): Promise<HarnessApprovalReceipt> {
    return this.exclusive(async () => {
      const receipt = this.requireMutable(id);
      receipt.status = 'approved';
      receipt.decidedAt = this.now();
      receipt.decisionNote = decisionNote ? redactString(decisionNote).slice(0, 500) : undefined;
      await this.persist();

      const job = await plane.getJob(receipt.jobId);
      if (job.status === 'paused') await plane.resumeJob(job.id);
      return cloneReceipt(receipt);
    });
  }

  async deny(
    id: string,
    plane: HarnessControlPlane,
    decisionNote?: string,
  ): Promise<HarnessApprovalReceipt> {
    return this.exclusive(async () => {
      const receipt = this.requireMutable(id);
      receipt.status = 'denied';
      receipt.decidedAt = this.now();
      receipt.decisionNote = decisionNote ? redactString(decisionNote).slice(0, 500) : undefined;
      await this.persist();

      const job = await plane.getJob(receipt.jobId);
      if (!['completed', 'failed', 'killed'].includes(job.status)) {
        await plane.killJob(job.id, `approval denied: ${receipt.id}`);
      }
      return cloneReceipt(receipt);
    });
  }

  private requireMutable(id: string): HarnessApprovalReceipt {
    const receipt = this.state.receipts[id];
    if (!receipt) throw new Error(`unknown approval receipt: ${id}`);
    if (receipt.status !== 'pending') {
      throw new Error(`approval receipt is already ${receipt.status}: ${id}`);
    }
    return receipt;
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release: (() => void) | undefined;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }

  private async persist(): Promise<void> {
    const temporary = `${this.path}.tmp`;
    await writeFile(temporary, `${JSON.stringify(this.state, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, this.path);
    await chmod(this.path, 0o600);
  }
}
