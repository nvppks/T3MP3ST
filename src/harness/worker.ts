import { randomUUID } from 'node:crypto';
import { redactString } from '../redact.js';
import type { HarnessControlPlane } from './control-plane.js';
import { HarnessApprovalStore } from './approval-store.js';
import { HarnessEgressManager } from './egress.js';
import {
  formatHarnessValidationErrors,
  HarnessRunnerRegistry,
} from './runner-contract.js';
import type { HarnessJob } from './types.js';

export interface HarnessWorkerOptions {
  workerId?: string;
  pollMs?: number;
  leaseMs?: number;
  kinds?: string[];
}

export interface HarnessWorkerStatus {
  running: boolean;
  workerId: string;
  activeJobId?: string;
  kinds?: string[];
}

function bounded(value: number | undefined, fallback: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(value as number)));
}

function errorMessage(error: unknown): string {
  return redactString(error instanceof Error ? error.message : String(error)).slice(0, 4_000);
}

function retryableError(error: unknown): boolean {
  const message = errorMessage(error).toLowerCase();
  return /timeout|temporar|econnreset|econnrefused|rate limit|429|503|unavailable/.test(message);
}

export class HarnessWorker {
  readonly workerId: string;
  private readonly pollMs: number;
  private readonly leaseMs: number;
  private readonly kinds?: string[];
  private readonly egress = new HarnessEgressManager();
  private running = false;
  private loopPromise?: Promise<void>;
  private activeJobId?: string;
  private activeController?: AbortController;

  constructor(
    private readonly plane: HarnessControlPlane,
    private readonly registry: HarnessRunnerRegistry,
    private readonly approvals: HarnessApprovalStore,
    options: HarnessWorkerOptions = {},
  ) {
    this.workerId = options.workerId?.trim() || `worker_${randomUUID()}`;
    this.pollMs = bounded(options.pollMs, 500, 50, 30_000);
    this.leaseMs = bounded(options.leaseMs, 60_000, 5_000, 15 * 60_000);
    this.kinds = options.kinds?.map((kind) => kind.trim()).filter(Boolean);
  }

  status(): HarnessWorkerStatus {
    return {
      running: this.running,
      workerId: this.workerId,
      activeJobId: this.activeJobId,
      kinds: this.kinds ? [...this.kinds] : undefined,
    };
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.loopPromise = this.loop();
  }

  async stop(): Promise<void> {
    this.running = false;
    this.activeController?.abort(new Error('harness worker stopping'));
    await this.loopPromise;
  }

  async runOnce(): Promise<boolean> {
    const job = await this.plane.leaseNext({
      workerId: this.workerId,
      kinds: this.kinds,
      leaseMs: this.leaseMs,
    });
    if (!job) return false;
    this.activeJobId = job.id;

    const runner = this.registry.get(job.kind);
    if (!runner) {
      await this.plane.failJob({
        jobId: job.id,
        workerId: this.workerId,
        error: `no runner registered for job kind: ${job.kind}`,
        retryable: false,
      });
      this.activeJobId = undefined;
      return true;
    }

    const validation = this.registry.validate(job.kind, job.config);
    if (validation.errors.length > 0) {
      await this.plane.failJob({
        jobId: job.id,
        workerId: this.workerId,
        error: `validation_error: ${formatHarnessValidationErrors(validation.errors)}`,
        retryable: false,
      });
      this.activeJobId = undefined;
      return true;
    }

    const approval = await this.approvals.ensure(job, runner);
    if (!approval.allowed) {
      const latest = await this.plane.getJob(job.id);
      if (!['completed', 'failed', 'killed', 'paused'].includes(latest.status)) {
        await this.plane.pauseJob(job.id);
      }
      this.activeJobId = undefined;
      return true;
    }

    const controller = new AbortController();
    this.activeController = controller;
    await this.plane.registerAbortController(job.id, this.workerId, controller);
    await this.plane.markRunning(job.id, this.workerId);

    const heartbeat = setInterval(() => {
      void this.plane.heartbeat(job.id, this.workerId, this.leaseMs)
        .catch((error) => console.warn(`[harness-worker] heartbeat failed: ${errorMessage(error)}`));
    }, Math.max(1_000, Math.floor(this.leaseMs / 3)));
    heartbeat.unref?.();

    try {
      const result = await this.egress.run(
        this.plane,
        job,
        runner.networked,
        () => runner.run({
          plane: this.plane,
          job,
          workerId: this.workerId,
          signal: controller.signal,
          config: validation.config,
        }),
      );
      await this.plane.completeJob({
        jobId: job.id,
        workerId: this.workerId,
        resultArtifactIds: result.artifacts?.map((artifact) => artifact.id),
        resultSummary: result.summary,
      });
    } catch (error) {
      const latest = await this.plane.getJob(job.id).catch(() => undefined);
      if (!latest || !['paused', 'killed'].includes(latest.status)) {
        await this.plane.failJob({
          jobId: job.id,
          workerId: this.workerId,
          error: controller.signal.aborted
            ? `execution_aborted: ${errorMessage(controller.signal.reason ?? error)}`
            : `execution_error: ${errorMessage(error)}`,
          retryable: !controller.signal.aborted && retryableError(error),
          retryDelayMs: 2_000,
        });
      }
    } finally {
      clearInterval(heartbeat);
      this.activeController = undefined;
      this.activeJobId = undefined;
    }
    return true;
  }

  private async loop(): Promise<void> {
    while (this.running) {
      try {
        const handled = await this.runOnce();
        if (!handled) await this.sleep(this.pollMs);
      } catch (error) {
        console.error(`[harness-worker] loop error: ${errorMessage(error)}`);
        await this.sleep(this.pollMs);
      }
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

export function jobUsesApproval(job: HarnessJob, registry: HarnessRunnerRegistry): boolean {
  const runner = registry.get(job.kind);
  return runner ? ['intrusive', 'credential', 'dangerous'].includes(runner.riskTier) : false;
}
