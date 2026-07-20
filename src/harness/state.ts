import {
  appendFile,
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  unlink,
  writeFile,
} from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { dirname, join } from 'node:path';
import { redactSecrets } from '../redact.js';
import type { HarnessEvent, HarnessSnapshot } from './types.js';

const STATE_VERSION = 1 as const;
const MAX_EVENT_LIMIT = 1_000;

export interface HarnessStateRepositoryOptions {
  rootDir: string;
  apiToken?: string;
  now?: () => number;
}

export type EmitHarnessEvent = (
  type: string,
  context?: {
    at?: number;
    programId?: string;
    jobId?: string;
    data?: Record<string, unknown>;
  },
) => HarnessEvent;

export function defaultHarnessSnapshot(): HarnessSnapshot {
  return {
    version: STATE_VERSION,
    globalState: 'active',
    sequence: 0,
    programs: {},
    authCapsules: {},
    artifacts: {},
    bundles: {},
    requests: {},
    jobs: {},
    rateBuckets: {},
  };
}

export function cloneValue<T>(value: T): T {
  return structuredClone(value);
}

export class HarnessStateRepository {
  readonly rootDir: string;
  readonly statePath: string;
  readonly eventsPath: string;
  readonly apiTokenPath: string;

  private readonly nowFn: () => number;
  private readonly configuredApiToken?: string;
  private state: HarnessSnapshot = defaultHarnessSnapshot();
  private serial: Promise<void> = Promise.resolve();
  private lockHandle?: FileHandle;
  private apiToken = '';
  private closed = false;

  private constructor(options: HarnessStateRepositoryOptions) {
    this.rootDir = options.rootDir;
    this.statePath = join(this.rootDir, 'state.json');
    this.eventsPath = join(this.rootDir, 'events.jsonl');
    this.apiTokenPath = join(this.rootDir, 'api-token');
    this.nowFn = options.now ?? Date.now;
    this.configuredApiToken = options.apiToken?.trim() || undefined;
  }

  static async open(options: HarnessStateRepositoryOptions): Promise<HarnessStateRepository> {
    const repository = new HarnessStateRepository(options);
    try {
      await repository.initialize();
      return repository;
    } catch (error) {
      await repository.close().catch(() => undefined);
      throw error;
    }
  }

  now(): number {
    return this.nowFn();
  }

  verifyApiToken(candidate: string | undefined): boolean {
    if (!candidate || !this.apiToken) return false;
    const left = Buffer.from(candidate);
    const right = Buffer.from(this.apiToken);
    return left.length === right.length && timingSafeEqual(left, right);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    await this.serial;
    this.closed = true;
    if (this.lockHandle) {
      await this.lockHandle.close().catch(() => undefined);
      this.lockHandle = undefined;
      await unlink(join(this.rootDir, 'control.lock')).catch(() => undefined);
    }
  }

  async snapshot(): Promise<HarnessSnapshot> {
    this.ensureOpen();
    await this.serial;
    return cloneValue(this.state);
  }

  async mutate<T>(
    operation: (state: HarnessSnapshot, emit: EmitHarnessEvent) => Promise<T> | T,
  ): Promise<T> {
    this.ensureOpen();
    const run = this.serial.then(async () => {
      const events: HarnessEvent[] = [];
      const emit: EmitHarnessEvent = (type, context = {}) => {
        const event: HarnessEvent = {
          id: `evt_${randomUUID()}`,
          seq: ++this.state.sequence,
          at: context.at ?? this.now(),
          type,
          programId: context.programId,
          jobId: context.jobId,
          data: context.data
            ? redactSecrets(context.data) as Record<string, unknown>
            : undefined,
        };
        events.push(event);
        return event;
      };
      const result = await operation(this.state, emit);
      await this.persist(events);
      return result;
    });
    this.serial = run.then(() => undefined, () => undefined);
    return run;
  }

  async readEvents(cursor = 0, limit = 200): Promise<{ events: HarnessEvent[]; nextCursor: number }> {
    this.ensureOpen();
    await this.serial;
    const normalizedCursor = Number.isFinite(cursor) ? Math.max(0, Math.trunc(cursor)) : 0;
    const boundedLimit = boundedInteger(limit, 200, 1, MAX_EVENT_LIMIT);
    let content = '';
    try {
      content = await readFile(this.eventsPath, 'utf8');
    } catch (error) {
      if (!isErrorCode(error, 'ENOENT')) throw error;
    }

    const events: HarnessEvent[] = [];
    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line) as HarnessEvent;
        if (event.seq > normalizedCursor) events.push(event);
      } catch {
        // Ignore a truncated final JSONL line; state.json remains authoritative.
      }
      if (events.length >= boundedLimit) break;
    }
    return {
      events,
      nextCursor: events.at(-1)?.seq ?? normalizedCursor,
    };
  }

  private async initialize(): Promise<void> {
    await mkdir(this.rootDir, { recursive: true, mode: 0o700 });
    await chmod(this.rootDir, 0o700).catch(() => undefined);
    await this.acquireLock();
    this.apiToken = await this.loadApiToken();
    try {
      const raw = await readFile(this.statePath, 'utf8');
      this.state = assertSnapshot(JSON.parse(raw));
    } catch (error) {
      if (!isErrorCode(error, 'ENOENT')) throw error;
      this.state = defaultHarnessSnapshot();
      await this.persist([]);
    }
  }

  private async acquireLock(): Promise<void> {
    const lockPath = join(this.rootDir, 'control.lock');
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        this.lockHandle = await open(lockPath, 'wx', 0o600);
        await this.lockHandle.writeFile(`${process.pid}\n`, 'utf8');
        return;
      } catch (error) {
        if (!isErrorCode(error, 'EEXIST')) throw error;
        const existingPid = Number((await readFile(lockPath, 'utf8').catch(() => '')).trim());
        if (processIsAlive(existingPid)) {
          throw new Error(`harness state is already locked by pid ${existingPid}`);
        }
        await unlink(lockPath).catch(() => undefined);
      }
    }
    throw new Error('unable to acquire harness state lock');
  }

  private async loadApiToken(): Promise<string> {
    if (this.configuredApiToken) {
      await writeFile(this.apiTokenPath, `${this.configuredApiToken}\n`, { mode: 0o600 });
      await chmod(this.apiTokenPath, 0o600).catch(() => undefined);
      return this.configuredApiToken;
    }
    try {
      const existing = (await readFile(this.apiTokenPath, 'utf8')).trim();
      if (existing.length < 32) throw new Error('harness api-token file is invalid');
      return existing;
    } catch (error) {
      if (!isErrorCode(error, 'ENOENT')) throw error;
    }
    const token = randomBytes(32).toString('hex');
    await writeFile(this.apiTokenPath, `${token}\n`, { flag: 'wx', mode: 0o600 });
    await chmod(this.apiTokenPath, 0o600).catch(() => undefined);
    return token;
  }

  private async persist(events: HarnessEvent[]): Promise<void> {
    const temporary = join(
      dirname(this.statePath),
      `.state-${process.pid}-${randomUUID()}.tmp`,
    );
    await writeFile(temporary, `${JSON.stringify(this.state, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, this.statePath);
    await chmod(this.statePath, 0o600).catch(() => undefined);
    if (events.length) {
      const lines = `${events.map((event) => JSON.stringify(event)).join('\n')}\n`;
      await appendFile(this.eventsPath, lines, { mode: 0o600 });
      await chmod(this.eventsPath, 0o600).catch(() => undefined);
    }
  }

  private ensureOpen(): void {
    if (this.closed) throw new Error('harness control plane is closed');
  }
}

function assertSnapshot(value: unknown): HarnessSnapshot {
  if (!value || typeof value !== 'object') throw new Error('invalid harness state snapshot');
  const snapshot = value as Partial<HarnessSnapshot>;
  if (snapshot.version !== STATE_VERSION) {
    throw new Error(`unsupported harness state version: ${String(snapshot.version)}`);
  }
  if (!snapshot.programs || !snapshot.jobs || !snapshot.artifacts || !snapshot.requests) {
    throw new Error('harness state snapshot is missing required collections');
  }
  return {
    ...defaultHarnessSnapshot(),
    ...snapshot,
    programs: snapshot.programs,
    authCapsules: snapshot.authCapsules ?? {},
    artifacts: snapshot.artifacts,
    bundles: snapshot.bundles ?? {},
    requests: snapshot.requests,
    jobs: snapshot.jobs,
    rateBuckets: snapshot.rateBuckets ?? {},
  };
}

function boundedInteger(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function isErrorCode(error: unknown, code: string): boolean {
  return !!error
    && typeof error === 'object'
    && 'code' in error
    && (error as { code?: unknown }).code === code;
}

function processIsAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return isErrorCode(error, 'EPERM');
  }
}
