import { createHash, randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { basename, dirname, join, relative } from 'node:path';
import { redactString } from '../redact.js';
import type {
  HarnessArtifactMetadata,
  HarnessArtifactTier,
  HarnessBundleMode,
  HarnessEvidenceBundle,
  HarnessEvidenceBundleEntry,
} from './types.js';

export interface PutHarnessArtifactInput {
  programId: string;
  content: Uint8Array | string;
  mediaType?: string;
  tier?: HarnessArtifactTier;
  fileName?: string;
  source?: string;
  createdAt?: number;
}

export interface ReadHarnessArtifactOptions {
  allowOperator?: boolean;
  allowSealed?: boolean;
}

export interface CreateHarnessEvidenceBundleInput {
  programId: string;
  findingId: string;
  mode: HarnessBundleMode;
  reportMarkdown: string;
  artifacts: HarnessArtifactMetadata[];
  createdAt?: number;
}

function sha256(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

function artifactId(programId: string, digest: string, tier: HarnessArtifactTier): string {
  const id = createHash('sha256')
    .update(programId)
    .update('\0')
    .update(tier)
    .update('\0')
    .update(digest)
    .digest('hex');
  return `art_${id.slice(0, 32)}`;
}

function programNamespace(programId: string): string {
  return sha256(programId).slice(0, 20);
}

function safeFileName(value: string | undefined, fallback: string): string {
  const candidate = basename(value?.trim() || fallback)
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/^\.+/, '')
    .slice(0, 120);
  return candidate || fallback;
}

function tierAllowed(tier: HarnessArtifactTier, mode: HarnessBundleMode): boolean {
  if (mode === 'private-full') return true;
  if (mode === 'operator-review') return tier !== 'sealed';
  return tier === 'report';
}

export class HarnessArtifactStore {
  readonly rootDir: string;
  readonly maxArtifactBytes: number;

  constructor(rootDir: string, maxArtifactBytes = 64 * 1024 * 1024) {
    this.rootDir = rootDir;
    this.maxArtifactBytes = maxArtifactBytes;
  }

  async initialize(): Promise<void> {
    await mkdir(join(this.rootDir, 'artifacts'), { recursive: true, mode: 0o700 });
    await mkdir(join(this.rootDir, 'exports'), { recursive: true, mode: 0o700 });
  }

  async put(input: PutHarnessArtifactInput): Promise<HarnessArtifactMetadata> {
    const bytes = typeof input.content === 'string'
      ? Buffer.from(input.content, 'utf8')
      : Buffer.from(input.content);
    if (bytes.length > this.maxArtifactBytes) {
      throw new Error(`artifact exceeds ${this.maxArtifactBytes} byte limit`);
    }

    const tier = input.tier ?? 'operator';
    const digest = sha256(bytes);
    const metadata: HarnessArtifactMetadata = {
      id: artifactId(input.programId, digest, tier),
      programId: input.programId,
      sha256: digest,
      size: bytes.length,
      mediaType: input.mediaType?.trim() || 'application/octet-stream',
      tier,
      fileName: input.fileName ? safeFileName(input.fileName, `${digest}.bin`) : undefined,
      source: input.source ? redactString(input.source).slice(0, 500) : undefined,
      createdAt: input.createdAt ?? Date.now(),
    };

    const path = this.contentPath(metadata);
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    try {
      await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
    } catch (error) {
      if (!isAlreadyExists(error)) throw error;
      const existing = await readFile(path);
      if (existing.length !== bytes.length || sha256(existing) !== digest) {
        throw new Error(`existing artifact content failed integrity check: ${metadata.id}`);
      }
    }
    await chmod(path, 0o600).catch(() => undefined);
    return metadata;
  }

  async read(
    metadata: HarnessArtifactMetadata,
    options: ReadHarnessArtifactOptions = {},
  ): Promise<Buffer> {
    if (metadata.tier === 'sealed' && !options.allowSealed) {
      throw new Error('sealed artifact requires explicit reveal permission');
    }
    if (metadata.tier === 'operator' && !options.allowOperator && !options.allowSealed) {
      throw new Error('operator artifact requires explicit review permission');
    }

    const content = await readFile(this.contentPath(metadata));
    if (content.length !== metadata.size || sha256(content) !== metadata.sha256) {
      throw new Error(`artifact integrity check failed: ${metadata.id}`);
    }
    return content;
  }

  async createEvidenceBundle(
    input: CreateHarnessEvidenceBundleInput,
  ): Promise<HarnessEvidenceBundle> {
    if (!input.findingId.trim()) throw new Error('findingId is required');
    if (!['report-safe', 'operator-review', 'private-full'].includes(input.mode)) {
      throw new Error(`invalid evidence bundle mode: ${String(input.mode)}`);
    }
    if (input.artifacts.some((artifact) => artifact.programId !== input.programId)) {
      throw new Error('all evidence artifacts must belong to the same program');
    }

    const createdAt = input.createdAt ?? Date.now();
    const id = `bundle_${randomUUID()}`;
    const bundleDir = join(this.rootDir, 'exports', programNamespace(input.programId), id);
    await mkdir(bundleDir, { recursive: true, mode: 0o700 });

    const report = input.mode === 'private-full'
      ? input.reportMarkdown
      : redactString(input.reportMarkdown);
    await writePrivateFile(join(bundleDir, 'README.md'), report);

    const entries: HarnessEvidenceBundleEntry[] = [];
    for (const artifact of input.artifacts) {
      const included = tierAllowed(artifact.tier, input.mode);
      const entry: HarnessEvidenceBundleEntry = {
        artifactId: artifact.id,
        tier: artifact.tier,
        mediaType: artifact.mediaType,
        sha256: artifact.sha256,
        size: artifact.size,
        included,
      };

      if (included) {
        const directory = join(bundleDir, artifact.tier);
        await mkdir(directory, { recursive: true, mode: 0o700 });
        const name = `${artifact.id}-${safeFileName(artifact.fileName, 'evidence.bin')}`;
        const destination = join(directory, name);
        const content = await this.read(artifact, { allowOperator: true, allowSealed: true });
        await writeFile(destination, content, { mode: 0o600 });
        await chmod(destination, 0o600).catch(() => undefined);
        entry.relativePath = relative(bundleDir, destination);
      }
      entries.push(entry);
    }

    const bundle: HarnessEvidenceBundle = {
      id,
      programId: input.programId,
      findingId: input.findingId,
      mode: input.mode,
      relativePath: relative(this.rootDir, bundleDir),
      entries,
      createdAt,
    };
    await writePrivateFile(
      join(bundleDir, 'manifest.json'),
      `${JSON.stringify(bundle, null, 2)}\n`,
    );
    return bundle;
  }

  contentPath(metadata: HarnessArtifactMetadata): string {
    return join(
      this.rootDir,
      'artifacts',
      programNamespace(metadata.programId),
      metadata.sha256.slice(0, 2),
      metadata.sha256,
    );
  }
}

async function writePrivateFile(path: string, content: string): Promise<void> {
  await writeFile(path, content, { mode: 0o600 });
  await chmod(path, 0o600).catch(() => undefined);
}

function isAlreadyExists(error: unknown): boolean {
  return !!error
    && typeof error === 'object'
    && 'code' in error
    && (error as { code?: unknown }).code === 'EEXIST';
}
