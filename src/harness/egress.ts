import {
  configureProxy,
  initProxyFromConfig,
  parseProxyUrl,
} from '../net/proxy.js';
import type { HarnessControlPlane } from './control-plane.js';
import type { HarnessJob } from './types.js';

export type HarnessEgressMode = 'inherit' | 'direct' | 'socks';

export interface HarnessEgressProfile {
  mode: HarnessEgressMode;
  proxyArtifactId?: string;
}

function parseProfile(config: Record<string, unknown>): HarnessEgressProfile {
  const value = config.egress;
  if (value === undefined) return { mode: 'inherit' };
  if (typeof value === 'string') {
    if (!['inherit', 'direct', 'socks'].includes(value)) {
      throw new Error(`invalid egress mode: ${value}`);
    }
    return { mode: value as HarnessEgressMode };
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('egress must be a mode string or object');
  }
  const record = value as Record<string, unknown>;
  const mode = record.mode;
  if (typeof mode !== 'string' || !['inherit', 'direct', 'socks'].includes(mode)) {
    throw new Error(`invalid egress mode: ${String(mode)}`);
  }
  return {
    mode: mode as HarnessEgressMode,
    proxyArtifactId: typeof record.proxyArtifactId === 'string'
      ? record.proxyArtifactId.trim() || undefined
      : undefined,
  };
}

/**
 * Upstream's SOCKS dispatcher is process-global. Networked harness jobs therefore
 * execute under one shared lock whenever an explicit egress profile is applied.
 * This keeps two programs from racing to replace the global dispatcher.
 */
export class HarnessEgressManager {
  private static tail: Promise<void> = Promise.resolve();

  async run<T>(
    plane: HarnessControlPlane,
    job: HarnessJob,
    networked: boolean,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (!networked) return operation();
    const profile = parseProfile(job.config);
    if (profile.mode === 'inherit') return operation();

    return this.exclusive(async () => {
      try {
        if (profile.mode === 'direct') {
          configureProxy(null);
        } else {
          if (!profile.proxyArtifactId) {
            throw new Error('socks egress requires proxyArtifactId');
          }
          const metadata = await plane.getArtifactMetadata(profile.proxyArtifactId);
          if (metadata.programId !== job.programId) {
            throw new Error('proxy artifact belongs to another program');
          }
          if (metadata.tier !== 'sealed') {
            throw new Error('proxy URL must be stored as a sealed artifact');
          }
          const proxyUrl = (await plane.readArtifact(profile.proxyArtifactId, { allowSealed: true }))
            .toString('utf8')
            .trim();
          if (!parseProxyUrl(proxyUrl)) throw new Error('sealed proxy artifact is not a valid SOCKS URL');
          const status = configureProxy(proxyUrl);
          if (status.error) throw new Error(status.error);
        }
        return await operation();
      } finally {
        configureProxy(null);
        const restored = initProxyFromConfig();
        if (restored.error) {
          console.warn(`[harness-egress] could not restore configured proxy: ${restored.error}`);
        }
      }
    });
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = HarnessEgressManager.tail;
    let release: (() => void) | undefined;
    HarnessEgressManager.tail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }
}

export function harnessEgressProfile(config: Record<string, unknown>): HarnessEgressProfile {
  return parseProfile(config);
}
