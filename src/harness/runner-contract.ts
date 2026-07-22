import { assertSchemaDepth, validateToolArgs } from '../validation/index.js';
import type { RiskTier, ToolParameter, ToolValidationError } from '../types/index.js';
import type { HarnessControlPlane } from './control-plane.js';
import type { HarnessArtifactMetadata, HarnessJob } from './types.js';

export interface HarnessRunnerResult {
  artifacts?: HarnessArtifactMetadata[];
  summary?: string;
}

export interface HarnessRunnerContext {
  plane: HarnessControlPlane;
  job: HarnessJob;
  workerId: string;
  signal: AbortSignal;
  config: Record<string, unknown>;
}

export interface HarnessRunnerDefinition {
  kind: string;
  description: string;
  riskTier: RiskTier;
  networked: boolean;
  parameters: ToolParameter[];
  run: (context: HarnessRunnerContext) => Promise<HarnessRunnerResult>;
}

export interface HarnessRunnerSummary {
  kind: string;
  description: string;
  riskTier: RiskTier;
  networked: boolean;
  parameters: ToolParameter[];
}

export interface HarnessConfigValidation {
  config: Record<string, unknown>;
  errors: ToolValidationError[];
}

function cloneConfig(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}

export class HarnessRunnerRegistry {
  private readonly runners = new Map<string, HarnessRunnerDefinition>();

  register(definition: HarnessRunnerDefinition): void {
    const kind = definition.kind.trim();
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(kind)) {
      throw new Error('runner kind must match [A-Za-z0-9._:-] and be 1-128 characters');
    }
    if (this.runners.has(kind)) throw new Error(`runner already registered: ${kind}`);
    assertSchemaDepth(definition.parameters);
    this.runners.set(kind, { ...definition, kind });
  }

  require(kind: string): HarnessRunnerDefinition {
    const runner = this.runners.get(kind);
    if (!runner) throw new Error(`no runner registered for job kind: ${kind}`);
    return runner;
  }

  get(kind: string): HarnessRunnerDefinition | undefined {
    return this.runners.get(kind);
  }

  validate(kind: string, config: Record<string, unknown>): HarnessConfigValidation {
    const runner = this.require(kind);
    const normalized = cloneConfig(config);
    return {
      config: normalized,
      errors: validateToolArgs(kind, normalized, runner.parameters),
    };
  }

  list(): HarnessRunnerSummary[] {
    return [...this.runners.values()]
      .sort((a, b) => a.kind.localeCompare(b.kind))
      .map((runner) => ({
        kind: runner.kind,
        description: runner.description,
        riskTier: runner.riskTier,
        networked: runner.networked,
        parameters: runner.parameters.map((parameter) => ({ ...parameter })),
      }));
  }
}

export function formatHarnessValidationErrors(errors: ToolValidationError[]): string {
  return errors
    .map((error) => `${error.field}: ${error.message} (expected ${error.expected})`)
    .join('; ')
    .slice(0, 4_000);
}
