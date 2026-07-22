import {
  createMultiLangIngestConfig,
  ingestRepository,
  type AnalysisUnit,
} from '../../recon/code-ingest.js';
import { initGrammars } from '../../recon/ts-grammars.js';
import type { HarnessRunnerDefinition } from '../runner-contract.js';

function numberValue(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? Math.trunc(value) : fallback;
}

function throwIfAborted(signal: AbortSignal): void {
  if (!signal.aborted) return;
  throw signal.reason instanceof Error ? signal.reason : new Error('white-box job aborted');
}

function reportUnit(unit: AnalysisUnit): Record<string, unknown> {
  return {
    id: unit.block.id,
    path: unit.block.path,
    name: unit.block.name,
    kind: unit.block.kind,
    lineStart: unit.block.lineStart,
    lineEnd: unit.block.lineEnd,
    exposure: unit.exposure,
    reachable: unit.reachable,
    reachDepth: unit.reachDepth,
    riskSignals: unit.riskSignals,
    priority: unit.priority,
  };
}

export const whiteboxIngestRunner: HarnessRunnerDefinition = {
  kind: 'whitebox_ingest',
  description: 'Run the upstream multi-language tree-sitter security ingest against a local repository path.',
  riskTier: 'local_read',
  networked: false,
  parameters: [
    {
      name: 'repoPath',
      type: 'string',
      description: 'Local repository directory to ingest.',
      required: true,
    },
    {
      name: 'maxFiles',
      type: 'number',
      description: 'Maximum files to inspect.',
      required: false,
      default: 50_000,
    },
    {
      name: 'maxTotalBytes',
      type: 'number',
      description: 'Maximum cumulative source bytes to inspect.',
      required: false,
      default: 1_000_000_000,
    },
    {
      name: 'maxFileBytes',
      type: 'number',
      description: 'Maximum bytes per source file. Hard-capped at the upstream 1 MiB safety bound.',
      required: false,
      default: 1_000_000,
    },
    {
      name: 'maxUnits',
      type: 'number',
      description: 'Maximum prioritized analysis units retained in sealed evidence.',
      required: false,
      default: 500,
    },
    {
      name: 'reportUnits',
      type: 'number',
      description: 'Maximum report-safe units emitted without source bodies.',
      required: false,
      default: 100,
    },
  ],
  async run(context) {
    const repoPath = String(context.config.repoPath ?? '').trim();
    if (!repoPath) throw new Error('repoPath is required');

    await initGrammars();
    throwIfAborted(context.signal);

    const config = createMultiLangIngestConfig(repoPath);
    config.maxFiles = Math.min(50_000, Math.max(1, numberValue(context.config.maxFiles, 50_000)));
    config.maxTotalBytes = Math.min(
      1_000_000_000,
      Math.max(1, numberValue(context.config.maxTotalBytes, 1_000_000_000)),
    );
    config.maxFileBytes = Math.min(
      1_000_000,
      Math.max(1, numberValue(context.config.maxFileBytes, 1_000_000)),
    );

    const result = ingestRepository(config);
    throwIfAborted(context.signal);

    const maxUnits = Math.min(2_000, Math.max(1, numberValue(context.config.maxUnits, 500)));
    const reportUnits = Math.min(500, Math.max(1, numberValue(context.config.reportUnits, 100)));
    const retained = result.analysisUnits.slice(0, maxUnits);
    const report = {
      runner: 'whitebox_ingest',
      repoPath,
      stats: result.stats,
      entryPoints: result.entryPoints,
      retainedUnits: retained.length,
      totalUnits: result.analysisUnits.length,
      topUnits: retained.slice(0, reportUnits).map(reportUnit),
    };
    const sealed = await context.plane.putArtifact({
      programId: context.job.programId,
      content: `${JSON.stringify({ ...report, analysisUnits: retained }, null, 2)}\n`,
      mediaType: 'application/json',
      tier: 'sealed',
      fileName: 'whitebox-analysis.sealed.json',
      source: `harness:${context.job.id}`,
    });
    const reportArtifact = await context.plane.putArtifact({
      programId: context.job.programId,
      content: `${JSON.stringify(report, null, 2)}\n`,
      mediaType: 'application/json',
      tier: 'report',
      fileName: 'whitebox-analysis.report.json',
      source: `harness:${context.job.id}`,
    });

    return {
      artifacts: [sealed, reportArtifact],
      summary:
        `multi-language ingest: ${result.stats.files} files, ${result.stats.blocks} blocks, `
        + `${result.analysisUnits.length} prioritized units`,
    };
  },
};
