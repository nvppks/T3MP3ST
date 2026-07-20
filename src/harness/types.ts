import type { ProgramScope } from '../bounty/index.js';

export type HarnessProgramState = 'active' | 'paused' | 'killed';
export type HarnessGlobalState = 'active' | 'paused' | 'killed';
export type HarnessJobStatus =
  | 'queued'
  | 'leased'
  | 'running'
  | 'completed'
  | 'failed'
  | 'paused'
  | 'killed';

export type HarnessArtifactTier = 'sealed' | 'operator' | 'report';
export type HarnessBundleMode = 'report-safe' | 'operator-review' | 'private-full';

export interface HarnessProgram {
  id: string;
  label: string;
  state: HarnessProgramState;
  scope: ProgramScope;
  maxConcurrency: number;
  maxRequestsPerSecond: number;
  createdAt: number;
  updatedAt: number;
}

export interface HarnessAuthCapsule {
  id: string;
  programId: string;
  owner: 'burp' | 'local-secret-store' | 'external';
  label: string;
  role: string;
  tenant?: string;
  expiresAt?: number;
  replayReference?: string;
  createdAt: number;
  updatedAt: number;
}

export interface HarnessArtifactMetadata {
  id: string;
  programId: string;
  sha256: string;
  size: number;
  mediaType: string;
  tier: HarnessArtifactTier;
  fileName?: string;
  source?: string;
  createdAt: number;
}

export interface HarnessEvidenceBundleEntry {
  artifactId: string;
  tier: HarnessArtifactTier;
  mediaType: string;
  sha256: string;
  size: number;
  included: boolean;
  relativePath?: string;
}

export interface HarnessEvidenceBundle {
  id: string;
  programId: string;
  findingId: string;
  mode: HarnessBundleMode;
  relativePath: string;
  entries: HarnessEvidenceBundleEntry[];
  createdAt: number;
}

export interface HarnessNormalizedRequest {
  id: string;
  programId: string;
  source: 'burp' | 'mitmproxy' | 'openapi' | 'manual' | 'other';
  method: string;
  scheme: 'http' | 'https';
  host: string;
  port: number;
  path: string;
  pathTemplate: string;
  displayUrl: string;
  queryParameters: string[];
  bodySha256: string;
  authCapsuleId?: string;
  sealedRequestArtifactId: string;
  reportRequestArtifactId: string;
  capturedAt: number;
}

export interface HarnessJobTarget {
  displayUrl: string;
  method: string;
  sealedUrlArtifactId: string;
}

export interface HarnessJobLease {
  workerId: string;
  leasedAt: number;
  heartbeatAt: number;
  expiresAt: number;
}

export interface HarnessJob {
  id: string;
  programId: string;
  kind: string;
  status: HarnessJobStatus;
  target?: HarnessJobTarget;
  requestId?: string;
  authCapsuleId?: string;
  payloadArtifactId?: string;
  config: Record<string, unknown>;
  priority: number;
  attempts: number;
  maxAttempts: number;
  availableAt: number;
  lease?: HarnessJobLease;
  resultArtifactIds: string[];
  resultSummary?: string;
  error?: string;
  createdAt: number;
  updatedAt: number;
  completedAt?: number;
  killedAt?: number;
}

export interface HarnessEvent {
  id: string;
  seq: number;
  at: number;
  type: string;
  programId?: string;
  jobId?: string;
  data?: Record<string, unknown>;
}

export interface HarnessRateBucket {
  tokens: number;
  updatedAt: number;
}

export interface HarnessSnapshot {
  version: 1;
  globalState: HarnessGlobalState;
  sequence: number;
  programs: Record<string, HarnessProgram>;
  authCapsules: Record<string, HarnessAuthCapsule>;
  artifacts: Record<string, HarnessArtifactMetadata>;
  bundles: Record<string, HarnessEvidenceBundle>;
  requests: Record<string, HarnessNormalizedRequest>;
  jobs: Record<string, HarnessJob>;
  rateBuckets: Record<string, HarnessRateBucket>;
}
