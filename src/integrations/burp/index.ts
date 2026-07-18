import { randomUUID } from 'node:crypto';
import type { Request, Response, Router } from 'express';
import express from 'express';
import {
  AssetGraph,
  analyzeAuthzDifferential,
  evaluateProgramScope,
  type AuthzCandidate,
  type HttpObservation,
  type IdentityContext,
  type ProgramScope,
} from '../../bounty/index.js';

export interface BurpCapture {
  identity: IdentityContext;
  observation: HttpObservation;
  scope: ProgramScope;
}

export interface BurpAnalyzeRequest {
  ownerIdentityId: string;
  attackerIdentityId: string;
  baselineEvidenceId: string;
  exploitEvidenceId: string;
  negativeControlEvidenceId?: string;
}

export class BurpBridgeStore {
  readonly graph = new AssetGraph();
  private readonly identities = new Map<string, IdentityContext>();
  private readonly observations = new Map<string, HttpObservation>();

  importCapture(capture: BurpCapture): { evidenceId: string; endpointKey: string } {
    const decision = evaluateProgramScope(capture.scope, capture.observation.url, capture.observation.method);
    if (!decision.allowed) throw new Error(`scope denied: ${decision.reason}`);

    const evidenceId = capture.observation.evidenceIds[0] || `burp-${randomUUID()}`;
    const observation: HttpObservation = {
      ...capture.observation,
      identityId: capture.identity.id,
      evidenceIds: [...new Set([evidenceId, ...capture.observation.evidenceIds])],
      capturedAt: capture.observation.capturedAt ?? Date.now(),
    };

    this.identities.set(capture.identity.id, capture.identity);
    this.observations.set(evidenceId, observation);
    const endpoint = this.graph.addObservation(observation);
    return { evidenceId, endpointKey: endpoint.key };
  }

  analyze(input: BurpAnalyzeRequest): AuthzCandidate | null {
    const owner = this.requireIdentity(input.ownerIdentityId);
    const attacker = this.requireIdentity(input.attackerIdentityId);
    const baseline = this.requireObservation(input.baselineEvidenceId);
    const exploit = this.requireObservation(input.exploitEvidenceId);
    const negativeControl = input.negativeControlEvidenceId
      ? this.requireObservation(input.negativeControlEvidenceId)
      : undefined;

    if (baseline.identityId !== owner.id) throw new Error('baseline identity does not match owner');
    if (exploit.identityId !== attacker.id) throw new Error('exploit identity does not match attacker');

    return analyzeAuthzDifferential({ owner, attacker, baseline, exploit, negativeControl });
  }

  listIdentities(): IdentityContext[] {
    return [...this.identities.values()];
  }

  listObservations(): HttpObservation[] {
    return [...this.observations.values()];
  }

  private requireIdentity(id: string): IdentityContext {
    const value = this.identities.get(id);
    if (!value) throw new Error(`unknown identity: ${id}`);
    return value;
  }

  private requireObservation(id: string): HttpObservation {
    const value = this.observations.get(id);
    if (!value) throw new Error(`unknown observation: ${id}`);
    return value;
  }
}

function sendError(res: Response, error: unknown): void {
  res.status(400).json({ ok: false, error: error instanceof Error ? error.message : String(error) });
}

export function createBurpBridgeRouter(store = new BurpBridgeStore()): Router {
  const router = express.Router();
  router.use(express.json({ limit: '10mb' }));

  router.post('/capture', (req: Request, res: Response) => {
    try {
      res.json({ ok: true, ...store.importCapture(req.body as BurpCapture) });
    } catch (error) {
      sendError(res, error);
    }
  });

  router.post('/analyze/authz', (req: Request, res: Response) => {
    try {
      res.json({ ok: true, candidate: store.analyze(req.body as BurpAnalyzeRequest) });
    } catch (error) {
      sendError(res, error);
    }
  });

  router.get('/state', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      identities: store.listIdentities(),
      observations: store.listObservations(),
      endpoints: store.graph.listEndpoints().map((endpoint) => ({
        key: endpoint.key,
        method: endpoint.method,
        path: endpoint.normalizedPath,
        identities: endpoint.identities,
        observationCount: endpoint.observations.length,
      })),
    });
  });

  return router;
}
