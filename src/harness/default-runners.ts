import { HarnessRunnerRegistry } from './runner-contract.js';
import { httpProbeRunner } from './runners/http-probe.js';
import { whiteboxIngestRunner } from './runners/whitebox.js';

export function createDefaultHarnessRunnerRegistry(): HarnessRunnerRegistry {
  const registry = new HarnessRunnerRegistry();
  registry.register(whiteboxIngestRunner);
  registry.register(httpProbeRunner);
  return registry;
}
