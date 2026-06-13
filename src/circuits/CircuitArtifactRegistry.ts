import type { CircuitArtifactDescriptor, CircuitArtifactManifest } from "../types";
import { requiredCircuitIds } from "./CircuitManifest";
import { CircuitId } from "./CircuitId";
import {
  CircuitArtifactStore,
  formatCircuitArtifactMissingError,
  getMissingCircuitArtifactPaths
} from "./CircuitArtifactStore";

export class CircuitArtifactRegistry {
  private readonly store: CircuitArtifactStore;

  constructor(manifest: CircuitArtifactManifest = { artifacts: [] }) {
    this.store = CircuitArtifactStore.fromManifest(manifest);
  }

  get(circuitId: CircuitId): CircuitArtifactDescriptor | undefined {
    return this.store.resolve(circuitId);
  }

  require(circuitId: CircuitId): CircuitArtifactDescriptor {
    return this.store.require(circuitId);
  }

  validate(): void {
    for (const artifact of this.storeArtifacts()) {
      validateArtifact(artifact);
    }
  }

  missingRequiredCircuitIds(): CircuitId[] {
    return requiredCircuitIds.filter((circuitId) => !this.store.resolve(circuitId));
  }

  private storeArtifacts(): CircuitArtifactDescriptor[] {
    return Object.values(CircuitId)
      .map((circuitId) => this.store.resolve(circuitId))
      .filter((artifact): artifact is CircuitArtifactDescriptor => Boolean(artifact));
  }
}

function validateArtifact(artifact: CircuitArtifactDescriptor): void {
  if (!Object.values(CircuitId).includes(artifact.circuitId)) {
    throw new Error(`Unknown circuit id: ${artifact.circuitId}.`);
  }
  const missing = getMissingCircuitArtifactPaths(artifact);
  if (missing.length > 0) {
    throw new Error(formatCircuitArtifactMissingError(artifact.circuitId, missing));
  }
}
