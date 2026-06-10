import type { CircuitArtifactDescriptor, CircuitArtifactManifest } from "../types";
import { requiredCircuitIds } from "./CircuitManifest";
import { CircuitId } from "./CircuitId";

export class CircuitArtifactRegistry {
  private readonly artifacts = new Map<CircuitId, CircuitArtifactDescriptor>();

  constructor(manifest: CircuitArtifactManifest = { artifacts: [] }) {
    for (const artifact of manifest.artifacts) {
      this.artifacts.set(artifact.circuitId, artifact);
    }
  }

  get(circuitId: CircuitId): CircuitArtifactDescriptor | undefined {
    return this.artifacts.get(circuitId);
  }

  require(circuitId: CircuitId): CircuitArtifactDescriptor {
    const artifact = this.get(circuitId);
    if (!artifact) {
      throw new Error(`Circuit artifact is not registered: ${circuitId}.`);
    }
    return artifact;
  }

  validate(): void {
    for (const artifact of this.artifacts.values()) {
      validateArtifact(artifact);
    }
  }

  missingRequiredCircuitIds(): CircuitId[] {
    return requiredCircuitIds.filter((circuitId) => !this.artifacts.has(circuitId));
  }
}

function validateArtifact(artifact: CircuitArtifactDescriptor): void {
  if (!Object.values(CircuitId).includes(artifact.circuitId)) {
    throw new Error(`Unknown circuit id: ${artifact.circuitId}.`);
  }
  validateFile(artifact.wasm, `${artifact.circuitId}.wasm`);
  validateFile(artifact.zkey, `${artifact.circuitId}.zkey`);
  validateFile(artifact.verificationKey, `${artifact.circuitId}.verificationKey`);
}

function validateFile(value: { url?: string; localPath?: string; sha256: string; sizeBytes: number }, path: string): void {
  if (!value.url && !value.localPath) {
    throw new Error(`Circuit artifact ${path} requires url or localPath.`);
  }
  if (!value.sha256) {
    throw new Error(`Circuit artifact ${path} requires sha256.`);
  }
  if (!Number.isInteger(value.sizeBytes) || value.sizeBytes <= 0) {
    throw new Error(`Circuit artifact ${path} requires sizeBytes.`);
  }
}
