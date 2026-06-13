import { CircuitId } from "./CircuitId";
import type {
  CircuitArtifactDescriptor,
  CircuitArtifactManifest,
  CircuitArtifactResolver,
  CircuitArtifactValidationResult,
  CircuitWitnessMode
} from "../types";

export interface CircuitArtifactStoreOptions {
  artifacts?: CircuitArtifactDescriptor[];
}

export class CircuitArtifactStore implements CircuitArtifactResolver {
  private readonly artifacts = new Map<CircuitId, CircuitArtifactDescriptor>();

  constructor(options: CircuitArtifactStoreOptions = {}) {
    for (const artifact of options.artifacts ?? []) {
      this.register(artifact);
    }
  }

  static fromManifest(manifest: CircuitArtifactManifest = { artifacts: [] }): CircuitArtifactStore {
    return new CircuitArtifactStore({ artifacts: manifest.artifacts });
  }

  register(descriptor: CircuitArtifactDescriptor): void {
    assertKnownCircuitId(descriptor.circuitId);
    this.artifacts.set(descriptor.circuitId, normalizeCircuitArtifactDescriptor(descriptor));
  }

  resolve(circuitId: CircuitId): CircuitArtifactDescriptor | undefined {
    return this.artifacts.get(circuitId);
  }

  require(circuitId: CircuitId): CircuitArtifactDescriptor {
    const artifact = this.resolve(circuitId);
    if (!artifact) {
      throw new Error(formatCircuitArtifactMissingError(circuitId, []));
    }
    return artifact;
  }

  validate(circuitId: CircuitId, witnessMode?: CircuitWitnessMode): CircuitArtifactValidationResult {
    const artifact = this.resolve(circuitId);
    if (!artifact) {
      return {
        circuitId,
        valid: false,
        missing: ["descriptor"]
      };
    }
    const missing = getMissingCircuitArtifactPaths(artifact, witnessMode);
    return {
      circuitId,
      valid: missing.length === 0,
      missing
    };
  }

  validateRegistered(witnessMode?: CircuitWitnessMode): CircuitArtifactValidationResult[] {
    return [...this.artifacts.keys()].map((circuitId) => this.validate(circuitId, witnessMode));
  }
}

export function normalizeCircuitArtifactDescriptor(
  descriptor: CircuitArtifactDescriptor
): CircuitArtifactDescriptor {
  return {
    ...descriptor,
    wasm: descriptor.wasm ?? fileFromPath(descriptor.wasmPath, descriptor.hashes?.wasm, descriptor.sizes?.wasm),
    graph: descriptor.graph ?? fileFromPath(descriptor.graphPath, descriptor.hashes?.graph, descriptor.sizes?.graph),
    dat: descriptor.dat ?? fileFromPath(descriptor.datPath, descriptor.hashes?.dat, descriptor.sizes?.dat),
    zkey: descriptor.zkey ?? fileFromPath(descriptor.zkeyPath, descriptor.hashes?.zkey, descriptor.sizes?.zkey),
    verificationKey:
      descriptor.verificationKey ??
      fileFromPath(
        descriptor.verificationKeyPath,
        descriptor.hashes?.verificationKey,
        descriptor.sizes?.verificationKey
      )
  };
}

export function getMissingCircuitArtifactPaths(
  descriptor: CircuitArtifactDescriptor,
  witnessMode?: CircuitWitnessMode
): string[] {
  assertKnownCircuitId(descriptor.circuitId);
  const normalized = normalizeCircuitArtifactDescriptor(descriptor);
  const missing: string[] = [];

  if (!hasPath(normalized.zkey)) {
    missing.push("zkey");
  }

  if (witnessMode === "wasm") {
    if (!hasPath(normalized.wasm)) {
      missing.push("wasm");
    }
  } else if (witnessMode === "native") {
    if (!hasPath(normalized.graph)) {
      missing.push("graph");
    }
  } else if (!hasPath(normalized.wasm) && !hasPath(normalized.graph)) {
    missing.push("wasmOrGraph");
  }

  return missing;
}

export function formatCircuitArtifactMissingError(
  circuitId: CircuitId,
  missing: readonly string[]
): string {
  if (circuitId === CircuitId.AuthV2) {
    return missing.length === 0
      ? "AuthV2 circuit artifacts are required to claim a credential from offer."
      : `AuthV2 circuit artifacts are incomplete: missing ${missing.join(", ")}.`;
  }
  return missing.length === 0
    ? `${circuitId} circuit artifacts are required.`
    : `${circuitId} circuit artifacts are incomplete: missing ${missing.join(", ")}.`;
}

function fileFromPath(path: string | undefined, sha256?: string, sizeBytes?: number) {
  if (!path) {
    return undefined;
  }
  return {
    localPath: path,
    sha256,
    sizeBytes
  };
}

function hasPath(file: { url?: string; localPath?: string; path?: string } | undefined): boolean {
  return Boolean(file?.localPath || file?.url || file?.path);
}

function assertKnownCircuitId(circuitId: CircuitId): void {
  if (!Object.values(CircuitId).includes(circuitId)) {
    throw new Error(`Unknown circuit id: ${circuitId}.`);
  }
}
