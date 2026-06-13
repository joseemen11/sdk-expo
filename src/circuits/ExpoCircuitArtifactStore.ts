import { CircuitArtifactStore } from "./CircuitArtifactStore";
import type {
  CircuitArtifactDescriptor,
  CircuitArtifactManifest,
  CircuitArtifactValidationResult,
  CircuitWitnessMode
} from "../types";

export interface ExpoCircuitArtifactStoreOptions {
  manifest?: CircuitArtifactManifest;
  artifacts?: CircuitArtifactDescriptor[];
  fileExists?: (path: string) => Promise<boolean> | boolean;
}

export class ExpoCircuitArtifactStore extends CircuitArtifactStore {
  private readonly fileExists?: (path: string) => Promise<boolean> | boolean;

  constructor(options: ExpoCircuitArtifactStoreOptions = {}) {
    super({
      artifacts: options.artifacts ?? options.manifest?.artifacts ?? []
    });
    this.fileExists = options.fileExists;
  }

  async validateLocalFiles(
    circuitId: CircuitArtifactDescriptor["circuitId"],
    witnessMode?: CircuitWitnessMode
  ): Promise<CircuitArtifactValidationResult> {
    const base = this.validate(circuitId, witnessMode);
    if (!base.valid || !this.fileExists) {
      return base;
    }

    const artifact = this.require(circuitId);
    const missing: string[] = [];
    await this.checkFile(artifact.wasm?.localPath ?? artifact.wasmPath, "wasm", missing);
    await this.checkFile(artifact.graph?.localPath ?? artifact.graphPath, "graph", missing);
    await this.checkFile(artifact.zkey?.localPath ?? artifact.zkeyPath, "zkey", missing);
    await this.checkFile(
      artifact.verificationKey?.localPath ?? artifact.verificationKeyPath,
      "verificationKey",
      missing
    );

    return {
      circuitId,
      valid: missing.length === 0,
      missing
    };
  }

  private async checkFile(path: string | undefined, label: string, missing: string[]): Promise<void> {
    if (!path || path.includes("://")) {
      return;
    }
    if (!(await this.fileExists?.(path))) {
      missing.push(label);
    }
  }
}
