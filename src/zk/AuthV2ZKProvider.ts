import { CircuitId } from "../circuits/CircuitId";
import {
  formatCircuitArtifactMissingError,
  getMissingCircuitArtifactPaths
} from "../circuits/CircuitArtifactStore";
import { coerceAuthV2NativeWitnessInputs } from "../auth/AuthV2InputPreflight";
import type { GeneratedProof, GenerateProofInput, ZKProvider } from "../types";

export interface NativeWitnessCalculatorInput {
  circuitId: CircuitId;
  graphPath: string;
  inputs: Record<string, unknown>;
}

export interface NativeWitnessCalculatorResult {
  witnessPath?: string;
  witness?: unknown;
  publicSignals?: unknown;
  witnessSource?: "base64" | "file" | "unknown";
  witnessByteLength?: number;
  witnessSha256?: string;
  inputByteLength?: number;
  inputSha256?: string;
}

export interface NativeWitnessCalculator {
  calculateWitness(input: NativeWitnessCalculatorInput): Promise<NativeWitnessCalculatorResult>;
}

export interface NativeProverInput {
  circuitId: CircuitId;
  zkeyPath: string;
  witnessPath?: string;
  witness?: unknown;
  witnessByteLength?: number;
  witnessSha256?: string;
}

export interface NativeProverResult {
  proof: unknown;
  publicSignals?: unknown;
  rawProof?: string;
  rawPublicSignals?: string;
  runId?: string;
  startedAt?: string;
  finishedAt?: string;
  zkeyPath?: string;
  witnessSource?: "base64" | "file" | "unknown";
  witnessPath?: string;
  witnessByteLength?: number;
  witnessSha256?: string;
}

export interface NativeProver {
  generateProof(input: NativeProverInput): Promise<NativeProverResult>;
}

export interface AuthV2ZKProviderOptions {
  witnessCalculator?: NativeWitnessCalculator;
  prover?: NativeProver;
}

export class AuthV2ZKProvider implements ZKProvider {
  private readonly witnessCalculator?: NativeWitnessCalculator;
  private readonly prover?: NativeProver;

  constructor(options: AuthV2ZKProviderOptions = {}) {
    this.witnessCalculator = options.witnessCalculator;
    this.prover = options.prover;
  }

  async generateProof(input: GenerateProofInput): Promise<GeneratedProof> {
    if (input.request.circuitId !== CircuitId.AuthV2) {
      throw new Error("AuthV2ZKProvider only supports AuthV2.");
    }
    if (!input.circuitArtifacts) {
      throw new Error("AuthV2 circuit artifacts are required to claim a credential from offer.");
    }

    const missing = getMissingCircuitArtifactPaths(input.circuitArtifacts, "native");
    if (missing.length > 0) {
      throw new Error(formatCircuitArtifactMissingError(CircuitId.AuthV2, missing));
    }

    const graphPath = pathFrom(input.circuitArtifacts.graph?.localPath, input.circuitArtifacts.graphPath);
    const zkeyPath = pathFrom(input.circuitArtifacts.zkey?.localPath, input.circuitArtifacts.zkeyPath);
    if (!graphPath) {
      throw new Error("AuthV2 circuit artifacts are incomplete: missing graph.");
    }
    if (!zkeyPath) {
      throw new Error("AuthV2 circuit artifacts are incomplete: missing zkey.");
    }

    if (!this.witnessCalculator) {
      throw new Error("Mobile witness calculator is required to generate AuthV2 proof.");
    }
    const witnessInputs = coerceAuthV2NativeWitnessInputs(input.witnessInputs);

    const witnessResult = await this.witnessCalculator.calculateWitness({
      circuitId: CircuitId.AuthV2,
      graphPath,
      inputs: witnessInputs
    });

    if (!this.prover) {
      throw new Error("Native prover is required to generate AuthV2 proof.");
    }

    const proofResult = await this.prover.generateProof({
      circuitId: CircuitId.AuthV2,
      zkeyPath,
      witnessPath: witnessResult.witnessPath,
      witness: witnessResult.witness,
      witnessByteLength: witnessResult.witnessByteLength,
      witnessSha256: witnessResult.witnessSha256
    });

    return {
      circuitId: CircuitId.AuthV2,
      proof: proofResult.proof,
      publicSignals: proofResult.publicSignals ?? witnessResult.publicSignals ?? [],
      request: input.request
    };
  }
}

function pathFrom(...values: Array<string | undefined>): string | undefined {
  return values.find((value) => typeof value === "string" && value.length > 0);
}
