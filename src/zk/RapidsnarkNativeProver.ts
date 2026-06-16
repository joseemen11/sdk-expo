import { CircuitId } from "../circuits/CircuitId";
import type { NativeProver, NativeProverInput, NativeProverResult } from "./AuthV2ZKProvider";

declare function require(moduleName: string): unknown;

export interface RapidsnarkModule {
  groth16Prove(
    zkeyPath: string,
    witness: string,
    options?: {
      proofBufferSize?: number;
      publicBufferSize?: number;
      errorBufferSize?: number;
    }
  ): Promise<{
    proof: string;
    pub_signals: string;
  }>;
  groth16PublicBufferSize(
    zkeyPath: string,
    options?: {
      errorBufferSize?: number;
    }
  ): Promise<number>;
}

export interface RapidsnarkNativeProverOptions {
  module?: RapidsnarkModule;
  loadModule?: () => RapidsnarkModule;
  fileInspector?: RapidsnarkFileInspector;
  proofBufferSize?: number;
  publicBufferSize?: number;
  errorBufferSize?: number;
}

export interface RapidsnarkFileInfo {
  exists: boolean;
  sizeBytes?: number;
}

export interface RapidsnarkFileInspector {
  inspectFile(path: string): Promise<RapidsnarkFileInfo>;
}

export class RapidsnarkNativeProver implements NativeProver {
  private readonly module?: RapidsnarkModule;
  private readonly loadModule?: () => RapidsnarkModule;
  private readonly fileInspector?: RapidsnarkFileInspector;
  private readonly proofBufferSize?: number;
  private readonly publicBufferSize?: number;
  private readonly errorBufferSize?: number;

  constructor(options: RapidsnarkNativeProverOptions = {}) {
    this.module = options.module;
    this.loadModule = options.loadModule;
    this.fileInspector = options.fileInspector;
    this.proofBufferSize = options.proofBufferSize;
    this.publicBufferSize = options.publicBufferSize;
    this.errorBufferSize = options.errorBufferSize;
  }

  async checkAvailable(zkeyPath: string): Promise<{ available: boolean; publicBufferSize?: number }> {
    const rapidsnark = this.resolveModule();
    const publicBufferSize = await rapidsnark.groth16PublicBufferSize(toNativeFilePath(zkeyPath), {
      errorBufferSize: this.errorBufferSize
    });
    return {
      available: true,
      publicBufferSize
    };
  }

  async inspectZkey(zkeyPath: string): Promise<RapidsnarkFileInfo | undefined> {
    return this.fileInspector?.inspectFile(zkeyPath);
  }

  async generateProof(input: NativeProverInput): Promise<NativeProverResult> {
    if (!supportsNativeProver(input.circuitId)) {
      throw new Error(`RapidsnarkNativeProver does not support ${input.circuitId}.`);
    }
    const witness = witnessString(input);
    if (input.witnessPath && !input.witness) {
      throw new Error("Native prover requires witness base64, not witnessPath, for @iden3/react-native-rapidsnark.");
    }
    const rapidsnark = this.resolveModule();
    const runId = createRunId(input.circuitId);
    const startedAt = new Date().toISOString();
    const zkeyPath = toNativeFilePath(input.zkeyPath);
    const result = await rapidsnark.groth16Prove(zkeyPath, witness, {
      proofBufferSize: this.proofBufferSize,
      publicBufferSize: this.publicBufferSize,
      errorBufferSize: this.errorBufferSize
    });
    const finishedAt = new Date().toISOString();
    return {
      proof: parseJsonOrString(result.proof),
      publicSignals: parseJsonOrString(result.pub_signals),
      rawProof: result.proof,
      rawPublicSignals: result.pub_signals,
      runId,
      startedAt,
      finishedAt,
      zkeyPath,
      witnessSource: input.witnessPath ? "file" : typeof input.witness === "string" ? "base64" : "unknown",
      witnessPath: input.witnessPath,
      witnessByteLength:
        input.witnessByteLength ?? (typeof input.witness === "string" ? decodedBase64Size(input.witness) : undefined),
      witnessSha256: input.witnessSha256
    };
  }

  private resolveModule(): RapidsnarkModule {
    try {
      return this.module ?? this.loadModule?.() ?? loadDefaultRapidsnarkModule();
    } catch {
      throw new Error("Native Rapidsnark module is not available in this build.");
    }
  }
}

function supportsNativeProver(circuitId: CircuitId): boolean {
  return (
    circuitId === CircuitId.AuthV2 ||
    circuitId === CircuitId.CredentialAtomicQuerySigV2 ||
    circuitId === CircuitId.CredentialAtomicQuerySigV2OnChain ||
    circuitId === CircuitId.CredentialAtomicQueryMTPV2 ||
    circuitId === CircuitId.CredentialAtomicQueryMTPV2OnChain
  );
}

export function loadDefaultRapidsnarkModule(): RapidsnarkModule {
  const mod = require("@iden3/react-native-rapidsnark") as Partial<RapidsnarkModule>;
  if (typeof mod.groth16Prove !== "function" || typeof mod.groth16PublicBufferSize !== "function") {
    throw new Error("Native Rapidsnark module is not available in this build.");
  }
  return mod as RapidsnarkModule;
}

function witnessString(input: NativeProverInput): string {
  if (typeof input.witness === "string" && input.witness.length > 0) {
    return input.witness;
  }
  throw new Error("Native prover requires witness or witnessPath.");
}

function toNativeFilePath(path: string): string {
  return path.replace(/^file:\/\//, "");
}

function parseJsonOrString(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function createRunId(circuitId: CircuitId): string {
  return `${circuitId}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function decodedBase64Size(value: string): number {
  const normalized = value.replace(/\s/g, "");
  if (!normalized) {
    return 0;
  }
  const padding = normalized.endsWith("==") ? 2 : normalized.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((normalized.length * 3) / 4) - padding);
}
