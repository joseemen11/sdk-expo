import { CircuitId } from "../circuits/CircuitId";
import { coerceAuthV2NativeWitnessInputs } from "../auth/AuthV2InputPreflight";
import type {
  NativeWitnessCalculator,
  NativeWitnessCalculatorInput,
  NativeWitnessCalculatorResult
} from "./AuthV2ZKProvider";

declare function require(moduleName: string): unknown;

export interface CircomWitnesscalcModule {
  calculateWitness(inputs: string, graph: string): Promise<string>;
}

export interface CircomWitnessGraphData {
  base64: string;
  sizeBytes?: number;
}

export interface CircomWitnessGraphInfo {
  graphSource: "base64";
  graphExtension: string;
  graphExists: boolean;
  graphSizeBytes: number;
}

export interface CircomWitnessGraphReader {
  readGraphBase64(graphPath: string): Promise<CircomWitnessGraphData>;
}

export interface CircomWitnessNativeCalculatorOptions {
  module?: CircomWitnesscalcModule;
  loadModule?: () => CircomWitnesscalcModule;
  graphReader?: CircomWitnessGraphReader;
}

export interface CircomWitnessAvailabilityResult {
  available: boolean;
  message: string;
}

export class CircomWitnessNativeCalculator implements NativeWitnessCalculator {
  private readonly module?: CircomWitnesscalcModule;
  private readonly loadModule?: () => CircomWitnesscalcModule;
  private readonly graphReader?: CircomWitnessGraphReader;

  constructor(options: CircomWitnessNativeCalculatorOptions = {}) {
    this.module = options.module;
    this.loadModule = options.loadModule;
    this.graphReader = options.graphReader;
  }

  async checkAvailable(): Promise<CircomWitnessAvailabilityResult> {
    return this.isAvailable();
  }

  async isAvailable(): Promise<CircomWitnessAvailabilityResult> {
    this.resolveModule();
    return {
      available: true,
      message: "Native witness calculator module is linked. Real witness calculation requires complete circuit inputs."
    };
  }

  async calculateWitness(input: NativeWitnessCalculatorInput): Promise<NativeWitnessCalculatorResult> {
    if (!supportsNativeWitness(input.circuitId)) {
      throw new Error(`CircomWitnessNativeCalculator does not support ${input.circuitId}.`);
    }
    const nativeInputs =
      input.circuitId === CircuitId.AuthV2 ? coerceAuthV2NativeWitnessInputs(input.inputs) : input.inputs;
    const graph = await this.readGraph(input.graphPath);
    const witnesscalc = this.resolveModule();
    const witness = await witnesscalc.calculateWitness(JSON.stringify(nativeInputs), graph.base64);
    return {
      witness
    };
  }

  async inspectGraph(graphPath: string): Promise<CircomWitnessGraphInfo> {
    const graph = await this.readGraph(graphPath);
    return {
      graphSource: "base64",
      graphExtension: extensionOf(graphPath),
      graphExists: true,
      graphSizeBytes: graph.sizeBytes ?? decodedBase64Size(graph.base64)
    };
  }

  private resolveModule(): CircomWitnesscalcModule {
    try {
      return this.module ?? this.loadModule?.() ?? loadDefaultCircomWitnesscalcModule();
    } catch {
      throw new Error("Native witness calculator module is not available in this build.");
    }
  }

  private async readGraph(graphPath: string): Promise<CircomWitnessGraphData> {
    if (!graphPath || extensionOf(graphPath) !== ".wcd") {
      throw new Error("Native witness graph must be a .wcd artifact.");
    }
    if (!this.graphReader) {
      throw new Error("Native witness graph reader is required to read .wcd artifact.");
    }
    let graph: CircomWitnessGraphData;
    try {
      graph = await this.graphReader.readGraphBase64(graphPath);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Native witness graph could not be read: ${message}`);
    }
    if (!graph.base64) {
      throw new Error("Native witness graph file is empty.");
    }
    const sizeBytes = graph.sizeBytes ?? decodedBase64Size(graph.base64);
    if (sizeBytes <= 0) {
      throw new Error("Native witness graph file is empty.");
    }
    return {
      base64: graph.base64,
      sizeBytes
    };
  }
}

function supportsNativeWitness(circuitId: CircuitId): boolean {
  return (
    circuitId === CircuitId.AuthV2 ||
    circuitId === CircuitId.CredentialAtomicQuerySigV2 ||
    circuitId === CircuitId.CredentialAtomicQuerySigV2OnChain
  );
}

function extensionOf(path: string): string {
  const cleanPath = path.split("?")[0] ?? path;
  const last = cleanPath.split("/").pop() ?? "";
  const dot = last.lastIndexOf(".");
  return dot >= 0 ? last.slice(dot).toLowerCase() : "";
}

function decodedBase64Size(value: string): number {
  const normalized = value.replace(/\s/g, "");
  if (!normalized) {
    return 0;
  }
  const padding = normalized.endsWith("==") ? 2 : normalized.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((normalized.length * 3) / 4) - padding);
}

export function loadDefaultCircomWitnesscalcModule(): CircomWitnesscalcModule {
  const mod = require("@iden3/react-native-circom-witnesscalc") as Partial<CircomWitnesscalcModule>;
  if (typeof mod.calculateWitness !== "function") {
    throw new Error("Native witness calculator module is not available in this build.");
  }
  return mod as CircomWitnesscalcModule;
}
