import type { GeneratedProof, PrivadoExpoConfig, UniversalVerifierPayload } from "../types";

export interface PrepareUniversalVerifierPayloadInput {
  requestId: string | number;
  proof: GeneratedProof;
  config: PrivadoExpoConfig;
  queryHash?: string;
  metadata?: Record<string, unknown>;
}

export function prepareUniversalVerifierPayload(input: PrepareUniversalVerifierPayloadInput): UniversalVerifierPayload {
  const proofRecord = asRecord(input.proof.proof);
  return {
    contractAddress: input.config.contracts.universalVerifierAddress,
    requestId: input.requestId,
    inputs: input.proof.publicSignals,
    piA: proofRecord.piA ?? proofRecord.a,
    piB: proofRecord.piB ?? proofRecord.b,
    piC: proofRecord.piC ?? proofRecord.c,
    queryHash: input.queryHash,
    metadata: input.metadata
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}
