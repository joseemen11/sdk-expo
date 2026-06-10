import type { CircuitId } from "../circuits/CircuitId";
import type { BuildProofRequestInput, ProofRequest } from "../types";

export function createProofRequest(input: BuildProofRequestInput, circuitId: CircuitId): ProofRequest {
  const credentialType = input.credentialType;
  const credentialSchema = input.credentialSchema;
  const query = {
    ...(credentialType ? { type: credentialType } : {}),
    ...(credentialSchema ? { credentialSchema } : {}),
    ...(input.query ?? {})
  };

  return {
    id: input.requestId ?? `${circuitId}:${Date.now()}`,
    circuitId,
    query,
    challenge: input.challenge,
    scope: [
      {
        circuitId,
        query
      }
    ],
    metadata: {
      credentialSubjectId: input.credentialSubjectId,
      verifierDid: input.verifierDid,
      verifierAddress: input.verifierAddress,
      ...(input.metadata ?? {})
    }
  };
}
