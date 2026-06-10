import { CircuitId } from "../circuits/CircuitId";
import type { BuildProofRequestInput, ProofRequest } from "../types";
import { createProofRequest } from "./createProofRequest";

export function buildOffchainSigV2Request(input: BuildProofRequestInput): ProofRequest {
  return createProofRequest(input, CircuitId.CredentialAtomicQuerySigV2);
}
