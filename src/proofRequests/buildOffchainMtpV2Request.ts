import { CircuitId } from "../circuits/CircuitId";
import type { BuildProofRequestInput, ProofRequest } from "../types";
import { createProofRequest } from "./createProofRequest";

export function buildOffchainMtpV2Request(input: BuildProofRequestInput): ProofRequest {
  return createProofRequest(input, CircuitId.CredentialAtomicQueryMTPV2);
}
