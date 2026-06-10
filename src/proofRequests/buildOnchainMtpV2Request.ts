import { addressToUint256LE } from "../onchain/challengeEncoding";
import { CircuitId } from "../circuits/CircuitId";
import type { BuildProofRequestInput, ProofRequest } from "../types";
import { createProofRequest } from "./createProofRequest";

export function buildOnchainMtpV2Request(input: BuildProofRequestInput): ProofRequest {
  const challenge = input.challenge ?? (input.verifierAddress ? addressToUint256LE(input.verifierAddress) : undefined);
  return createProofRequest({ ...input, challenge }, CircuitId.CredentialAtomicQueryMTPV2OnChain);
}
