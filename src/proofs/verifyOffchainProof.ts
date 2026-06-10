import type { GeneratedProof } from "../types";

export interface OffchainProofVerificationResult {
  verified: boolean;
  reason?: string;
  proof?: GeneratedProof;
}

export async function verifyOffchainProof(proof: GeneratedProof): Promise<OffchainProofVerificationResult> {
  return {
    verified: false,
    reason: "Off-chain proof verification is not configured.",
    proof
  };
}
