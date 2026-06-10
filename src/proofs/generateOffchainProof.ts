import type { GeneratedProof, GenerateProofInput, ZKProvider } from "../types";

export async function generateOffchainProof(input: GenerateProofInput, zkProvider?: ZKProvider): Promise<GeneratedProof> {
  if (!zkProvider) {
    throw new Error("ZKProvider is required to generate proofs.");
  }
  return zkProvider.generateProof(input);
}
