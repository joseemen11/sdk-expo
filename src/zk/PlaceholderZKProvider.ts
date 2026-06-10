import type { GeneratedProof, GenerateProofInput, ZKProvider } from "../types";

export class PlaceholderZKProvider implements ZKProvider {
  async generateProof(_input: GenerateProofInput): Promise<GeneratedProof> {
    throw new Error("ZKProvider is required to generate proofs.");
  }
}
