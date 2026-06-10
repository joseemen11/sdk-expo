import type { SubmitProofInput } from "../types";

export function assertSubmitProofReady(input: SubmitProofInput): void {
  if (!input.payload.contractAddress) {
    throw new Error("UniversalVerifier contract address is required.");
  }
  if (input.payload.requestId === undefined || input.payload.requestId === null) {
    throw new Error("Request id is required.");
  }
}
