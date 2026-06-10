import type { SubmitProofInput, ZkpTxSubmitter } from "../types";

export async function submitProof(
  input: SubmitProofInput,
  submitter?: ZkpTxSubmitter
): Promise<{ txHash: string; raw?: unknown }> {
  if (!submitter) {
    throw new Error("ZkpTxSubmitter is required to submit a proof.");
  }
  return submitter.submitProof(input);
}
