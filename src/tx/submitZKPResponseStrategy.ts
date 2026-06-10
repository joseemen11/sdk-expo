import type { OnchainSubmitStrategy, SubmitProofInput, ZkpTxSubmitter } from "../types";

export class SubmitZKPResponseStrategy implements OnchainSubmitStrategy {
  async submit(input: SubmitProofInput, submitter: ZkpTxSubmitter): Promise<{ txHash: string; raw?: unknown }> {
    return submitter.submitProof(input);
  }
}
