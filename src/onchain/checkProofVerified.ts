import type { CheckProofVerifiedInput, PrivadoExpoConfig, RPCAdapter } from "../types";
import { universalVerifierAbi } from "./universalVerifierAbi";

export async function checkProofVerified(
  input: CheckProofVerifiedInput,
  config: PrivadoExpoConfig,
  rpcAdapter?: RPCAdapter
): Promise<boolean> {
  if (!rpcAdapter) {
    throw new Error("RPCAdapter is required to check proof status.");
  }

  return rpcAdapter.readContract<boolean>({
    chainId: config.network.chainId,
    rpcUrl: config.network.rpcUrl,
    contractAddress: config.contracts.universalVerifierAddress,
    abi: universalVerifierAbi,
    functionName: "isProofVerified",
    args: [input.userAddress, input.requestId]
  });
}
