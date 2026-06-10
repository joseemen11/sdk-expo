import type { PrivadoExpoConfig, RPCAdapter } from "../types";
import { universalVerifierAbi } from "./universalVerifierAbi";

export async function checkRequestStatus(
  requestId: string | number,
  config: PrivadoExpoConfig,
  rpcAdapter?: RPCAdapter
): Promise<unknown> {
  if (!rpcAdapter) {
    throw new Error("RPCAdapter is required to check request status.");
  }

  return rpcAdapter.readContract({
    chainId: config.network.chainId,
    rpcUrl: config.network.rpcUrl,
    contractAddress: config.contracts.universalVerifierAddress,
    abi: universalVerifierAbi,
    functionName: "getZKPRequest",
    args: [requestId]
  });
}
