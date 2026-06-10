import type { PrivadoExpoConfig } from "../types";

export interface EthConnectionConfig {
  chainId: number;
  url?: string;
  stateContractAddress: string;
  universalVerifierAddress: string;
}

export function ethConnectionConfig(config: PrivadoExpoConfig): EthConnectionConfig {
  return {
    chainId: config.network.chainId,
    url: config.network.rpcUrl,
    stateContractAddress: config.contracts.stateContractAddress,
    universalVerifierAddress: config.contracts.universalVerifierAddress
  };
}
