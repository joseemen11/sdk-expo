export interface MobileStateStorageOptions {
  rpcUrl?: string;
  stateContractAddress?: string;
}

export class MobileStateStorage {
  readonly rpcUrl?: string;
  readonly stateContractAddress?: string;

  constructor(options: MobileStateStorageOptions = {}) {
    this.rpcUrl = options.rpcUrl;
    this.stateContractAddress = options.stateContractAddress;
  }

  async getLatestStateById(_id: bigint): Promise<never> {
    throw new Error("MobileStateStorage.getLatestStateById requires a mobile RPC state adapter.");
  }

  async getStateInfoByIdAndState(_id: bigint, _state: bigint): Promise<never> {
    throw new Error("MobileStateStorage.getStateInfoByIdAndState requires a mobile RPC state adapter.");
  }

  async publishState(_proof: unknown, _signer: unknown): Promise<never> {
    throw new Error("MobileStateStorage.publishState is outside holder identity creation.");
  }

  async publishStateGeneric(_signer: unknown, _userStateTransitionInfo?: unknown): Promise<never> {
    throw new Error("MobileStateStorage.publishStateGeneric is outside holder identity creation.");
  }

  async getGISTProof(_id: bigint): Promise<never> {
    throw new Error("MobileStateStorage.getGISTProof requires a mobile RPC state adapter.");
  }

  async getGISTRootInfo(_root: bigint, _userId: bigint): Promise<never> {
    throw new Error("MobileStateStorage.getGISTRootInfo requires a mobile RPC state adapter.");
  }

  getRpcProvider(): never {
    throw new Error("MobileStateStorage.getRpcProvider requires a mobile RPC state adapter.");
  }
}
