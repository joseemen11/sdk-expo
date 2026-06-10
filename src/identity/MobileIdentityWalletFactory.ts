export interface MobileIdentityWalletFactoryOptions {
  identityStorage: unknown;
  credentialStorage: unknown;
  merkleTreeStorage: unknown;
  kms: unknown;
}

export class MobileIdentityWalletFactory {
  constructor(readonly options: MobileIdentityWalletFactoryOptions) {}

  async createIdentityWallet(): Promise<never> {
    throw new Error("Real Privado ID holder creation is not configured.");
  }
}
