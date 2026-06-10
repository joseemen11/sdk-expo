import type { HolderDidProvider } from "../types";

export class RealPrivadoIdentityProvider implements HolderDidProvider {
  readonly developmentOnly = false;

  async createDid(_input: {
    keyId: string;
    method?: string;
    network?: string;
  }): Promise<{
    did: string;
    method?: string;
    network?: string;
    developmentOnly?: boolean;
  }> {
    throw new Error("Real Privado ID holder creation is not configured.");
  }
}
