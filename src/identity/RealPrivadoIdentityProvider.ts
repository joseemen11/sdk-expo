import type { HolderDidProvider } from "../types";
import { MobileIdentityWalletFactory, type MobileIdentityWalletFactoryOptions } from "./MobileIdentityWalletFactory";

export class RealPrivadoIdentityProvider implements HolderDidProvider {
  readonly developmentOnly = false;
  private readonly walletFactory: MobileIdentityWalletFactory;

  constructor(options: MobileIdentityWalletFactoryOptions = {}) {
    this.walletFactory = new MobileIdentityWalletFactory(options);
  }

  async createHolderIdentity(input: {
    keyId?: string;
    method?: string;
    network?: string;
  }): Promise<{
    did: string;
    keyId: string;
    method?: string;
    network?: string;
    developmentOnly?: boolean;
  }> {
    try {
      const result = await this.walletFactory.createIdentity({
        method: input.method,
        network: input.network
      });
      return {
        did: result.did,
        keyId: input.keyId ?? result.keyId ?? extractKeyReference(result.credential) ?? `${result.did}#auth-bjj`,
        method: input.method,
        network: input.network,
        developmentOnly: false
      };
    } catch (error) {
      throw new Error(`Real Privado ID holder creation failed at IdentityWallet.createIdentity: ${formatDetailedError(error)}`);
    }
  }

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
    const result = await this.createHolderIdentity(_input);
    return {
      did: result.did,
      method: result.method,
      network: result.network,
      developmentOnly: result.developmentOnly
    };
  }
}

function extractKeyReference(credential: unknown): string | undefined {
  if (!credential || typeof credential !== "object") {
    return undefined;
  }
  const record = credential as Record<string, unknown>;
  if (typeof record.id === "string" && record.id.length > 0) {
    return record.id;
  }
  return undefined;
}

function formatDetailedError(error: unknown): string {
  if (!(error instanceof Error)) {
    return String(error);
  }

  const name = error.name || "Error";
  const message = error.message || "Unknown error";
  const rawCause = (error as { cause?: unknown }).cause;
  const cause = rawCause instanceof Error ? ` Cause: ${rawCause.message}` : "";
  const stack = typeof error.stack === "string" ? ` Stack: ${safeStack(error.stack)}` : "";
  return `${name}: ${message}${cause}${stack}`;
}

function safeStack(stack: string): string {
  return stack
    .split(/\r?\n/)
    .slice(0, 3)
    .map((line) => line.trim())
    .join(" | ");
}
