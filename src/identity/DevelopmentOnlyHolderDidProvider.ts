import type { HolderDidProvider } from "../types";

export class DevelopmentOnlyHolderDidProvider implements HolderDidProvider {
  readonly developmentOnly = true;

  async createDid(input: { keyId: string; method?: string; network?: string }): Promise<{
    did: string;
    method?: string;
    network?: string;
    developmentOnly?: boolean;
  }> {
    const method = input.method ?? "development";
    const network = input.network ?? "local";
    return {
      did: `did:privado:development:${network}:${sanitizeDidPart(input.keyId)}`,
      method,
      network,
      developmentOnly: true
    };
  }
}

function sanitizeDidPart(value: string): string {
  return value.replace(/[^a-zA-Z0-9._:-]/g, "");
}
