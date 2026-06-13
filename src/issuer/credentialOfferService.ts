import type { AuthV2Provider, ClaimCredentialInput } from "../types";
import { parseCredentialOffer } from "./offerParser";

export interface CredentialOfferServiceOptions {
  authV2Provider?: AuthV2Provider;
}

export class CredentialOfferService {
  private readonly authV2Provider?: AuthV2Provider;

  constructor(options: CredentialOfferServiceOptions = {}) {
    this.authV2Provider = options.authV2Provider;
  }

  async claimCredentialFromOffer(input: ClaimCredentialInput): Promise<unknown> {
    const message = input.message ?? input.offer;
    if (!message) {
      throw new Error("Credential offer message is required.");
    }
    parseCredentialOffer(message);

    if (!this.authV2Provider) {
      throw new Error("AuthV2 provider is required to claim a credential from offer.");
    }

    return this.authV2Provider.createAuthProof(input);
  }
}
