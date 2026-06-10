import type { AuthV2Provider, ClaimCredentialInput } from "../types";
import { CredentialOfferService } from "./credentialOfferService";

export async function claimCredentialFromOffer(
  input: ClaimCredentialInput,
  authV2Provider?: AuthV2Provider
): Promise<unknown> {
  return new CredentialOfferService({ authV2Provider }).claimCredentialFromOffer(input);
}
