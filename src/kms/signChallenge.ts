import type { IdentityStorageAdapter, KMSAdapter, SignChallengeInput, SignChallengeResult } from "../types";

export async function signChallenge(input: {
  request: SignChallengeInput;
  kmsAdapter?: KMSAdapter;
  identityStorage?: IdentityStorageAdapter;
}): Promise<SignChallengeResult> {
  if (!input.kmsAdapter?.signChallenge) {
    throw new Error("KMS adapter with signChallenge is required to sign a challenge.");
  }

  const keyId = input.request.keyId ?? (await input.identityStorage?.getHolderDid())?.keyId;
  if (!keyId) {
    throw new Error("Holder DID keyId is required to sign a challenge.");
  }

  return input.kmsAdapter.signChallenge({
    ...input.request,
    keyId
  });
}
