import {
  BjjProvider,
  CredentialWallet,
  IdentityWallet,
  KMS,
  KmsKeyType,
  W3CCredential
} from "./vendorIdentityRuntime";

export interface MobileSafePolygonIdImports {
  IdentityWallet: unknown;
  KMS: unknown;
  BjjProvider: unknown;
  KmsKeyType: typeof KmsKeyType;
  CredentialWallet: unknown;
  W3CCredential?: unknown;
}

export async function loadMobileSafePolygonIdIdentityKms(): Promise<MobileSafePolygonIdImports> {
  return {
    IdentityWallet,
    KMS,
    BjjProvider,
    KmsKeyType,
    CredentialWallet,
    W3CCredential
  };
}
