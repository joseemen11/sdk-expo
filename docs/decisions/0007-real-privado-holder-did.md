# 0007 Real Privado ID Holder DID Integration

## Decision

Real Privado ID holder DID creation is not enabled in this block.

The SDK now supports `createOrLoadHolderDid({ mode })`:

- `mode: "real"` attempts the real Privado ID path.
- `mode: "development"` uses the explicit development-only provider.

When the real provider is not configured, the SDK fails with:

```txt
Real Privado ID holder creation is not configured.
```

## Technical Validation

The repository does not currently include `@0xpolygonid/js-sdk` or another Privado ID identity SDK package.

No local import was available for:

- `IdentityWallet`
- `KMS`
- `BjjProvider`

No mobile-safe implementation was available for the storage interfaces required by `IdentityWallet.createIdentity`:

- identity wallet storage;
- credential wallet storage;
- Merkle tree storage;
- BJJ private key store.

## Imports Used

No Privado ID SDK imports are used in this block because none are installed or locally verifiable.

The SDK adds boundary classes only:

- `RealPrivadoIdentityProvider`
- `MobileIdentityWalletFactory`
- `MobileBjjKmsAdapter`
- `MobilePrivateKeyStore`
- `MobileMerkleTreeStorage`
- `MobileCredentialStorage`

These boundaries do not create dummy identities and do not import browser storage or prover code.

## Blocker

To produce a real `developmentOnly: false` holder DID, the next block must add and verify the exact Privado ID identity SDK dependency and wire:

- `IdentityWallet.createIdentity`
- BJJ KMS provider
- mobile private key store backed by `SecureKeyStore`
- mobile Merkle tree storage
- mobile credential wallet storage

The selected imports must be checked to ensure they do not pull in browser-only storage, browser key stores, proving packages, or native prover execution.
