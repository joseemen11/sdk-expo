# 0006 Holder DID and KMS Boundary

## Decision

The SDK now exposes holder identity APIs without exposing private key material:

- `createOrLoadHolderDid`
- `getHolderDid`
- `signChallenge`
- `deleteHolderIdentity`

Holder metadata is stored through `IdentityStorageAdapter`. Sensitive key material is stored through `SecurePrivateKeyStore`, backed by `SecureKeyStore`.

## Real Privado ID Status

Real BJJ-backed Privado ID holder identity creation is not implemented in this block. The repository does not currently include the exact Privado ID JS SDK integration required to safely call identity creation with mobile-safe storage and KMS adapters.

`BjjKmsAdapter` is present as the production boundary and returns controlled errors until the BJJ integration is connected.

## Demo Strategy

The demo app uses `DevelopmentOnlyKmsAdapter` and `DevelopmentOnlyHolderDidProvider`. This path is explicitly marked with `developmentOnly: true` and is not used by the SDK by default.

`createOrLoadHolderDid` now accepts `mode: "real" | "development"`. Real mode must use a real Privado ID provider and fails with a controlled error when that provider is not configured.

The development adapter exists to test:

- persistence of holder metadata;
- secure storage of key material through SecureStore;
- loading the same holder identity on the second call;
- challenge signing without exposing key material.

It is not a real Privado ID holder identity and must not be used for credential issuance, proof generation, or production verification.

## Storage

Holder metadata contains only DID, keyId, method, network, createdAt, updatedAt, and developmentOnly. It does not contain private keys, seeds, or raw key material.

Private key material is generated and stored through `SecurePrivateKeyStore`, which writes only to `SecureKeyStore`. It is not stored in SQLite.

## Consequences

The public API is ready for a real BJJ KMS implementation without breaking changes. The next integration step is wiring the Privado ID identity wallet with mobile-safe adapters and confirming that no browser storage or proving dependencies are imported.
