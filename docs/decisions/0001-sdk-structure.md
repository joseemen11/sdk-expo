# 0001 SDK Structure

## Decision

The repository is organized as an independent TypeScript SDK with a separate Expo app under `example/demo-expo`.

The SDK public API is exported from `src/index.ts`. Feature areas are split into configuration, credentials, issuer, proof requests, circuits, ZK, storage, on-chain, transaction, network, native, KMS, and client modules.

## Rationale

The SDK needs clear mobile boundaries. Storage, proving, RPC, signing, and transaction submission are interfaces so React Native implementations can be added without coupling the core SDK to a single app or provider.

## Consequences

The first block is useful for integration and API stabilization, while native proving and encrypted persistent storage remain replaceable modules.
