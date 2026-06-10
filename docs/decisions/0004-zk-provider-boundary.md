# 0004 ZK Provider Boundary

## Decision

Real proof generation is hidden behind `ZKProvider`. The SDK delegates `generateOffchainProof` and `generateOnchainProof` to that provider and throws a controlled error when no provider is configured.

## Rationale

Expo and React Native proof generation needs native-aware execution and artifact loading. Keeping that work behind `ZKProvider` avoids coupling the SDK to a specific proving runtime.

## Consequences

Circuit artifacts are represented by a manifest and registry. The application can choose how artifacts are downloaded, cached, verified, and passed to the provider.
