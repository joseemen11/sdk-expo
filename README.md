# Privado ID Expo SDK

This repository contains an independent Privado ID SDK for Expo and React Native. The `example/demo-expo` app is only a test harness for Android integration work.

The first target is Android with an Expo development build. Expo Go is not a target for real proof generation because the ZK proving boundary is expected to use replaceable native capabilities behind `ZKProvider`.

## Current Scope

- Explicit SDK configuration through `PrivadoExpoConfig`.
- Secure-storage interfaces and adapters for encryption keys and credentials.
- Persistent encrypted credential storage through SecureStore-backed keys and SQLite-backed encrypted records in the demo app.
- VC JSON import, save, list, and lookup.
- Credential delete and clear operations.
- Holder DID API boundary for create/load/get/sign/delete.
- Safe credential summaries that exclude full claims.
- Pure builders for SigV2 and MTPV2 proof requests.
- On-chain challenge encoding with little-endian address conversion.
- Replaceable `ZKProvider`, `RPCAdapter`, and `ZkpTxSubmitter` boundaries.
- Controlled errors for claim, proof generation, transaction submit, and proof-status checks when required adapters are missing.

## Install

```sh
npm install
npm run build
```

## Basic Usage

```ts
import { createPrivadoExpoClient } from "@privado-id/expo-sdk";

const sdk = createPrivadoExpoClient({
  network: {
    name: "amoy",
    chainId: 80002,
    rpcUrl: "https://rpc-amoy.polygon.technology"
  },
  contracts: {
    stateContractAddress: "0x0000000000000000000000000000000000000001",
    universalVerifierAddress: "0x0000000000000000000000000000000000000002"
  },
  didResolver: {
    didResolverUrl: "https://resolver.privado.id"
  },
  circuits: {
    artifacts: []
  }
});

await sdk.init();
const imported = sdk.importCredentialFromJson(rawVcJson);
await sdk.saveCredential(imported.credential);
const summaries = await sdk.getCredentials();
```

## Holder DID

The SDK exposes holder identity methods, but real BJJ-backed Privado ID holder creation is not wired in this block.

```ts
const holder = await sdk.createOrLoadHolderDid({ mode: "real" });
const summary = await sdk.getHolderDid();
```

Real holder DID creation requires a configured Privado ID identity provider and BJJ KMS adapter. If the real provider is not configured, the SDK returns a controlled error. The demo app also exposes an explicit development mode to test persistence and challenge signing. Those demo identities are marked with `developmentOnly: true` and are not production Privado ID identities.

## Storage

Credential material must not be persisted in unencrypted app storage. `EncryptedCredentialStorage` encrypts each credential payload with XChaCha20-Poly1305 before it reaches the record store. The demo app stores the encryption key through `expo-secure-store` and stores encrypted records through `expo-sqlite`.

The SDK core stays adapter-based. Mobile apps can inject `ExpoSecureKeyStore`, `SQLiteCredentialRecordStore`, or stricter production adapters without changing the public client API.

## ZK Boundary

The SDK does not bundle a proving engine in this block. Real proof generation must be implemented behind `ZKProvider`, and circuit artifacts must be resolved from a manifest instead of shipping every artifact in the application bundle.

## Demo App

```sh
cd example/demo-expo
npm install
npm run android
```

The demo shows SDK status, controlled errors, and credential summaries only. It does not display full VCs.
