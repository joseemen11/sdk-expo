# Privado ID Expo SDK

## Overview

`privado-id-expo-sdk` helps Expo and React Native applications integrate Privado ID / PolygonID flows on Android.

The SDK provides client-side building blocks to:

- Manage a local Holder DID.
- Store verifiable credentials securely.
- Synchronize credentials until an MTP proof is available.
- Generate MTP zero-knowledge proofs.
- Prepare and submit proofs to a UniversalVerifier contract.
- Query on-chain verification results.

The package is designed for Expo development builds and React Native Android environments where native circuit execution is available.

## Features

- Holder DID creation and loading.
- Secure credential storage.
- Credential import, save, list, lookup, delete, and clear operations.
- MTP credential synchronization from an issuer.
- MTP off-chain proof generation.
- MTP on-chain proof generation.
- UniversalVerifier submission.
- On-chain verification result query.
- Native circuit support with `.wcd`, `.zkey`, and optional `.dat` artifacts.
- Expo/React Native Android support.

## Installation

### Install from GitHub

```bash
npm install git+<YOUR_GITHUB_REPO_URL>
```

```bash
pnpm add git+<YOUR_GITHUB_REPO_URL>
```

Replace `<YOUR_GITHUB_REPO_URL>` with the real repository URL.

### Install from local path

```bash
pnpm add ../privado-id-expo-sdk
```

### Future npm package

```bash
pnpm add @your-scope/privado-id-expo-sdk
```

## Running the demo app

```bash
git clone <YOUR_GITHUB_REPO_URL>
cd privado-id-expo-sdk
pnpm install
cd example/demo-expo
pnpm install
pnpm android
```

For native ZK flows, use an Expo development build. Do not assume Expo Go for native witness calculation or proof generation. Android is the validated target environment.

## Configuration

Applications usually keep their own flat configuration and map it into the SDK `PrivadoExpoConfig` shape.

```ts
const appConfig = {
  chainId: 80002,
  network: 'polygon-amoy',
  rpcUrl: '<YOUR_RPC_URL>',
  stateContractAddress: '<STATE_CONTRACT_ADDRESS>',
  universalVerifierAddress: '<UNIVERSAL_VERIFIER_ADDRESS>',
  validatorAddress: '<MTP_VALIDATOR_ADDRESS>',
  issuerBaseUrl: '<ISSUER_BASE_URL>',
  issuerDid: '<ISSUER_DID>',
  credentialSchema: '<CREDENTIAL_SCHEMA_URL>',
  credentialContext: '<CREDENTIAL_CONTEXT_URL>',
  credentialType: 'PersonCredential',
  requestId: '<REQUEST_ID>',
  challengeAddress: '<CHALLENGE_ADDRESS>',
};

const sdkConfig = {
  network: {
    name: appConfig.network,
    chainId: appConfig.chainId,
    rpcUrl: appConfig.rpcUrl,
  },
  contracts: {
    stateContractAddress: appConfig.stateContractAddress,
    universalVerifierAddress: appConfig.universalVerifierAddress,
  },
  didResolver: {
    didResolverUrl: '<DID_RESOLVER_URL>',
  },
  issuer: {
    issuerDid: appConfig.issuerDid,
    issuerBaseUrl: appConfig.issuerBaseUrl,
  },
  credential: {
    credentialType: appConfig.credentialType,
    credentialSchema: appConfig.credentialSchema,
    credentialContext: appConfig.credentialContext,
  },
  circuits: {
    artifacts: [],
  },
};
```

| Field | Description | Required | Example placeholder |
| --- | --- | --- | --- |
| `chainId` | EVM chain id used by the target network. | Yes | `80002` |
| `network` | Human-readable network name. | Yes | `polygon-amoy` |
| `rpcUrl` | RPC endpoint used for contract reads and transaction submission. | Yes for on-chain flows | `<YOUR_RPC_URL>` |
| `stateContractAddress` | Privado ID state contract address. | Yes for AuthV2/on-chain proofs | `<STATE_CONTRACT_ADDRESS>` |
| `universalVerifierAddress` | UniversalVerifier contract address. | Yes for proof submission | `<UNIVERSAL_VERIFIER_ADDRESS>` |
| `validatorAddress` | Validator registered for the MTP proof request. | Yes for on-chain request matching | `<MTP_VALIDATOR_ADDRESS>` |
| `issuerBaseUrl` | Issuer service base URL. | Yes for claim/synchronization flows | `<ISSUER_BASE_URL>` |
| `issuerDid` | DID of the credential issuer. | Yes | `<ISSUER_DID>` |
| `credentialSchema` | Credential schema URL. | Yes for credential proof requests | `<CREDENTIAL_SCHEMA_URL>` |
| `credentialContext` | JSON-LD credential context URL. | Yes for merklized proofs | `<CREDENTIAL_CONTEXT_URL>` |
| `credentialType` | Verifiable credential type. | Yes | `PersonCredential` |
| `requestId` | UniversalVerifier request id. | Yes for on-chain proofs | `<REQUEST_ID>` |
| `challengeAddress` | EVM sender address used to derive the on-chain challenge. | Yes for on-chain proofs | `<CHALLENGE_ADDRESS>` |

## Basic usage

```ts
import { createPrivadoExpoClient } from '@privado-id/expo-sdk';

const client = createPrivadoExpoClient(sdkConfig, adapters);
await client.init();
```

`adapters` should provide the storage, secure key, circuit, witness, prover, networking, and transaction capabilities required by your application environment.

## Holder DID

```ts
const holder = await client.createOrLoadHolderDid({ mode: 'real' });
```

The Holder DID is created locally or loaded from local storage. It is used as the credential subject and as the identity that signs proof challenges. It is not an EVM wallet and should not be confused with the EVM signer used to pay gas and submit transactions.

```ts
const currentHolder = await client.getHolderDid();
```

## Credential storage

The client exposes credential storage methods backed by the configured credential storage adapter.

```ts
await client.saveCredential(vc);

const credentials = await client.getCredentials();
const credential = await client.getCredentialById('<CREDENTIAL_STORAGE_ID>');

await client.deleteCredential('<CREDENTIAL_STORAGE_ID>');
await client.clearCredentials();
```

Available storage-related methods:

- `saveCredential`
- `importCredentialFromJson`
- `getCredentials`
- `getCredentialById`
- `deleteCredential`
- `clearCredentials`

## Credential claim and MTP synchronization

After a credential is claimed, the issuer may make `Iden3SparseMerkleTreeProof` available after issuer state processing. The SDK supports synchronizing the credential again so the locally stored VC becomes ready for MTP proof generation.

```ts
const claim = await client.claimCredentialFromIssuer({
  holderDid: holder.did,
  credentialSubject: {
    id: holder.did,
  },
  credentialType: 'PersonCredential',
  credentialSchema: '<CREDENTIAL_SCHEMA_URL>',
});

const mtpCredential = await client.refetchMtpCredentialFromIssuer({
  credentialId: claim.issuerCredentialId,
  holderDid: holder.did,
  credentialType: 'PersonCredential',
  credentialSchema: '<CREDENTIAL_SCHEMA_URL>',
});
```

Credential MTP states:

- `pending-mtp-hydration`: the credential is stored, but the MTP proof is not available yet.
- `mtp-ready`: the stored credential contains `Iden3SparseMerkleTreeProof` and can be used for MTP proofs.

`getCredentials()` returns safe summaries and uses proof types from the actual VC proof array.

## Recommended flow

```txt
Initialize SDK
→ Create or load Holder DID
→ Claim or import credential
→ Save credential
→ Synchronize MTP credential
→ Generate MTP off-chain proof
→ Generate MTP on-chain proof
→ Submit proof to UniversalVerifier
→ Query verification result
```

## Generating MTP off-chain proof

```ts
const proof = await client.generateCredentialAtomicQueryMTPV2Proof({
  credentialId: '<CREDENTIAL_STORAGE_ID>',
  credentialType: 'PersonCredential',
  issuerDid: '<ISSUER_DID>',
  schema: '<CREDENTIAL_SCHEMA_URL>',
  query: {
    credentialSubject: {
      birthDate: { $eq: 946684800 },
    },
  },
});
```

This uses:

- Circuit: `credentialAtomicQueryMTPV2`.
- Credential proof type: `Iden3SparseMerkleTreeProof`.
- Native `.wcd` graph and `.zkey` proving key.

It does not send a transaction. The result includes proof metadata and public signals.

## Generating MTP on-chain proof

```ts
const preparedProof = await client.generateCredentialAtomicQueryMTPV2OnChainPreparedProof({
  credentialId: '<CREDENTIAL_STORAGE_ID>',
  credentialType: 'PersonCredential',
  issuerDid: '<ISSUER_DID>',
  schema: '<CREDENTIAL_SCHEMA_URL>',
  query: {
    credentialSubject: {
      birthDate: { $eq: 946684800 },
    },
  },
  onchain: {
    requestId: '<REQUEST_ID>',
    universalVerifierAddress: '<UNIVERSAL_VERIFIER_ADDRESS>',
    validatorAddress: '<MTP_VALIDATOR_ADDRESS>',
    challengeAddress: '<CHALLENGE_ADDRESS>',
  },
});
```

This uses `credentialAtomicQueryMTPV2OnChain` and prepares a proof compatible with UniversalVerifier. The on-chain challenge is derived from the expected signer/sender address and must match the account that submits the transaction.

## Submitting proof to UniversalVerifier

```ts
const tx = await client.submitOnchainProofToUniversalVerifier({
  preparedProof: preparedProof.preparedProof,
  requestId: '<REQUEST_ID>',
  evmPrivateKey: '<EVM_PRIVATE_KEY_FROM_SECURE_STORAGE>',
  rpcUrl: '<YOUR_RPC_URL>',
  universalVerifierAddress: '<UNIVERSAL_VERIFIER_ADDRESS>',
  challengeAddress: '<CHALLENGE_ADDRESS>',
  validatorAddress: '<MTP_VALIDATOR_ADDRESS>',
  chainId: 80002,
});
```

The SDK prepares calldata for the UniversalVerifier-compatible submit method and performs a read-only preflight before sending. The result can include:

- `txHash`
- `receiptStatus`
- `requestId`
- `verificationResult`
- challenge/signer validation status

Do not hardcode EVM private keys in application code. Load signing material from a secure wallet or secure storage flow.

## Querying on-chain verification result

```ts
const verified = await client.checkProofVerified({
  sender: '<SIGNER_ADDRESS>',
  requestId: '<REQUEST_ID>',
});
```

Example result:

```ts
{
  verified: true
}
```

## Public API Reference

| Function | Purpose | Main input | Output | Typical usage |
| --- | --- | --- | --- | --- |
| `createPrivadoExpoClient` | Creates the SDK client. | `PrivadoExpoConfig`, adapters | `PrivadoExpoClient` | App initialization |
| `client.init` | Initializes configured storage and providers. | None | `Promise<void>` | Startup |
| `client.createOrLoadHolderDid` | Creates or loads the local Holder DID. | `{ mode: 'real' }` | Holder DID summary | Identity setup |
| `client.getHolderDid` | Reads the current Holder DID summary. | None | Holder DID summary or `undefined` | Session restore |
| `client.signChallenge` | Signs a challenge with the holder key. | Challenge input | Signature result | Auth/proof flows |
| `client.saveCredential` | Saves a VC into configured storage. | VC JSON | Safe credential summary | Credential persistence |
| `client.importCredentialFromJson` | Parses a VC JSON payload for storage. | VC JSON | Imported credential result | External credential import |
| `client.getCredentials` | Lists safe credential summaries. | None | `ImportedCredentialSummary[]` | Credential list UI |
| `client.getCredentialById` | Reads a stored credential by storage id. | Storage id | VC JSON or `undefined` | Proof generation |
| `client.deleteCredential` | Deletes one stored credential. | Storage id | `Promise<void>` | Credential management |
| `client.clearCredentials` | Deletes all stored credentials. | None | `Promise<void>` | Reset local credential store |
| `client.claimCredentialFromOffer` | Claims a credential from an iden3comm offer. | Offer/message, holder DID | Claim result | Wallet-style claim |
| `client.claimCredentialFromIssuer` | Creates, claims, and stores a credential through the configured issuer flow. | Credential subject/config | Claim result | Demo/backend-assisted claim |
| `client.refetchMtpCredentialFromIssuer` | Synchronizes a stored credential until MTP proof is available. | Issuer credential id or storage id | MTP hydration result | Prepare MTP proofs |
| `client.generateCredentialAtomicQueryMTPV2Proof` | Generates an off-chain MTP proof. | Credential proof request | Proof summary | Off-chain verification |
| `client.generateCredentialAtomicQueryMTPV2OnChainPreparedProof` | Generates an on-chain MTP proof and prepared proof payload. | On-chain credential proof request | Prepared proof result | UniversalVerifier submit |
| `client.submitOnchainProofToUniversalVerifier` | Submits a prepared proof to UniversalVerifier. | Prepared proof, signer data, contract config | Submit result | On-chain verification |
| `client.checkProofVerified` | Reads UniversalVerifier verification state. | Sender, request id | Boolean | Result query |
| `CircuitArtifactDownloader.prepare` | Downloads and registers circuit artifacts. | ZIP URL, required circuits, adapters | Artifact descriptors | Circuit setup |
| `CircuitArtifactStore.validate` | Checks local artifact availability. | Circuit id, witness mode | Validation result | Circuit readiness checks |

## Circuit artifacts

The SDK supports native circuit artifacts:

- `.wcd`: witness calculator graph for native environments.
- `.zkey`: proving key.
- `.dat`: auxiliary circuit data when required by a native calculator.

Applications can use `CircuitArtifactDownloader` to download and register artifacts, and `CircuitArtifactStore.validate` to check whether a circuit is available locally. `.wcd` files are registered as `graphPath`; `.zkey` files are registered as `zkeyPath`; `.dat` files are accepted as optional compatibility artifacts.

Use placeholders or application-controlled configuration for artifact URLs. Do not put private artifact endpoints in public documentation.

## Security considerations

- Do not store private keys in plaintext.
- Do not expose issuer Basic Auth credentials in production mobile applications.
- Use a backend for issuer administration and credential creation when credentials require privileged issuer access.
- Protect RPC keys and rate-limited provider URLs.
- Use secure storage for holder keys, encryption keys, and signer material.
- Avoid logging full credentials, credential subjects, proofs, witnesses, private keys, seeds, or authorization headers.
- Do not commit `.env` files containing real credentials.
- Do not include real credentials, transaction hashes, private keys, or API keys in public documentation.

## Example integration service

```ts
// privadoIdentityService.ts
import { createPrivadoExpoClient } from '@privado-id/expo-sdk';

export function createPrivadoIdentityService(config, adapters) {
  const client = createPrivadoExpoClient(config, adapters);

  return {
    async init() {
      await client.init();
      return client.createOrLoadHolderDid({ mode: 'real' });
    },

    async syncCredentialForMtp(input) {
      return client.refetchMtpCredentialFromIssuer({
        issuerDid: '<ISSUER_DID>',
        credentialId: input.credentialId,
        holderDid: input.holderDid,
        credentialType: 'PersonCredential',
        credentialSchema: '<CREDENTIAL_SCHEMA_URL>',
      });
    },

    async generateMtpProof(input) {
      return client.generateCredentialAtomicQueryMTPV2Proof({
        credentialId: input.credentialId,
        credentialType: 'PersonCredential',
        issuerDid: '<ISSUER_DID>',
        schema: '<CREDENTIAL_SCHEMA_URL>',
        query: input.query,
      });
    },

    async generateOnChainMtpProof(input) {
      return client.generateCredentialAtomicQueryMTPV2OnChainPreparedProof({
        credentialId: input.credentialId,
        credentialType: 'PersonCredential',
        issuerDid: '<ISSUER_DID>',
        schema: '<CREDENTIAL_SCHEMA_URL>',
        query: input.query,
        onchain: {
          requestId: '<REQUEST_ID>',
          universalVerifierAddress: '<UNIVERSAL_VERIFIER_ADDRESS>',
          validatorAddress: '<MTP_VALIDATOR_ADDRESS>',
          challengeAddress: '<CHALLENGE_ADDRESS>',
        },
      });
    },

    async submit(preparedProof, evmPrivateKey) {
      return client.submitOnchainProofToUniversalVerifier({
        preparedProof: preparedProof.preparedProof,
        requestId: '<REQUEST_ID>',
        evmPrivateKey,
        rpcUrl: '<YOUR_RPC_URL>',
        universalVerifierAddress: '<UNIVERSAL_VERIFIER_ADDRESS>',
        challengeAddress: '<CHALLENGE_ADDRESS>',
        validatorAddress: '<MTP_VALIDATOR_ADDRESS>',
        chainId: 80002,
      });
    },

    async isVerified() {
      return client.checkProofVerified({
        sender: '<SIGNER_ADDRESS>',
        requestId: '<REQUEST_ID>',
      });
    },
  };
}
```

## Troubleshooting

### Credential does not contain `Iden3SparseMerkleTreeProof` yet

Run credential synchronization with `refetchMtpCredentialFromIssuer`. The credential is MTP-ready only when the stored VC contains `Iden3SparseMerkleTreeProof` in `vc.proof[]`.

### Circuit artifacts missing

Use `CircuitArtifactDownloader.prepare` to download artifacts, then validate with `CircuitArtifactStore.validate`. For native Android proof generation, the selected circuit must have a `.wcd` graph and a `.zkey`.

### Invalid challenge

Ensure the configured `challengeAddress` matches the EVM account that will submit the transaction. The on-chain challenge is derived from the sender address.

### Wrong network

Confirm `chainId`, `rpcUrl`, `stateContractAddress`, `universalVerifierAddress`, validator address, and request id all belong to the same network.

### Insufficient gas

The submitting EVM account must have native tokens on the selected network.

### Request not registered in UniversalVerifier

Confirm the request id exists, is enabled, and uses the expected circuit, validator, schema, credential type, and query.

### Credential issuer/context/type mismatch

Ensure the stored credential issuer DID, credential type, schema URL, JSON-LD context, and proof request query match the UniversalVerifier request.

## Project status

The SDK supports the complete MTP flow on Android: credential storage, MTP proof generation, UniversalVerifier submission, and on-chain verification query.
