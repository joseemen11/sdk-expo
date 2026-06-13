declare function require(moduleName: string): unknown;

interface Iden3CryptoRuntime {
  PrivateKey: new (seed: Uint8Array) => { hex(): string; public(): { hex(): string } };
  PublicKey: { newFromHex(value: string): { p: [bigint, bigint] } };
  Hex: { decodeString(value: string): Uint8Array; encode(value: Uint8Array): Uint8Array | string };
  sha256(value: Uint8Array): Uint8Array;
}

interface Iden3CoreRuntime {
  Claim: {
    newClaim(schemaHash: unknown, ...args: unknown[]): {
      setRevocationNonce(value: bigint): void;
      hiHv(): { hi: bigint; hv: bigint };
      marshalJson(): string[];
    };
  };
  ClaimOptions: {
    withIndexDataInts(slotA: bigint | null, slotB: bigint | null): unknown;
    withRevocationNonce(nonce: bigint): unknown;
  };
  SchemaHash: { authSchemaHash: unknown };
  buildDIDType(method: string, blockchain: string, networkId: string): Uint8Array;
  DidMethod: { Iden3: string };
  Blockchain: { Polygon: string };
  NetworkId: { Amoy: string };
  Id: { idGenesisFromIdenState(didType: Uint8Array, state: bigint): unknown };
  DID: { parseFromId(id: unknown): { string(): string } };
}

interface MerkleTreeRuntime {
  ZERO_HASH: { bigInt(): bigint };
  hashElems(values: bigint[]): { bigInt(): bigint };
}

const Iden3Crypto = require("@iden3/js-crypto") as Iden3CryptoRuntime;
const Iden3Core = require("@iden3/js-iden3-core") as Iden3CoreRuntime;
const MerkleTree = require("@iden3/js-merkletree") as MerkleTreeRuntime;

export enum KmsKeyType {
  BabyJubJub = "BJJ"
}

export interface KmsKeyId {
  type: KmsKeyType;
  id: string;
}

export interface PrivateKeyStoreLike {
  importKey(args: { alias: string; key: string }): Promise<void>;
  get(args: { alias: string }): Promise<string>;
  list(): Promise<{ alias: string; key: string }[]>;
}

export interface KeyProviderLike {
  keyType: KmsKeyType;
  list(): Promise<{ alias: string; key: string }[]>;
  publicKey(keyID: KmsKeyId): Promise<string>;
  sign(keyId: KmsKeyId, data: Uint8Array, opts?: Record<string, unknown>): Promise<Uint8Array>;
  newPrivateKeyFromSeed(seed: Uint8Array): Promise<KmsKeyId>;
  newPrivateKey(): Promise<KmsKeyId>;
  verify(message: Uint8Array, signatureHex: string, keyId: KmsKeyId): Promise<boolean>;
  getPkStore(): Promise<PrivateKeyStoreLike>;
}

export class KMS {
  private readonly registry = new Map<KmsKeyType, KeyProviderLike>();

  registerKeyProvider(keyType: KmsKeyType, keyProvider: KeyProviderLike): void {
    if (this.registry.has(keyType)) {
      throw new Error("KMS key provider already registered.");
    }
    this.registry.set(keyType, keyProvider);
  }

  async createKeyFromSeed(keyType: KmsKeyType, bytes: Uint8Array): Promise<KmsKeyId> {
    return this.requireProvider(keyType).newPrivateKeyFromSeed(bytes);
  }

  async createKey(keyType: KmsKeyType): Promise<KmsKeyId> {
    return this.requireProvider(keyType).newPrivateKey();
  }

  async publicKey(keyId: KmsKeyId): Promise<string> {
    return this.requireProvider(keyId.type).publicKey(keyId);
  }

  async sign(keyId: KmsKeyId, data: Uint8Array, opts?: Record<string, unknown>): Promise<Uint8Array> {
    return this.requireProvider(keyId.type).sign(keyId, data, opts);
  }

  async verify(data: Uint8Array, signatureHex: string, keyId: KmsKeyId): Promise<boolean> {
    return this.requireProvider(keyId.type).verify(data, signatureHex, keyId);
  }

  async list(keyType: KmsKeyType): Promise<{ alias: string; key: string }[]> {
    return this.requireProvider(keyType).list();
  }

  getKeyProvider(keyType: KmsKeyType): KeyProviderLike | undefined {
    return this.registry.get(keyType);
  }

  private requireProvider(keyType: KmsKeyType): KeyProviderLike {
    const provider = this.registry.get(keyType);
    if (!provider) {
      throw new Error(`KMS key provider not found for ${keyType}.`);
    }
    return provider;
  }
}

export class BjjProvider implements KeyProviderLike {
  readonly keyType: KmsKeyType;
  private readonly keyStore: PrivateKeyStoreLike;

  constructor(keyType: KmsKeyType, keyStore: PrivateKeyStoreLike) {
    if (keyType !== KmsKeyType.BabyJubJub) {
      throw new Error("BjjProvider requires BabyJubJub key type.");
    }
    this.keyType = keyType;
    this.keyStore = keyStore;
  }

  async getPkStore(): Promise<PrivateKeyStoreLike> {
    return this.keyStore;
  }

  async list(): Promise<{ alias: string; key: string }[]> {
    const keys = await this.keyStore.list();
    return keys.filter((key) => key.alias.startsWith(this.keyType));
  }

  async newPrivateKeyFromSeed(seed: Uint8Array): Promise<KmsKeyId> {
    const key = await createBabyJubJubKey(seed);
    const id = keyPath(this.keyType, key.publicKeyHex);
    await this.keyStore.importKey({
      alias: id,
      key: key.privateKeyHex
    });
    return {
      type: this.keyType,
      id
    };
  }

  async newPrivateKey(): Promise<KmsKeyId> {
    const random = globalThis.crypto?.getRandomValues?.(new Uint8Array(32));
    if (!random) {
      throw new Error("BjjProvider requires crypto.getRandomValues for key creation.");
    }
    return this.newPrivateKeyFromSeed(random);
  }

  async publicKey(keyId: KmsKeyId): Promise<string> {
    const privateKeyHex = await this.keyStore.get({ alias: keyId.id });
    return publicKeyHexFromPrivateKeyHex(privateKeyHex);
  }

  async sign(_keyId: KmsKeyId, _data: Uint8Array): Promise<never> {
    throw new Error("BjjProvider.sign is outside this holder identity import block.");
  }

  async verify(_message: Uint8Array, _signatureHex: string, _keyId: KmsKeyId): Promise<boolean> {
    throw new Error("BjjProvider.verify is outside this holder identity import block.");
  }
}

export class CredentialWallet {
  constructor(readonly storage: unknown) {}

  async findByQuery(_query: unknown): Promise<unknown[]> {
    const credentialStorage = credentialStorageFrom(this.storage);
    return credentialStorage.findCredentialsByQuery(_query);
  }

  async remove(id: string): Promise<void> {
    const credentialStorage = credentialStorageFrom(this.storage);
    await credentialStorage.removeCredential(id);
  }
}

export class W3CCredential {}

export class IdentityWallet {
  constructor(
    private readonly _kms: KMS,
    private readonly _storage: {
      identity: {
        getIdentity(identifier: string): Promise<unknown | undefined>;
        saveIdentity(identity: {
          did: string;
          state?: unknown;
          isStatePublished?: boolean;
          isStateGenesis?: boolean;
        }): Promise<void>;
      };
      mt: {
        createIdentityMerkleTrees(identifier: string): Promise<unknown>;
        addToMerkleTree(identifier: string, mtType: unknown, hindex: bigint, hvalue: bigint): Promise<void>;
        getMerkleTreeByIdentifierAndType(identifier: string, mtType: unknown): Promise<{
          root(): Promise<{ bigInt(): bigint }>;
        }>;
        bindMerkleTreeToNewIdentifier(oldIdentifier: string, newIdentifier: string): Promise<void>;
      };
    },
    private readonly _credentialWallet: CredentialWallet
  ) {}

  get credentialWallet(): CredentialWallet {
    return this._credentialWallet;
  }

  async createIdentity(opts: {
    method?: string;
    blockchain?: string;
    networkId?: string;
    seed?: Uint8Array;
    revocationOpts: {
      id: string;
      type: string;
      nonce?: number;
      genesisPublishingDisabled?: boolean;
    };
  }): Promise<{ did: unknown; credential: unknown; keyId: string }> {
    let step = "random bytes available";
    try {
      const seed = opts.seed ?? createRandomSeed();
      step = "temporary identifier";
      const temporaryIdentifier = temporaryIdentifierFromSeed(seed);

      step = "create identity Merkle trees";
      await this._storage.mt.createIdentityMerkleTrees(temporaryIdentifier);

      step = "create BJJ key";
      const keyId = await this._kms.createKeyFromSeed(KmsKeyType.BabyJubJub, seed);
      step = "get BJJ public key";
      const publicKeyHex = await this._kms.publicKey(keyId);
      step = "create auth claim";
      const authClaim = createAuthCoreClaim(publicKeyHex, BigInt(opts.revocationOpts.nonce ?? 0));
      const { hi, hv } = authClaim.hiHv();

      step = "insert auth claim into claims tree";
      await this._storage.mt.addToMerkleTree(temporaryIdentifier, MerkleTreeType.Claims, hi, hv);
      step = "read claims tree root";
      const claimsTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
        temporaryIdentifier,
        MerkleTreeType.Claims
      );
      const claimsRoot = await claimsTree.root();
      step = "read revocation tree root";
      const revocationTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
        temporaryIdentifier,
        MerkleTreeType.Revocations
      );
      const revocationRoot = await revocationTree.root();
      step = "read roots tree root";
      const rootsTree = await this._storage.mt.getMerkleTreeByIdentifierAndType(
        temporaryIdentifier,
        MerkleTreeType.Roots
      );
      const rootsRoot = await rootsTree.root();
      step = "calculate identity state";
      const currentState = hashIdentityState(
        claimsRoot.bigInt(),
        revocationRoot.bigInt(),
        rootsRoot.bigInt()
      );
      step = "derive iden3 DID";
      const did = deriveIden3Did({
        method: opts.method,
        blockchain: opts.blockchain,
        networkId: opts.networkId,
        state: currentState
      });

      step = "bind Merkle trees to DID";
      await this._storage.mt.bindMerkleTreeToNewIdentifier(temporaryIdentifier, did);
      step = "persist holder identity metadata";
      if (!(await this._storage.identity.getIdentity(did))) {
        await this._storage.identity.saveIdentity({
          did,
          state: currentState.toString(),
          isStatePublished: false,
          isStateGenesis: true
        });
      }
      step = "persist AuthV2 identity material";
      await maybeSaveAuthV2IdentityMaterial(this._storage.identity, {
        did,
        keyId: keyId.id,
        authClaim: serializeAuthClaim(authClaim, BigInt(opts.revocationOpts.nonce ?? 0)),
        authClaimMarshal: authClaim.marshalJson(),
        authClaimHi: hi.toString(),
        authClaimHv: hv.toString(),
        authClaimRevocationNonce: BigInt(opts.revocationOpts.nonce ?? 0).toString(),
        claimsTreeRoot: claimsRoot.bigInt().toString(),
        revTreeRoot: revocationRoot.bigInt().toString(),
        rootsTreeRoot: rootsRoot.bigInt().toString(),
        state: currentState.toString(),
        isStateGenesis: true
      });

      return {
        did,
        keyId: keyId.id,
        credential: {
          id: `${did}#auth-bjj`,
          type: ["VerifiableCredential", "AuthBJJCredential"],
          issuer: did,
          credentialSubject: {
            id: did,
            x: authClaim.publicKeyX.toString(),
            y: authClaim.publicKeyY.toString()
          },
          credentialStatus: opts.revocationOpts,
          proof: []
        }
      };
    } catch (error) {
      throw new Error(`IdentityWallet.createIdentity failed at ${step}: ${formatDetailedError(error)}`);
    }
  }
}

enum MerkleTreeType {
  Claims = 0,
  Revocations = 1,
  Roots = 2
}

interface MobileAuthClaim {
  publicKeyX: bigint;
  publicKeyY: bigint;
  hiHv(): { hi: bigint; hv: bigint };
  marshalJson(): string[];
}

function createBabyJubJubKey(seed: Uint8Array): {
  privateKeyHex: string;
  publicKeyHex: string;
} {
  const privateKey = new Iden3Crypto.PrivateKey(seed);
  return {
    privateKeyHex: privateKey.hex(),
    publicKeyHex: privateKey.public().hex()
  };
}

function publicKeyHexFromPrivateKeyHex(privateKeyHex: string): string {
  const privateKey = new Iden3Crypto.PrivateKey(Iden3Crypto.Hex.decodeString(privateKeyHex));
  return privateKey.public().hex();
}

function keyPath(keyType: KmsKeyType, keyID: string): string {
  return `${keyType}:${keyID}`;
}

function credentialStorageFrom(storage: unknown): {
  findCredentialsByQuery(query: unknown): Promise<unknown[]>;
  removeCredential(id: string): Promise<void>;
} {
  if (storage && typeof storage === "object" && "credential" in storage) {
    return (storage as { credential: ReturnType<typeof credentialStorageFrom> }).credential;
  }
  return storage as ReturnType<typeof credentialStorageFrom>;
}

function createRandomSeed(): Uint8Array {
  const random = globalThis.crypto?.getRandomValues?.(new Uint8Array(32));
  if (!random) {
    throw new Error("IdentityWallet.createIdentity requires crypto.getRandomValues.");
  }
  return random;
}

function createAuthCoreClaim(publicKeyHex: string, revNonce: bigint): MobileAuthClaim {
  const publicKey = Iden3Crypto.PublicKey.newFromHex(publicKeyHex);
  const claim = Iden3Core.Claim.newClaim(
    Iden3Core.SchemaHash.authSchemaHash,
    Iden3Core.ClaimOptions.withIndexDataInts(publicKey.p[0], publicKey.p[1]),
    Iden3Core.ClaimOptions.withRevocationNonce(BigInt(0))
  );
  claim.setRevocationNonce(revNonce);
  return Object.assign(claim, {
    publicKeyX: publicKey.p[0],
    publicKeyY: publicKey.p[1]
  }) as MobileAuthClaim;
}

function hashIdentityState(claimsRoot: bigint, revTreeRoot: bigint, rootsTreeRoot: bigint): bigint {
  return MerkleTree.hashElems([
    claimsRoot,
    revTreeRoot,
    rootsTreeRoot
  ]).bigInt();
}

function deriveIden3Did(input: {
  method?: string;
  blockchain?: string;
  networkId?: string;
  state: bigint;
}): string {
  const didType = Iden3Core.buildDIDType(
    input.method || Iden3Core.DidMethod.Iden3,
    normalizeBlockchain(input.blockchain, Iden3Core.Blockchain.Polygon),
    input.networkId || Iden3Core.NetworkId.Amoy
  );
  const identifier = Iden3Core.Id.idGenesisFromIdenState(didType, input.state);
  return Iden3Core.DID.parseFromId(identifier).string();
}

function normalizeBlockchain(value: string | undefined, fallback: string): string {
  if (!value) {
    return fallback;
  }
  const normalized = value.toLowerCase();
  if (normalized === "polygon" || normalized === "ethereum") {
    return normalized;
  }
  return fallback;
}

function temporaryIdentifierFromSeed(seed: Uint8Array): string {
  return asciiBytesToString(Iden3Crypto.Hex.encode(Iden3Crypto.sha256(seed))).slice(0, 36);
}

function asciiBytesToString(value: Uint8Array | string): string {
  if (typeof value === "string") {
    return value;
  }
  return Array.from(value, (byte) => String.fromCharCode(byte)).join("");
}

function serializeAuthClaim(authClaim: MobileAuthClaim, revocationNonce: bigint): Record<string, string> {
  const { hi, hv } = authClaim.hiHv();
  return {
    schema: "auth",
    publicKeyX: authClaim.publicKeyX.toString(),
    publicKeyY: authClaim.publicKeyY.toString(),
    revocationNonce: revocationNonce.toString(),
    hi: hi.toString(),
    hv: hv.toString()
  };
}

async function maybeSaveAuthV2IdentityMaterial(
  identityStorage: unknown,
  material: {
    did: string;
    keyId: string;
    authClaim: unknown;
    authClaimMarshal?: string[];
    authClaimHi: string;
    authClaimHv: string;
    authClaimRevocationNonce: string;
    claimsTreeRoot: string;
    revTreeRoot: string;
    rootsTreeRoot: string;
    state: string;
    isStateGenesis: boolean;
  }
): Promise<void> {
  if (
    identityStorage &&
    typeof identityStorage === "object" &&
    "saveAuthV2IdentityMaterial" in identityStorage &&
    typeof (identityStorage as { saveAuthV2IdentityMaterial?: unknown }).saveAuthV2IdentityMaterial === "function"
  ) {
    const now = new Date().toISOString();
    await (identityStorage as {
      saveAuthV2IdentityMaterial(value: unknown): Promise<void>;
    }).saveAuthV2IdentityMaterial({
      ...material,
      createdAt: now,
      updatedAt: now
    });
  }
}

function formatDetailedError(error: unknown): string {
  if (!(error instanceof Error)) {
    return String(error);
  }

  const name = error.name || "Error";
  const message = error.message || "Unknown error";
  const rawCause = (error as { cause?: unknown }).cause;
  const cause = rawCause instanceof Error ? ` Cause: ${rawCause.message}` : "";
  const stack = typeof error.stack === "string" ? ` Stack: ${safeStack(error.stack)}` : "";
  return `${name}: ${message}${cause}${stack}`;
}

function safeStack(stack: string): string {
  return stack
    .split(/\r?\n/)
    .slice(0, 3)
    .map((line) => line.trim())
    .join(" | ");
}
