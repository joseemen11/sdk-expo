import { bytesToBase64, bytesToText, portableBase64UrlCodec, textToBytes } from "../network/Base64UrlCodec";
import { extractCredentialId } from "./extractCredentialId";
import type {
  ClaimCredentialRuntimeContext,
  Iden3commClaimProvider,
  IssuerClaimDebugStep,
  IssuerClaimDebugStepName,
  IssuerCredentialResolver,
  IssuerCredentialResolverInput,
  IssuerCredentialResolverResult,
  PrivadoExpoConfig
} from "../types";

const MEDIA_TYPE_ZKP_MESSAGE = "application/iden3-zkp-json";
const CONTENT_TYPE_ZKP_MESSAGE = "text/plain";
const FETCH_REQUEST_TYPE = "https://iden3-communication.io/credentials/1.0/fetch-request";
const ISSUANCE_RESPONSE_TYPE = "https://iden3-communication.io/credentials/1.0/issuance-response";
const FIELD_MODULUS = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DEFAULT_MTP_HYDRATION_ATTEMPTS = 10;
const DEFAULT_MTP_HYDRATION_DELAY_MS = 3000;

export interface IssuerClaimProviderOptions {
  config: PrivadoExpoConfig;
  fetchFn?: typeof fetch;
  now?: () => number;
  uuid?: () => string;
  onDebug?: (step: IssuerClaimDebugStep) => void;
  challengeCalculator?: (message: Record<string, unknown>) => Promise<string>;
}

export interface CreateIssuerCredentialInput {
  holderDid: string;
  credentialSubject: Record<string, unknown>;
  credentialType?: string;
  credentialSchema?: string;
  credentialExpirationDays?: number;
}

export interface PreparedIssuerClaimRequest {
  url: string;
  fetchRequest: Record<string, unknown>;
  challenge: string;
  tokenSummary: {
    header: {
      typ: string;
      alg: string;
      circuitId: string;
    };
    messageId?: string;
    messageIdFormat?: "uuid" | "invalid";
    threadId?: string;
    threadIdFormat?: "uuid" | "invalid";
    messageType?: string;
  };
}

export class IssuerClaimProvider implements Iden3commClaimProvider, IssuerCredentialResolver {
  private readonly config: PrivadoExpoConfig;
  private readonly fetchFn?: typeof fetch;
  private readonly now: () => number;
  private readonly uuid: () => string;
  private readonly onDebug?: (step: IssuerClaimDebugStep) => void;
  private readonly challengeCalculator: (message: Record<string, unknown>) => Promise<string>;

  constructor(options: IssuerClaimProviderOptions) {
    this.config = options.config;
    this.fetchFn = options.fetchFn;
    this.now = options.now ?? Date.now;
    this.uuid = options.uuid ?? randomId;
    this.onDebug = options.onDebug;
    this.challengeCalculator = options.challengeCalculator ?? calculateJwzAuthV2Challenge;
  }

  async createCredentialOffer(input: CreateIssuerCredentialInput): Promise<{ offer: string; raw: unknown }> {
    const issuer = requireIssuerAdminConfig(this.config);
    const credential = requireCredentialConfig(this.config, input);
    const expirationDays = input.credentialExpirationDays ?? this.config.credential?.credentialExpirationDays ?? 365;
    const expiration = Math.floor(this.now() / 1000) + expirationDays * 86400;
    const body = {
      credentialSchema: credential.schema,
      type: credential.type,
      credentialSubject: {
        id: input.holderDid,
        ...input.credentialSubject
      },
      expiration
    };

    const credentialResponse = await this.requestJson<unknown>({
      url: `${trimRightSlash(issuer.adminBase)}/v2/identities/${encodeURIComponent(
        issuer.issuerDid
      )}/credentials`,
      method: "POST",
      headers: this.adminHeaders(issuer),
      body: JSON.stringify(body)
    }, "createCredential");
    const credentialId = extractCredentialId(credentialResponse);
    if (!credentialId) {
      this.emitError("createCredential", "Issuer credential creation response did not include credential id.");
      throw new Error("Issuer credential creation response did not include credential id.");
    }
    const offerResponse = await this.requestJson<Record<string, unknown>>({
      url: `${trimRightSlash(issuer.adminBase)}/v2/identities/${encodeURIComponent(
        issuer.issuerDid
      )}/credentials/${encodeURIComponent(credentialId)}/offer?type=raw`,
      method: "GET",
      headers: this.adminHeaders(issuer)
    }, "offer");
    const offer = typeof offerResponse.universalLink === "string" ? offerResponse.universalLink : undefined;
    if (!offer) {
      this.emitError("offer", "Issuer credential offer response did not include universalLink.");
      throw new Error("Issuer credential offer response did not include universalLink.");
    }
    return { offer, raw: { credential: credentialResponse, offer: offerResponse } };
  }

  async claimCredentialFromOffer(input: ClaimCredentialRuntimeContext): Promise<unknown> {
    const prepared = await this.prepareClaimRequests(input);
    return this.claimPreparedCredentialRequests(prepared, input.authProof);
  }

  async prepareClaimRequests(input: ClaimCredentialRuntimeContext): Promise<PreparedIssuerClaimRequest[]> {
    const offer = parseOffer(input.message);
    const url = typeof offer.body.url === "string" ? offer.body.url : undefined;
    if (!url) {
      this.emitError("claim", "Credential offer is missing body.url.");
      throw new Error("Credential offer is missing body.url.");
    }
    const credentials = Array.isArray(offer.body.credentials) ? offer.body.credentials : [];
    if (credentials.length === 0) {
      this.emitError("claim", "Credential offer does not include credential references.");
      throw new Error("Credential offer does not include credential references.");
    }

    const prepared: PreparedIssuerClaimRequest[] = [];
    for (const credentialInfo of credentials) {
      const credentialId = getCredentialReferenceId(credentialInfo);
      let fetchRequest: Record<string, unknown>;
      try {
        fetchRequest = this.buildFetchRequest(input, credentialId);
        validateFetchRequestIds(fetchRequest);
      } catch (error) {
        this.emitError("claim", errorMessage(error), undefined, "build-fetch-request", false);
        throw error;
      }
      const tokenSummary = summarizeToken(fetchRequest);
      this.onDebug?.({
        step: "claim",
        status: "ok",
        claimLocalStep: "build-fetch-request",
        challengeSource: "jwz-message-hash",
        jwzHeader: tokenSummary.header,
        messageId: tokenSummary.messageId,
        messageIdFormat: tokenSummary.messageIdFormat,
        threadId: tokenSummary.threadId,
        threadIdFormat: tokenSummary.threadIdFormat,
        messageType: tokenSummary.messageType,
        postExecuted: false
      });
      let challenge: string;
      try {
        challenge = await this.challengeCalculator(fetchRequest);
        const challengeSummary = validateChallenge(challenge);
        this.onDebug?.({
          step: "claim",
          status: "ok",
          claimLocalStep: "compute-jwz-challenge",
          challengeSource: "jwz-message-hash",
          challengeLength: challengeSummary.length,
          challengeUnderField: challengeSummary.underField,
          postExecuted: false
        });
      } catch (error) {
        this.emitError("claim", errorMessage(error), undefined, "compute-jwz-challenge", false);
        throw error;
      }
      prepared.push({
        url,
        fetchRequest,
        challenge,
        tokenSummary
      });
    }
    return prepared;
  }

  async claimPreparedCredentialRequests(prepared: PreparedIssuerClaimRequest[], authProof: unknown): Promise<unknown> {
    const claimed: unknown[] = [];
    for (const request of prepared) {
      let token: string;
      try {
        token = packAuthV2ProofToken(request.fetchRequest, authProof);
        this.onDebug?.({
          step: "claim",
          status: "ok",
          claimLocalStep: "pack-jwz",
          challengeSource: "jwz-message-hash",
          jwzHeader: request.tokenSummary.header,
          messageId: request.tokenSummary.messageId,
          messageIdFormat: request.tokenSummary.messageIdFormat,
          threadId: request.tokenSummary.threadId,
          threadIdFormat: request.tokenSummary.threadIdFormat,
          messageType: request.tokenSummary.messageType,
          postExecuted: false
        });
      } catch (error) {
        this.emitError("claim", errorMessage(error), undefined, "pack-jwz", false);
        throw error;
      }
      this.onDebug?.({
        step: "claim",
        status: "ok",
        claimLocalStep: "post-agent",
        method: "POST",
        url: sanitizeUrl(request.url),
        challengeSource: "jwz-message-hash",
        jwzHeader: request.tokenSummary.header,
        messageId: request.tokenSummary.messageId,
        messageIdFormat: request.tokenSummary.messageIdFormat,
        threadId: request.tokenSummary.threadId,
        threadIdFormat: request.tokenSummary.threadIdFormat,
        messageType: request.tokenSummary.messageType,
        postExecuted: true
      });
      const responseText = await this.requestText({
        url: request.url,
        method: "POST",
        headers: {
          "Content-Type": CONTENT_TYPE_ZKP_MESSAGE
        },
        body: token
      }, "claim");
      const credential = parseCredentialFromIssuerResponse(responseText);
      const credentialSummary = summarizeIssuerCredential(credential);
      this.onDebug?.({
        step: "claim",
        status: "ok",
        claimLocalStep: "receive-credential",
        postExecuted: true,
        credentialSummary,
        responsePreview: credentialSummary.mtpViable
          ? "Issuer returned Iden3SparseMerkleTreeProof; MTP viable."
          : "Issuer returned only BJJSignature2021; MTP unavailable."
      });
      claimed.push(credential);
    }

    return { credentials: claimed };
  }

  async resolveCredentialWithProof(input: IssuerCredentialResolverInput): Promise<IssuerCredentialResolverResult> {
    const issuer = requireIssuerAdminConfig(this.config);
    const issuerDid = input.issuerDid ?? issuer.issuerDid;
    const requiredProofType = input.requiredProofType;
    const hydration = this.config.issuer?.credentialHydration;
    const attempts = Math.max(1, hydration?.proofPollAttempts ?? DEFAULT_MTP_HYDRATION_ATTEMPTS);
    const delayMs = Math.max(0, hydration?.proofPollDelayMs ?? DEFAULT_MTP_HYDRATION_DELAY_MS);
    let lastProofTypes: string[] = [];
    if (input.credentialId) {
      const detailUrl = `${trimRightSlash(issuer.adminBase)}/v2/identities/${encodeURIComponent(
        issuerDid
      )}/credentials/${encodeURIComponent(input.credentialId)}`;
      for (let attempt = 1; attempt <= attempts; attempt += 1) {
        const detail = await this.requestJson<unknown>({
          url: detailUrl,
          method: "GET",
          headers: this.adminHeaders(issuer)
        }, "hydrate");
        const metadataProofTypes = extractMetadataProofTypes(detail);
        const credential = extractCredentialFromIssuerAdminResponse(detail);
        const proofTypes = extractProofTypesFromCredential(credential);
        lastProofTypes = proofTypes.length > 0 ? proofTypes : metadataProofTypes;
        const matches = credential ? credentialsMatchForHydration(input.claimedCredential, credential, input) : false;
        const ready = credential && proofTypes.includes(requiredProofType) && matches;
        this.onDebug?.({
          step: "hydrate",
          status: ready ? "ok" : "skipped",
          hydration: buildHydrationSummary(input, credential, Boolean(ready), {
            credentialId: input.credentialId,
            metadataProofTypes,
            attempt,
            totalAttempts: attempts,
            source: "detail",
            reason: ready
              ? undefined
              : hydrationReason(proofTypes, metadataProofTypes, requiredProofType, matches)
          })
        });
        if (ready) {
          return {
            credential,
            hydrated: true,
            source: "detail",
            credentialId: input.credentialId,
            proofTypes
          };
        }
        if (attempt < attempts && delayMs > 0) {
          await sleep(delayMs);
        }
      }
    }

    const allowExistingFallback = input.allowExistingMtpCredentialFallback ?? hydration?.allowExistingMtpCredentialFallback ?? false;
    if (!allowExistingFallback) {
      return {
        hydrated: false,
        credentialId: input.credentialId,
        proofTypes: lastProofTypes
      };
    }

    const listUrl = buildCredentialListUrl({
      adminBase: issuer.adminBase,
      issuerDid,
      holderDid: input.holderDid,
      credentialType: input.credentialType,
      birthDate: extractCredentialSubjectField(input.claimedCredential, "birthDate")
    });
    const list = await this.requestJson<unknown>({
      url: listUrl,
      method: "GET",
      headers: this.adminHeaders(issuer)
    }, "hydrate");
    const candidates = extractCredentialsFromIssuerAdminList(list);
    const credential = candidates.find((candidate) =>
      hasProofType(candidate, requiredProofType) &&
      credentialsMatchForHydration(input.claimedCredential, candidate, input)
    );
    this.onDebug?.({
      step: "hydrate",
      status: credential ? "ok" : "skipped",
      hydration: buildHydrationSummary(input, credential, Boolean(credential), {
        credentialId: input.credentialId,
        source: "list",
        fallbackUsed: true,
        reason: credential ? undefined : `No existing credential with ${requiredProofType} was found.`
      })
    });
    return {
      credential,
      hydrated: Boolean(credential),
      source: credential ? "list" : undefined,
      credentialId: credential ? extractCredentialIdFromCredential(credential) : input.credentialId,
      proofTypes: credential ? extractProofTypesFromCredential(credential) : []
    };
  }

  private adminHeaders(issuer: RequiredIssuerAdminConfig): Record<string, string> {
    return {
      Authorization: toBasicAuth(issuer.username, issuer.password),
      "Content-Type": "application/json"
    };
  }

  private async requestJson<T>(input: RequestInput, step: IssuerClaimDebugStepName): Promise<T> {
    const text = await this.requestText(input, step);
    return (text ? JSON.parse(text) : null) as T;
  }

  private async requestText(input: RequestInput, step: IssuerClaimDebugStepName): Promise<string> {
    const fetchFn = this.fetchFn ?? (globalThis as unknown as { fetch?: typeof fetch }).fetch;
    if (!fetchFn) {
      throw new Error("A fetch-compatible HTTP client is required for issuer claim.");
    }
    let response: Response;
    try {
      response = await fetchFn(input.url, {
        method: input.method,
        headers: input.headers,
        body: input.body
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emitError(step, message, input);
      throw new Error(`Issuer ${step} network failed: ${message}`);
    }
    const text = await response.text();
    const event = {
      step,
      status: response.ok ? "ok" as const : "error" as const,
      method: input.method,
      url: sanitizeUrl(input.url),
      httpStatus: response.status,
      contentType: readHeader(response, "content-type"),
      responsePreview:
        response.ok && ((step === "claim" && input.method === "POST") || step === "hydrate")
          ? "credential response received"
          : truncate(text, 300)
    };
    this.onDebug?.(event);
    if (!response.ok) {
      throw new Error(readIssuerError(step, response.status, text));
    }
    return text;
  }

  private emitError(
    step: IssuerClaimDebugStepName,
    error: string,
    input?: RequestInput,
    claimLocalStep?: IssuerClaimDebugStep["claimLocalStep"],
    postExecuted?: boolean
  ): void {
    this.onDebug?.({
      step,
      status: "error",
      method: input?.method,
      url: input?.url ? sanitizeUrl(input.url) : undefined,
      claimLocalStep,
      postExecuted,
      error: truncate(error, 300)
    });
  }

  private buildFetchRequest(input: ClaimCredentialRuntimeContext, credentialId: string): Record<string, unknown> {
    return {
      id: this.uuid(),
      typ: MEDIA_TYPE_ZKP_MESSAGE,
      type: FETCH_REQUEST_TYPE,
      thid: readOfferThreadId(input.message),
      body: {
        id: credentialId
      },
      from: input.holderDid.did,
      to: typeof input.message.from === "string" ? input.message.from : undefined
    };
  }
}

function packAuthV2ProofToken(message: Record<string, unknown>, authProof: unknown): string {
  validateFetchRequestIds(message);
  const proof = toJwzProof(authProof);
  const header = jwzHeader();
  const protectedHeaders = JSON.stringify(header, Object.keys(header).sort());
  return [
    portableBase64UrlCodec.encode(protectedHeaders),
    portableBase64UrlCodec.encode(JSON.stringify(message)),
    portableBase64UrlCodec.encode(JSON.stringify(proof))
  ].join(".");
}

async function calculateJwzAuthV2Challenge(message: Record<string, unknown>): Promise<string> {
  const { poseidon, sha256 } = await import("@iden3/js-crypto");
  const header = jwzHeader();
  const protectedHeaders = JSON.stringify(header, Object.keys(header).sort());
  const protectedPart = portableBase64UrlCodec.encode(protectedHeaders);
  const payloadPart = portableBase64UrlCodec.encode(JSON.stringify(message));
  const messageToProof = textToBytes(`${protectedPart}.${payloadPart}`);
  const hashBytes = sha256(messageToProof);
  const bi = bytesToLittleEndianInt(hashBytes);
  const messageField = bi < FIELD_MODULUS ? bi : bi % FIELD_MODULUS;
  const hashInt = poseidon.hash([messageField]);
  const challenge = hashInt.toString();
  validateChallenge(challenge);
  return challenge;
}

function validateChallenge(value: string): { length: number; underField: boolean } {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error("JWZ challenge must be a decimal bigint string.");
  }
  const parsed = BigInt(value);
  if (parsed < 0n) {
    throw new Error("JWZ challenge must be non-negative.");
  }
  if (parsed >= FIELD_MODULUS) {
    throw new Error("JWZ challenge is outside the BN254 field.");
  }
  return {
    length: value.length,
    underField: true
  };
}

function jwzHeader(): { alg: string; circuitId: string; crit: string[]; typ: string } {
  return {
    alg: "groth16",
    circuitId: "authV2",
    crit: ["circuitId"],
    typ: MEDIA_TYPE_ZKP_MESSAGE
  };
}

function summarizeToken(message: Record<string, unknown>): PreparedIssuerClaimRequest["tokenSummary"] {
  const header = jwzHeader();
  const messageId = typeof message.id === "string" ? message.id : undefined;
  const threadId = typeof message.thid === "string" ? message.thid : undefined;
  return {
    header: {
      typ: header.typ,
      alg: header.alg,
      circuitId: header.circuitId
    },
    messageId,
    messageIdFormat: messageId ? uuidFormat(messageId) : undefined,
    threadId,
    threadIdFormat: threadId ? uuidFormat(threadId) : undefined,
    messageType: typeof message.type === "string" ? message.type : undefined
  };
}

function validateFetchRequestIds(message: Record<string, unknown>): void {
  if (typeof message.id !== "string" || !isUuid(message.id)) {
    throw new Error("Iden3comm fetch-request id must be a UUID.");
  }
  if (typeof message.thid === "string" && !isUuid(message.thid)) {
    throw new Error("Iden3comm fetch-request thid must be a UUID.");
  }
}

function readOfferThreadId(message: Record<string, unknown>): string | undefined {
  const thid = typeof message.thid === "string" ? message.thid : undefined;
  if (thid) {
    if (!isUuid(thid)) {
      throw new Error("Iden3comm offer thid must be a UUID.");
    }
    return thid;
  }
  const id = typeof message.id === "string" ? message.id : undefined;
  if (id && isUuid(id)) {
    return id;
  }
  return undefined;
}

function isUuid(value: string): boolean {
  return UUID_REGEX.test(value);
}

function uuidFormat(value: string): "uuid" | "invalid" {
  return isUuid(value) ? "uuid" : "invalid";
}

function toJwzProof(authProof: unknown): { proof: unknown; pub_signals: unknown } {
  const generated = isRecord(authProof) && isRecord(authProof.proof) ? authProof.proof : authProof;
  if (!isRecord(generated)) {
    throw new Error("AuthV2 proof is missing for issuer claim.");
  }
  const proof = generated.proof;
  const publicSignals = generated.pub_signals ?? generated.publicSignals;
  if (!proof || !publicSignals) {
    throw new Error("AuthV2 proof is incomplete for issuer claim.");
  }
  return {
    proof,
    pub_signals: publicSignals
  };
}

function parseCredentialFromIssuerResponse(text: string): unknown {
  const message = parseIden3commMessage(text);
  if (message.type && message.type !== ISSUANCE_RESPONSE_TYPE) {
    throw new Error(`Unexpected issuer response type: ${String(message.type)}`);
  }
  const body = isRecord(message.body) ? message.body : {};
  const credential = body.credential ?? message.credential ?? message.vc ?? message.verifiableCredential;
  if (!credential) {
    throw new Error("Issuer response did not include a credential.");
  }
  return credential;
}

function summarizeIssuerCredential(credential: unknown): NonNullable<IssuerClaimDebugStep["credentialSummary"]> {
  const record = isRecord(credential) ? credential : {};
  const proofTypes = extractProofTypes(record.proof);
  const credentialStatus = summarizeCredentialStatus(record.credentialStatus);
  const mtpViable = proofTypes.includes("Iden3SparseMerkleTreeProof");
  return {
    id: typeof record.id === "string" ? record.id : undefined,
    type: extractTypes(record.type),
    issuer: extractIssuer(record.issuer),
    proofTypes,
    credentialStatus,
    mtpViable,
    mtpUnavailableReason: mtpViable ? undefined : "Issuer returned only BJJSignature2021; MTP unavailable."
  };
}

function extractTypes(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === "string");
  }
  return typeof value === "string" ? [value] : [];
}

function extractProofTypes(value: unknown): string[] {
  const proofs = Array.isArray(value) ? value : value ? [value] : [];
  return proofs
    .filter(isRecord)
    .map((proof) => proof.type)
    .flatMap((type) => Array.isArray(type) ? type : [type])
    .filter((type): type is string => typeof type === "string" && type.length > 0);
}

function extractIssuer(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  return isRecord(value) && typeof value.id === "string" ? value.id : undefined;
}

function summarizeCredentialStatus(value: unknown): NonNullable<IssuerClaimDebugStep["credentialSummary"]>["credentialStatus"] | undefined {
  const statuses = Array.isArray(value) ? value : value ? [value] : [];
  const first = statuses.find(isRecord);
  if (!first) {
    return undefined;
  }
  return {
    type: typeof first.type === "string" ? first.type : undefined,
    url: typeof first.id === "string" ? sanitizeUrlWithoutQuery(first.id) : undefined
  };
}

function extractCredentialFromIssuerAdminResponse(value: unknown): unknown | undefined {
  if (isCredentialObject(value)) {
    return value;
  }
  if (!isRecord(value)) {
    return undefined;
  }
  const candidates = [
    value.credential,
    value.vc,
    value.verifiableCredential,
    value.data,
    value.item,
    value.result
  ];
  for (const candidate of candidates) {
    const credential = extractCredentialFromIssuerAdminResponse(candidate);
    if (credential) {
      return credential;
    }
  }
  return undefined;
}

function extractCredentialsFromIssuerAdminList(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => {
      const credential = extractCredentialFromIssuerAdminResponse(entry);
      return credential ? [credential] : [];
    });
  }
  if (!isRecord(value)) {
    return [];
  }
  const candidates = [
    value.credentials,
    value.items,
    value.data,
    value.results,
    value.docs
  ];
  for (const candidate of candidates) {
    const credentials = extractCredentialsFromIssuerAdminList(candidate);
    if (credentials.length > 0) {
      return credentials;
    }
  }
  const single = extractCredentialFromIssuerAdminResponse(value);
  return single ? [single] : [];
}

function isCredentialObject(value: unknown): value is Record<string, unknown> {
  return isRecord(value) &&
    typeof value.id === "string" &&
    Boolean(value.credentialSubject) &&
    (Boolean(value.proof) || Boolean(value.credentialStatus));
}

function hasProofType(credential: unknown, proofType: string): boolean {
  return extractProofTypesFromCredential(credential).includes(proofType);
}

function extractProofTypesFromCredential(credential: unknown): string[] {
  return isRecord(credential) ? extractProofTypes(credential.proof) : [];
}

function extractCredentialIdFromCredential(credential: unknown): string | undefined {
  return isRecord(credential) && typeof credential.id === "string" ? credential.id : undefined;
}

function credentialsMatchForHydration(
  claimedCredential: unknown,
  candidate: unknown,
  input: IssuerCredentialResolverInput
): boolean {
  const claimedSubjectId = extractCredentialSubjectId(claimedCredential);
  const candidateSubjectId = extractCredentialSubjectId(candidate);
  if (!sameWhenBothPresent(candidateSubjectId, claimedSubjectId ?? input.holderDid)) {
    return false;
  }
  if (!sameWhenBothPresent(extractIssuer(candidate), extractIssuer(claimedCredential) ?? input.issuerDid)) {
    return false;
  }
  if (!sameWhenBothPresent(extractCredentialType(candidate), extractCredentialType(claimedCredential) ?? input.credentialType)) {
    return false;
  }
  if (!sameWhenBothPresent(extractCredentialSchema(candidate), extractCredentialSchema(claimedCredential) ?? input.credentialSchema)) {
    return false;
  }
  const claimedBirthDate = extractCredentialSubjectField(claimedCredential, "birthDate");
  const candidateBirthDate = extractCredentialSubjectField(candidate, "birthDate");
  if (!sameWhenBothPresent(candidateBirthDate, claimedBirthDate)) {
    return false;
  }
  return true;
}

function buildCredentialListUrl(input: {
  adminBase: string;
  issuerDid: string;
  holderDid: string;
  credentialType?: string;
  birthDate?: string;
}): string {
  const params = new URLSearchParams();
  params.set("credentialSubject", input.holderDid);
  if (input.credentialType) {
    params.set("schemaType", input.credentialType);
  }
  if (input.birthDate) {
    params.set("birthDate", input.birthDate);
  }
  params.set("revoked", "false");
  params.set("status", "all");
  params.set("sort", "-createdAt");
  return `${trimRightSlash(input.adminBase)}/v2/identities/${encodeURIComponent(input.issuerDid)}/credentials?${params.toString()}`;
}

function buildHydrationSummary(
  input: IssuerCredentialResolverInput,
  credential: unknown,
  hydrated: boolean,
  options: {
    credentialId?: string;
    metadataProofTypes?: string[];
    attempt?: number;
    totalAttempts?: number;
    source?: "detail" | "list";
    fallbackUsed?: boolean;
    reason?: string;
  } = {}
): NonNullable<IssuerClaimDebugStep["hydration"]> {
  const hydratedProofTypes = extractProofTypesFromCredential(credential);
  const metadataProofTypes = options.metadataProofTypes ?? [];
  return {
    credentialId: options.credentialId,
    claimedCredentialId: extractCredentialIdFromCredential(input.claimedCredential),
    claimedProofTypes: extractProofTypesFromCredential(input.claimedCredential),
    hydrated,
    hydratedCredentialId: extractCredentialIdFromCredential(credential),
    hydratedProofTypes,
    metadataProofTypes,
    metadataMtpOnly: metadataProofTypes.includes(input.requiredProofType) && !hydratedProofTypes.includes(input.requiredProofType),
    attempt: options.attempt,
    totalAttempts: options.totalAttempts,
    source: options.source,
    fallbackUsed: options.fallbackUsed,
    credentialSubjectId: extractCredentialSubjectId(credential) ?? extractCredentialSubjectId(input.claimedCredential),
    issuer: extractIssuer(credential) ?? extractIssuer(input.claimedCredential) ?? input.issuerDid,
    schema: extractCredentialSchema(credential) ?? extractCredentialSchema(input.claimedCredential) ?? input.credentialSchema,
    selectedProofType: hydrated ? input.requiredProofType : undefined,
    reason: options.reason
  };
}

function extractMetadataProofTypes(value: unknown): string[] {
  if (!isRecord(value)) {
    return [];
  }
  const direct = value.proofTypes ?? value.proof_types ?? value.credentialProofTypes;
  if (Array.isArray(direct)) {
    return direct.filter((entry): entry is string => typeof entry === "string" && entry.length > 0);
  }
  if (typeof direct === "string") {
    return [direct];
  }
  const nested = [value.data, value.result, value.item].flatMap((entry) => extractMetadataProofTypes(entry));
  return [...new Set(nested)];
}

function hydrationReason(
  proofTypes: string[],
  metadataProofTypes: string[],
  requiredProofType: string,
  matches: boolean
): string {
  if (!matches) {
    return "Hydrated credential did not match claimed credential metadata.";
  }
  if (metadataProofTypes.includes(requiredProofType) && !proofTypes.includes(requiredProofType)) {
    return `Issuer metadata advertises ${requiredProofType}, but vc.proof[] does not contain it yet.`;
  }
  return `Credential proofTypes from vc.proof[]: ${proofTypes.length > 0 ? proofTypes.join(", ") : "none"}.`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function extractCredentialType(credential: unknown): string | undefined {
  if (!isRecord(credential)) {
    return undefined;
  }
  const types = Array.isArray(credential.type) ? credential.type : [credential.type];
  return [...types].reverse().find((type): type is string => typeof type === "string" && type !== "VerifiableCredential");
}

function extractCredentialSchema(credential: unknown): string | undefined {
  if (!isRecord(credential)) {
    return undefined;
  }
  const schema = credential.credentialSchema;
  if (typeof schema === "string") {
    return schema;
  }
  return isRecord(schema) && typeof schema.id === "string" ? schema.id : undefined;
}

function extractCredentialSubjectId(credential: unknown): string | undefined {
  const subject = isRecord(credential) ? credential.credentialSubject : undefined;
  if (Array.isArray(subject)) {
    const first = subject.find(isRecord);
    return typeof first?.id === "string" ? first.id : undefined;
  }
  return isRecord(subject) && typeof subject.id === "string" ? subject.id : undefined;
}

function extractCredentialSubjectField(credential: unknown, field: string): string | undefined {
  const subject = isRecord(credential) ? credential.credentialSubject : undefined;
  const source = Array.isArray(subject) ? subject.find(isRecord) : subject;
  const value = isRecord(source) ? source[field] : undefined;
  return value === undefined || value === null ? undefined : String(value);
}

function sameWhenBothPresent(left?: string, right?: string): boolean {
  return !left || !right || left === right;
}

function parseIden3commMessage(text: string): Record<string, unknown> {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("Issuer returned an empty credential response.");
  }
  if (trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed) as unknown;
    return isRecord(parsed) ? parsed : {};
  }
  const parts = trimmed.split(".");
  if (parts.length === 3) {
    const payload = JSON.parse(bytesToText(portableBase64UrlCodec.decodeToBytes(parts[1]))) as unknown;
    return isRecord(payload) ? payload : {};
  }
  throw new Error("Issuer credential response shape is unsupported.");
}

function parseOffer(message: Record<string, unknown>): { body: Record<string, unknown> } {
  const body = isRecord(message.body) ? message.body : undefined;
  if (!body) {
    throw new Error("Credential offer is missing body.");
  }
  return { body };
}

function getCredentialReferenceId(value: unknown): string {
  if (isRecord(value) && typeof value.id === "string" && value.id.length > 0) {
    return value.id;
  }
  throw new Error("Credential offer includes a credential reference without id.");
}

interface RequiredIssuerAdminConfig {
  issuerDid: string;
  adminBase: string;
  username: string;
  password: string;
}

function requireIssuerAdminConfig(config: PrivadoExpoConfig): RequiredIssuerAdminConfig {
  const issuer = config.issuer;
  const username = issuer?.basicAuth?.username;
  const password = issuer?.basicAuth?.password;
  if (!issuer?.issuerDid || !issuer.issuerAdminBase || !username || !password) {
    throw new Error("Issuer admin configuration is required to claim credential from issuer.");
  }
  return {
    issuerDid: issuer.issuerDid,
    adminBase: issuer.issuerAdminBase,
    username,
    password
  };
}

function requireCredentialConfig(
  config: PrivadoExpoConfig,
  input: CreateIssuerCredentialInput
): { type: string; schema: string } {
  const type = input.credentialType ?? config.credential?.credentialType;
  const schema = input.credentialSchema ?? config.credential?.credentialSchema;
  if (!type || !schema) {
    throw new Error("Credential type and schema are required to claim credential from issuer.");
  }
  return { type, schema };
}

function toBasicAuth(username: string, password: string): string {
  return `Basic ${bytesToBase64(textToBytes(`${username}:${password}`))}`;
}

function trimRightSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function readIssuerError(step: IssuerClaimDebugStepName, status: number, text: string): string {
  if (!text) {
    return `Issuer ${step} failed with HTTP ${status} without body.`;
  }
  try {
    const parsed = JSON.parse(text) as { message?: unknown; error?: unknown };
    if (typeof parsed.message === "string") {
      return `Issuer ${step} failed with HTTP ${status}: ${truncate(parsed.message, 300)}`;
    }
    if (typeof parsed.error === "string") {
      return `Issuer ${step} failed with HTTP ${status}: ${truncate(parsed.error, 300)}`;
    }
  } catch {
    // Keep the raw response text below.
  }
  return `Issuer ${step} failed with HTTP ${status}: ${truncate(text, 300)}`;
}

function randomId(): string {
  const cryptoLike = globalThis as unknown as {
    crypto?: {
      randomUUID?: () => string;
      getRandomValues?: <T extends Uint8Array>(array: T) => T;
    };
  };
  const randomUUID = cryptoLike.crypto?.randomUUID?.();
  if (randomUUID && isUuid(randomUUID)) {
    return randomUUID;
  }
  const bytes = new Uint8Array(16);
  if (!cryptoLike.crypto?.getRandomValues) {
    throw new Error("crypto.getRandomValues is required to create iden3comm message id.");
  }
  cryptoLike.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return bytesToUuid(bytes);
}

function bytesToUuid(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  return [
    hex.slice(0, 4).join(""),
    hex.slice(4, 6).join(""),
    hex.slice(6, 8).join(""),
    hex.slice(8, 10).join(""),
    hex.slice(10, 16).join("")
  ].join("-");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function truncate(value: string, maxLength: number): string {
  return value.length <= maxLength ? value : `${value.slice(0, maxLength)}...`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sanitizeUrl(value: string): string {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    return url.toString();
  } catch {
    return value;
  }
}

function sanitizeUrlWithoutQuery(value: string): string {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return value.split("?")[0].split("#")[0];
  }
}

function readHeader(response: Response, name: string): string | undefined {
  const headers = response.headers as Headers | undefined;
  return headers?.get?.(name) ?? undefined;
}

function bytesToLittleEndianInt(bytes: Uint8Array): bigint {
  let result = 0n;
  let base = 1n;
  for (const byte of bytes) {
    result += base * BigInt(byte);
    base *= 256n;
  }
  return result;
}

interface RequestInput {
  url: string;
  method: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
}
