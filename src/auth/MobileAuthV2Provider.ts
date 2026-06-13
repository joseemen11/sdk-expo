import { CircuitId } from "../circuits/CircuitId";
import {
  formatCircuitArtifactMissingError,
  getMissingCircuitArtifactPaths
} from "../circuits/CircuitArtifactStore";
import { AuthV2InputBuilder } from "./AuthV2InputBuilder";
import {
  assertAuthV2InputsReadyForNativeWitness,
  buildAuthV2InputsPreview,
  type AuthV2NativeWitnessInputs,
  type AuthV2InputsPreview
} from "./AuthV2InputPreflight";
import type {
  AuthV2Provider,
  CircuitArtifactDescriptor,
  ClaimCredentialRuntimeContext,
  GeneratedProof,
  ProofRequest,
  ZKProvider
} from "../types";

const demoAuthV2Challenge = "12345678901234567890";

export interface MobileAuthV2ProviderOptions {
  zkProvider?: ZKProvider;
  circuitArtifacts?: CircuitArtifactDescriptor;
  inputBuilder?: AuthV2InputBuilder;
}

export interface AuthV2ClaimProof {
  circuitId: CircuitId.AuthV2;
  holderDid: string;
  keyId: string;
  proof: GeneratedProof;
  request: ProofRequest;
}

export interface AuthV2NativeWitnessInputResult {
  request: ProofRequest;
  inputs: AuthV2NativeWitnessInputs;
}

export class MobileAuthV2Provider implements AuthV2Provider {
  private readonly zkProvider?: ZKProvider;
  private readonly circuitArtifacts?: CircuitArtifactDescriptor;
  private readonly inputBuilder: AuthV2InputBuilder;

  constructor(options: MobileAuthV2ProviderOptions = {}) {
    this.zkProvider = options.zkProvider;
    this.circuitArtifacts = options.circuitArtifacts;
    this.inputBuilder = options.inputBuilder ?? new AuthV2InputBuilder();
  }

  async createAuthProof(input: ClaimCredentialRuntimeContext): Promise<AuthV2ClaimProof> {
    if (!this.zkProvider) {
      throw new Error("ZKProvider is required to generate AuthV2 proof for credential claim.");
    }
    if (!this.circuitArtifacts) {
      throw new Error("AuthV2 circuit artifacts are required to claim a credential from offer.");
    }
    const missingArtifacts = getMissingCircuitArtifactPaths(this.circuitArtifacts);
    if (missingArtifacts.length > 0) {
      throw new Error(formatCircuitArtifactMissingError(CircuitId.AuthV2, missingArtifacts));
    }

    const { request, inputs: nativeWitnessInputs } = await this.buildAuthV2NativeWitnessInputs(input);
    const proof = await this.zkProvider.generateProof({
      request,
      holderDid: input.holderDid.did,
      profileNonce: input.profileNonce,
      circuitArtifacts: this.circuitArtifacts,
      witnessInputs: nativeWitnessInputs,
      metadata: {
        holderDid: input.holderDid.did,
        keyId: input.keyId,
        credentialOfferMessageId: stringValue(input.message.id),
        credentialOfferThreadId: stringValue(input.message.thid)
      }
    });

    return {
      circuitId: CircuitId.AuthV2,
      holderDid: input.holderDid.did,
      keyId: input.keyId,
      proof,
      request
    };
  }

  async buildAuthV2InputsPreview(input: ClaimCredentialRuntimeContext): Promise<AuthV2InputsPreview> {
    const request = buildAuthV2ProofRequest(input);
    const witnessInputs = await this.inputBuilder.build({
      runtime: input,
      request
    });
    return buildAuthV2InputsPreview(witnessInputs);
  }

  async buildAuthV2NativeWitnessInputs(input: ClaimCredentialRuntimeContext): Promise<AuthV2NativeWitnessInputResult> {
    const request = buildAuthV2ProofRequest(input);
    const witnessInputs = await this.inputBuilder.build({
      runtime: input,
      request
    });
    return {
      request,
      inputs: assertAuthV2InputsReadyForNativeWitness(witnessInputs)
    };
  }
}

function buildAuthV2ProofRequest(input: ClaimCredentialRuntimeContext): ProofRequest {
  const messageBody = isRecord(input.message.body) ? input.message.body : {};
  const challenge =
    decimalStringValue(messageBody.challenge) ??
    decimalStringValue(messageBody.requestId) ??
    decimalStringValue(input.message.thid) ??
    decimalStringValue(input.message.id) ??
    demoAuthV2Challenge;

  return {
    id: stringValue(input.message.id) ?? "credential-claim-auth-v2",
    circuitId: CircuitId.AuthV2,
    challenge,
    query: {
      allowedIssuers: ["*"],
      type: "AuthV2"
    },
    scope: [],
    metadata: {
      holderDid: input.holderDid.did,
      keyId: input.keyId,
      profileNonce: input.profileNonce,
      credentialOfferMessageType: stringValue(input.message.type),
      credentialOfferUrl: stringValue(messageBody.url)
    }
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function decimalStringValue(value: unknown): string | undefined {
  if (typeof value === "bigint" && value >= 0n) {
    return value.toString();
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return String(value);
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    return value;
  }
  return undefined;
}
