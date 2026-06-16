import { Merklizer, Path } from "@iden3/js-jsonld-merklization";
import type {
  CredentialAtomicQuerySigV2ValueProofProvider,
  CredentialProofQuery,
  JsonLdContextStore
} from "@privado-id/expo-sdk";

export class SigV2JsonLdValueProofProvider implements CredentialAtomicQuerySigV2ValueProofProvider {
  private readonly contextStore: JsonLdContextStore;
  private readonly contextUrls: string[];

  constructor(options: {
    contextStore: JsonLdContextStore;
    contextUrls?: string[];
  }) {
    this.contextStore = options.contextStore;
    this.contextUrls = options.contextUrls ?? [];
  }

  async buildValueProof(input: {
    credential: unknown;
    credentialType: string;
    field: string;
    operator: CredentialProofQuery["operator"];
    queryValue: unknown;
  }): Promise<{
    proof: unknown;
    pathKey: string;
    pathValue: string;
    queryValues: string[];
  }> {
    const credential = sanitizeCredentialForMerklization(asRecord(input.credential));
    await ensureContextsForCredential(this.contextStore, credential, this.contextUrls);
    const options = {
      documentLoader: this.contextStore.createDocumentLoader()
    };
    try {
      const merklizer = await Merklizer.merklizeJSONLD(JSON.stringify(credential), options);
      const path = await resolveCredentialSubjectPath({
        credential,
        credentialType: input.credentialType,
        field: input.field,
        merklizer,
        options
      });
      const proofResult = await merklizer.proof(path);
      if (!proofResult.value) {
        throw new Error(`ValueProof does not exist at credentialSubject.${input.field}.`);
      }
      const datatype = await merklizer.jsonLDType(path);
      const queryValues = await hashQueryValues(input.queryValue, input.operator, datatype);
      return {
        proof: proofResult.proof,
        pathKey: (await path.mtEntry()).toString(),
        pathValue: (await proofResult.value.mtEntry()).toString(),
        queryValues
      };
    } catch (error) {
      throw new Error(
        `Cannot build ValueProof for field ${input.field}. Check JSON-LD context, credentialSubject value, and query field path. ${errorMessage(error)}`
      );
    }
  }
}

async function resolveCredentialSubjectPath(input: {
  credential: Record<string, unknown>;
  credentialType: string;
  field: string;
  merklizer: Merklizer;
  options: Merklizer["options"];
}): Promise<Path> {
  try {
    const path = await Path.getContextPathKey(
      JSON.stringify({ "@context": input.credential["@context"] }),
      input.credentialType,
      input.field,
      input.options
    );
    path.prepend(["https://www.w3.org/2018/credentials#credentialSubject"]);
    return path;
  } catch {
    return input.merklizer.resolveDocPath(`credentialSubject.${input.field}`, input.options);
  }
}

async function hashQueryValues(
  value: unknown,
  operator: CredentialProofQuery["operator"],
  datatype: string
): Promise<string[]> {
  if (operator === "noop") {
    return [];
  }
  const values = Array.isArray(value) ? value : [value];
  const hashedValues: string[] = [];
  for (const entry of values) {
    hashedValues.push((await Merklizer.hashValue(datatype, entry)).toString());
  }
  return hashedValues;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Credential ValueProof requires a credential object.");
  }
  return value as Record<string, unknown>;
}

function sanitizeCredentialForMerklization(credential: Record<string, unknown>): Record<string, unknown> {
  const clone = JSON.parse(JSON.stringify(credential)) as Record<string, unknown>;
  delete clone.proof;
  delete clone.privadoId;
  return clone;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function ensureContextsForCredential(
  store: JsonLdContextStore,
  credential: unknown,
  contextUrls: string[]
): Promise<void> {
  const maybeNewStore = store as JsonLdContextStore & {
    ensureContextsForCredential?: (credential: unknown, extraContextUrls?: string[]) => Promise<unknown>;
  };
  if (typeof maybeNewStore.ensureContextsForCredential === "function") {
    await maybeNewStore.ensureContextsForCredential(credential, contextUrls);
    return;
  }
  await store.ensureContextsFromCredential(credential, contextUrls);
}
