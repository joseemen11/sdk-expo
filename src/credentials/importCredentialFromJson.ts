import { buildCredentialSummary } from "./diagnostics";

export interface ImportedCredential {
  credential: unknown;
  summary: ReturnType<typeof buildCredentialSummary>;
}

export function importCredentialFromJson(rawJson: string | Record<string, unknown>): ImportedCredential {
  const credential = typeof rawJson === "string" ? parseCredentialJson(rawJson) : rawJson;
  return {
    credential,
    summary: buildCredentialSummary(credential)
  };
}

function parseCredentialJson(rawJson: string): unknown {
  try {
    return JSON.parse(rawJson) as unknown;
  } catch {
    throw new Error("Credential JSON is invalid.");
  }
}
