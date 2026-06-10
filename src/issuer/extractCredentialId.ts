export function extractCredentialId(input: unknown): string | undefined {
  if (typeof input === "string") {
    return extractFromString(input);
  }

  if (isRecord(input)) {
    const direct = stringValue(input.id) ?? stringValue(input.credentialId);
    if (direct) {
      return direct;
    }

    const body = isRecord(input.body) ? input.body : input;
    const credentials = body.credentials;
    if (Array.isArray(credentials)) {
      const first = credentials.find(isRecord);
      return first ? stringValue(first.id) ?? stringValue(first.credentialId) : undefined;
    }
  }

  return undefined;
}

function extractFromString(value: string): string | undefined {
  try {
    const url = new URL(value);
    return url.searchParams.get("credentialId") ?? url.searchParams.get("id") ?? undefined;
  } catch {
    return value.length > 0 ? value : undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
