import { portableBase64UrlCodec, type Base64UrlCodec } from "../network/Base64UrlCodec";

export interface ParsedCredentialOffer {
  raw: string | Record<string, unknown>;
  message: Record<string, unknown>;
}

export function parseCredentialOffer(
  offer: string | Record<string, unknown>,
  codec: Base64UrlCodec = portableBase64UrlCodec
): ParsedCredentialOffer {
  if (typeof offer !== "string") {
    return { raw: offer, message: offer };
  }

  const trimmed = offer.trim();
  if (trimmed.startsWith("{")) {
    const message = JSON.parse(trimmed) as unknown;
    if (!isRecord(message)) {
      throw new Error("Credential offer message must be a JSON object.");
    }
    return { raw: offer, message };
  }

  const encodedMessage = extractEncodedMessage(trimmed);
  if (!encodedMessage) {
    throw new Error("Credential offer is invalid.");
  }

  const decoded = codec.decode(encodedMessage);
  const message = JSON.parse(decoded) as unknown;
  if (!isRecord(message)) {
    throw new Error("Credential offer message must be a JSON object.");
  }

  return { raw: offer, message };
}

function extractEncodedMessage(offer: string): string | undefined {
  try {
    const url = new URL(offer);
    return url.searchParams.get("i_m") ?? url.searchParams.get("message") ?? undefined;
  } catch {
    return offer;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
