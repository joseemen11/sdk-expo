export function normalizeCredentialContexts(context: unknown): string[] {
  if (Array.isArray(context)) {
    return context.filter((item): item is string => typeof item === "string");
  }
  return typeof context === "string" ? [context] : [];
}
