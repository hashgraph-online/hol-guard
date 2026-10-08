const CLI_ID_PATTERN = /^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$/;
export const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`Invalid local CLI ${field}`);
  return value.trim();
}

export function requiredInt(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) throw new Error(`Invalid local CLI ${field}`);
  return value;
}

export function optionalString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") throw new Error("Invalid local CLI string");
  return value;
}

export function isLocalCliId(value: string): boolean {
  return CLI_ID_PATTERN.test(value);
}
