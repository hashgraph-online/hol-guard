import schemaJson from "../../src/codex_plugin_scanner/guard/schemas/guard_action_explanation_v1.json";
import type { GuardActionExplanationV1 } from "./guard-types";

type Schema = Record<string, unknown>;
const schema = schemaJson as Schema;
const KEYWORDS = new Set([
  "$defs", "$id", "$ref", "$schema", "title", "type", "const", "enum", "properties", "required",
  "additionalProperties", "items", "minLength", "maxLength", "maxItems", "minimum", "maximum", "pattern",
]);
const patterns = new Map<string, RegExp>();
const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

function typeMatches(value: unknown, type: unknown): boolean {
  if (Array.isArray(type)) return type.some((item) => typeMatches(value, item));
  if (type === "null") return value === null;
  if (type === "object") return isRecord(value);
  if (type === "array") return Array.isArray(value);
  if (type === "integer") return typeof value === "number" && Number.isSafeInteger(value);
  return type === "string" ? typeof value === "string" : type === "boolean" && typeof value === "boolean";
}

function matchesString(value: string, rule: Schema): boolean {
  // JSON Schema measures Unicode code points, not JavaScript UTF-16 units.
  const length = Array.from(value).length;
  if (typeof rule.minLength === "number" && length < rule.minLength) return false;
  if (typeof rule.maxLength === "number" && length > rule.maxLength) return false;
  if (typeof rule.pattern !== "string") return true;
  let pattern = patterns.get(rule.pattern);
  if (!pattern) { pattern = new RegExp(rule.pattern, "u"); patterns.set(rule.pattern, pattern); }
  return pattern.test(value);
}

function matchesSchema(value: unknown, rule: Schema, budget: { left: number }, depth = 0): boolean {
  if (depth > 16 || --budget.left < 0 || Object.keys(rule).some((key) => !KEYWORDS.has(key))) return false;
  if (typeof rule.$ref === "string") {
    if (!rule.$ref.startsWith("#/$defs/") || !isRecord(schema.$defs)) return false;
    const resolved = schema.$defs[rule.$ref.slice(8)];
    if (!isRecord(resolved) || !matchesSchema(value, resolved, budget, depth + 1)) return false;
  }
  if (rule.type !== undefined && !typeMatches(value, rule.type)) return false;
  if (Object.hasOwn(rule, "const") && value !== rule.const) return false;
  if (Array.isArray(rule.enum) && !rule.enum.includes(value)) return false;
  if (typeof value === "string" && !matchesString(value, rule)) return false;
  if (typeof value === "number" && (!Number.isFinite(value)
    || (typeof rule.minimum === "number" && value < rule.minimum)
    || (typeof rule.maximum === "number" && value > rule.maximum))) return false;
  if (Array.isArray(value)) {
    if (typeof rule.maxItems === "number" && value.length > rule.maxItems) return false;
    if (isRecord(rule.items) && !value.every((item) => matchesSchema(item, rule.items as Schema, budget, depth + 1))) return false;
  }
  if (isRecord(value)) {
    const properties = isRecord(rule.properties) ? rule.properties : {};
    if (Array.isArray(rule.required) && rule.required.some((key) => typeof key !== "string" || !Object.hasOwn(value, key))) return false;
    for (const [key, item] of Object.entries(value)) {
      if (!Object.hasOwn(properties, key)) { if (rule.additionalProperties === false) return false; continue; }
      if (!isRecord(properties[key]) || !matchesSchema(item, properties[key] as Schema, budget, depth + 1)) return false;
    }
  }
  return true;
}

export function parseActionExplanation(value: unknown): GuardActionExplanationV1 | null {
  try {
    if (!isRecord(value) || !matchesSchema(value, schema, { left: 25000 })) return null;
    const explanation = value as GuardActionExplanationV1;
    if (explanation.explanation_version !== "1.0.0" || explanation.renderer_version !== "1.0.0"
      || explanation.redaction.policy_version !== "1" || !/^act_[a-f0-9]{64}$/.test(explanation.action_identity)
      || explanation.technical.action_id !== explanation.action_identity) return null;
    return explanation;
  } catch { return null; }
}

export async function opaqueExplanationIdentity(actionIdentity: string): Promise<string | null> {
  if (!actionIdentity.trim() || actionIdentity.length > 65536 || !globalThis.crypto?.subtle) return null;
  const bytes = new TextEncoder().encode(`hol-guard:action-explanation:v1\0${actionIdentity.trim()}`);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return `act_${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
