import { cleanAgentText, firstToolInput } from "../agent-stated-intent";
import type { McpFact } from "./mcp-call-types";
import { sentenceCase } from "./mcp-services";

// The keys Core reads a tool's input from, in its order (see `agent-stated-intent.ts`).
const TOOL_INPUT_KEYS = ["tool_input", "toolInput", "toolArgs", "arguments"] as const;
const KEY_PATTERN = /^[A-Za-z0-9_.-]{1,60}$/;
const VALUE_CHARS = 160;
const MAX_FACTS = 8;
const MAX_LIST_ITEMS = 6;
// Everything except tab and newline, plus bidirectional overrides that could reorder code on screen.
const UNSAFE_CODE_CHARACTERS = new RegExp(
  "[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f\\u061c\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]",
  "g",
);

export function recordOf(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function textOf(value: unknown, maxChars = VALUE_CHARS): string | null {
  if (typeof value !== "string") return null;
  const text = cleanAgentText(value, maxChars);
  return text.length > 0 ? text : null;
}

export function recordList(value: unknown, max = 20): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  return value.map(recordOf).filter((item): item is Record<string, unknown> => item !== null).slice(0, max);
}

export function textList(value: unknown, max = 20): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => textOf(item, 80))
    .filter((item): item is string => item !== null)
    .slice(0, max);
}

export function unique(values: string[]): string[] {
  const seen = new Set<string>();
  return values.filter((value) => {
    const key = value.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function joinList(values: string[], limit = 3): string {
  const shown = values.slice(0, limit);
  const rest = values.length - shown.length;
  const list =
    shown.length <= 2 ? shown.join(" and ") : `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
  return rest > 0 ? `${shown.join(", ")} and ${rest} more` : list;
}

/** Code or a command with control and bidi characters removed but its lines kept. */
export function codeOf(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const text = value.replace(UNSAFE_CODE_CHARACTERS, " ").trim();
  return text.length > 0 ? text : null;
}

/**
 * The tool input as an object, chosen the way Core chooses it. A string input
 * is never decoded: Core redacts the encoded text, so decoding it could surface
 * a secret the redaction hid. When Core's input is a string the card shows no
 * rows rather than rows from a different key.
 */
export function toolInputRecord(raw: Record<string, unknown> | null): Record<string, unknown> | null {
  return firstToolInput(raw);
}

/**
 * The input exactly as Guard holds it, for the disclosure that shows what an
 * approval matches. It follows the same order as `toolInputRecord`, so the rows
 * and the disclosure always describe the same value.
 */
export function rawInputText(raw: Record<string, unknown> | null): string | null {
  if (raw === null) return null;
  for (const key of TOOL_INPUT_KEYS) {
    const value = raw[key];
    const input = recordOf(value);
    if (input !== null) {
      try {
        return JSON.stringify(input, null, 2);
      } catch {
        return null;
      }
    }
    if (typeof value !== "string" || value.trim().length === 0) continue;
    if (isNonObjectJson(value)) continue;
    return value;
  }
  return null;
}

/** Core skips a string under these keys only when it parses as JSON that is not an object. */
function isNonObjectJson(text: string): boolean {
  try {
    return recordOf(JSON.parse(text)) === null;
  } catch {
    return false;
  }
}

/** A value short enough for a one-line row, or null when it needs the full input to make sense. */
export function scalarText(value: unknown): string | null {
  if (typeof value === "string") return textOf(value);
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value) && value.length > 0) {
    if (value.every((item) => typeof item === "string" || typeof item === "number")) {
      const shown = value.slice(0, MAX_LIST_ITEMS).map((item) => textOf(String(item), 60) ?? "");
      const rest = value.length - shown.length;
      return cleanAgentText(`${shown.filter(Boolean).join(", ")}${rest > 0 ? ` and ${rest} more` : ""}`, VALUE_CHARS);
    }
    return `${value.length} items`;
  }
  return null;
}

/** One row per simple field in an input, plus how many fields were left for the full input. */
export function scalarFacts(
  input: Record<string, unknown> | null,
  options: { skip?: string[]; max?: number } = {},
): { facts: McpFact[]; hidden: number } {
  if (input === null) return { facts: [], hidden: 0 };
  const skip = new Set(options.skip ?? []);
  const max = options.max ?? MAX_FACTS;
  const facts: McpFact[] = [];
  let hidden = 0;
  for (const [key, value] of Object.entries(input)) {
    if (skip.has(key)) continue;
    const text = KEY_PATTERN.test(key) ? scalarText(value) : null;
    if (text === null || text.length === 0 || facts.length >= max) {
      hidden += value === null || value === "" ? 0 : 1;
      continue;
    }
    facts.push({ label: sentenceCase(key), value: text });
  }
  return { facts, hidden };
}
