import { cleanAgentText } from "../agent-stated-intent";
import type { McpFact } from "./mcp-call-types";
import { previewFieldsFor } from "./mcp-previews";
import { sentenceCase } from "./mcp-services";
import { valueKindOf } from "./mcp-values";

// The keys Core reads a tool's input from, in its order (see `agent-stated-intent.ts`).
const TOOL_INPUT_KEYS = ["tool_input", "toolInput", "toolArgs", "arguments"] as const;
// The keys Core reads the tool's name from, which picks the `toolCalls` item to use.
const TOOL_NAME_KEYS = ["tool_name", "toolName", "name", "tool"] as const;
/** Core cuts every string it records at this length. A cut string is exactly this long. */
export const CORE_STRING_LIMIT = 240;
// Bidirectional controls reorder text on screen, so the exact input shows them as escapes.
const BIDI_CONTROLS = new RegExp("[\\u061c\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]", "g");
const KEY_PATTERN = /^[A-Za-z0-9_.-]{1,60}$/;
// Core cuts every recorded string at its limit, so a row can show all that was kept.
const VALUE_CHARS = CORE_STRING_LIMIT;
const MAX_FACTS = 8;
// Fields that only point a tool at a tab, a spot on screen or a session. They mean nothing to a person, so they stay in the exact input.
const POINTER_FIELDS = new Set([
  "tabid", "tab_id", "coordinate", "coordinates", "start_coordinate", "request_id", "requestid", "session_id", "sessionid", "trace_id",
]);
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

/** The input Core approves: as an object for the rows, and as text for the exact-input disclosure. */
export type SelectedToolInput = { record: Record<string, unknown> | null; text: string | null };

const NO_INPUT: SelectedToolInput = { record: null, text: null };

/**
 * Picks the tool input the way Core does, once, so the rows and the disclosure
 * always describe the same value. A string input is never decoded for rows:
 * Core redacts the encoded text, so decoding it could surface a secret the
 * redaction hid. The disclosure shows that string as recorded.
 */
export function selectToolInput(raw: Record<string, unknown> | null): SelectedToolInput {
  if (raw === null) return NO_INPUT;
  const keyed = inputFromKeys(raw);
  const hasKeyedInput = keyed !== null && (keyed.record === null || Object.keys(keyed.record).length > 0);
  if (hasKeyedInput) return keyed;
  // Core falls back to the matching `toolCalls` item's args when the top-level input is empty.
  return inputFromToolCalls(raw) ?? keyed ?? NO_INPUT;
}

function inputFromKeys(raw: Record<string, unknown>): SelectedToolInput | null {
  for (const key of TOOL_INPUT_KEYS) {
    const value = raw[key];
    const record = recordOf(value);
    if (record !== null) return inputFromRecord(record);
    if (typeof value !== "string" || value.trim().length === 0) continue;
    if (coreSkipsString(value)) continue;
    return { record: null, text: escapeBidi(value) };
  }
  return null;
}

function inputFromToolCalls(raw: Record<string, unknown>): SelectedToolInput | null {
  const calls: unknown = raw.toolCalls;
  if (!Array.isArray(calls)) return null;
  const expected = TOOL_NAME_KEYS.map((key) => raw[key]).find(
    (value): value is string => typeof value === "string" && value.trim().length > 0,
  );
  let chosen: Record<string, unknown> | null | undefined;
  for (const item of calls) {
    const call = recordOf(item);
    const name = call?.name;
    if (call === null || typeof name !== "string" || name.trim().length === 0) continue;
    const args = recordOf(call.args);
    // The first named call stays the fallback even when it has no input, as it does in Core.
    if (chosen === undefined) chosen = args;
    if (expected === undefined || expected.trim() === name.trim()) {
      chosen = args;
      break;
    }
  }
  return chosen === undefined || chosen === null ? null : inputFromRecord(chosen);
}

function inputFromRecord(record: Record<string, unknown>): SelectedToolInput {
  try {
    return { record, text: escapeBidi(JSON.stringify(record, null, 2)) };
  } catch {
    return { record, text: null };
  }
}

/**
 * Core skips a string under these keys when it is not an object once decoded.
 * A string that does not decode is skipped too, unless it looks like an object
 * Core cut: Core ends a cut string with an ellipsis at exactly its cut length,
 * and an object starts with a brace. Core read the full text before the cut,
 * so such a string may be the input it chose.
 */
function coreSkipsString(text: string): boolean {
  try {
    return recordOf(JSON.parse(text)) === null;
  } catch {
    return !looksLikeCutObject(text);
  }
}

function looksLikeCutObject(text: string): boolean {
  return text.endsWith("…") && text.trimStart().startsWith("{") && Array.from(text).length === CORE_STRING_LIMIT;
}

/** Writes bidi controls as `\uXXXX` so the disclosure shows what they are instead of reordering the text. */
function escapeBidi(text: string): string {
  return text.replace(BIDI_CONTROLS, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})?)?$/;
const DAY_FORMAT: Intl.DateTimeFormatOptions = { weekday: "short", month: "short", day: "numeric", year: "numeric" };

/**
 * `2026-11-20T09:00:00` as `Fri, Nov 20, 2026, 9:00 AM`. A time with no zone is
 * shown exactly as written, with no clock change applied; one with a zone is
 * shown in the viewer's time with the zone named. Anything that is not a whole,
 * valid date and time stays as it was.
 */
export function readableDate(text: string): string | null {
  const match = ISO_DATE.exec(text.trim());
  if (match === null) return null;
  const [, year, month, day, hour, minute, second, zone] = match;
  const y = Number(year);
  const m = Number(month) - 1;
  const d = Number(day);
  const dayOnly = new Date(Date.UTC(y, m, d));
  if (dayOnly.getUTCFullYear() !== y || dayOnly.getUTCMonth() !== m || dayOnly.getUTCDate() !== d) return null;
  if (hour === undefined) {
    return new Intl.DateTimeFormat("en-US", { ...DAY_FORMAT, timeZone: "UTC" }).format(dayOnly);
  }
  const h = Number(hour);
  const min = Number(minute);
  const s = Number(second ?? 0);
  if (h > 23 || min > 59 || s > 59) return null;
  const time: Intl.DateTimeFormatOptions = { ...DAY_FORMAT, hour: "numeric", minute: "2-digit" };
  if (zone !== undefined) {
    const date = new Date(text.trim());
    if (Number.isNaN(date.getTime())) return null;
    return new Intl.DateTimeFormat("en-US", { ...time, timeZoneName: "short" }).format(date);
  }
  // Formatted in UTC so the viewer's clock changes cannot move the written time.
  return new Intl.DateTimeFormat("en-US", { ...time, timeZone: "UTC" }).format(new Date(Date.UTC(y, m, d, h, min, s)));
}

// Fields whose name says they hold a date or time. Only these are reformatted; a subject or a message stays as written.
const DATE_KEY = /(date|time|_at$|At$|^at$|start|end|due|deadline|until|since|when|day|scheduled|expires?)/i;

function isDateKey(key: string | undefined): boolean {
  return key !== undefined && DATE_KEY.test(key);
}

/** A value short enough for a one-line row, or null when it needs the full input to make sense. */
export function scalarText(value: unknown, key?: string): string | null {
  if (typeof value === "string") {
    const date = isDateKey(key) ? readableDate(value) : null;
    return date ?? textOf(value);
  }
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

/**
 * One row per simple field in an input, plus how many fields were left for the
 * full input. When `tool` names an action Guard knows, the fields people look
 * for (who an email goes to, what it says) come first, under plain labels.
 */
export function scalarFacts(
  input: Record<string, unknown> | null,
  options: { skip?: string[]; max?: number; tool?: string } = {},
): { facts: McpFact[]; hidden: number } {
  if (input === null) return { facts: [], hidden: 0 };
  const skip = new Set(options.skip ?? []);
  const max = options.max ?? MAX_FACTS;
  const facts = promotedFacts(input, skip, options.tool, max);
  const promoted = new Set(facts.map((fact) => fact.key));
  let hidden = 0;
  for (const [key, value] of Object.entries(input)) {
    if (skip.has(key) || promoted.has(key)) continue;
    if (POINTER_FIELDS.has(key.toLowerCase())) {
      hidden += 1;
      continue;
    }
    const text = KEY_PATTERN.test(key) ? scalarText(value, key) : null;
    if (text === null || text.length === 0 || facts.length >= max) {
      hidden += value === null || value === "" ? 0 : 1;
      continue;
    }
    facts.push({ label: sentenceCase(key), value: text, kind: valueKindOf(text), key });
  }
  return { facts, hidden };
}

/** Code keeps its lines, which a query needs to be read; other values become one line. Both stay within the row limit. */
function fieldText(value: unknown, kind: McpFact["kind"], key: string): string | null {
  if (kind !== "code" || typeof value !== "string") return scalarText(value, key);
  const code = codeOf(value);
  if (code === null) return null;
  const chars = Array.from(code);
  return chars.length > VALUE_CHARS ? `${chars.slice(0, VALUE_CHARS - 1).join("")}…` : code;
}

function promotedFacts(input: Record<string, unknown>, skip: Set<string>, tool: string | undefined, max: number): McpFact[] {
  const fields = tool !== undefined ? previewFieldsFor(tool) : null;
  if (fields === null) return [];
  const keysByLowerCase = new Map(Object.keys(input).map((key) => [key.toLowerCase(), key]));
  const facts: McpFact[] = [];
  for (const field of fields) {
    if (facts.length >= max) break;
    for (const candidate of field.keys) {
      const key = keysByLowerCase.get(candidate);
      if (key === undefined || skip.has(key) || facts.some((fact) => fact.key === key)) continue;
      const text = KEY_PATTERN.test(key) ? fieldText(input[key], field.kind, key) : null;
      if (text === null || text.length === 0) continue;
      facts.push({ label: field.label, value: text, kind: field.kind ?? valueKindOf(text), key });
      break;
    }
  }
  return facts;
}
