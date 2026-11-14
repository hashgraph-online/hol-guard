import type { GuardActionEnvelope, GuardApprovalRequest } from "./guard-types";

/** What the tool's name says it does. Guard cannot see what the server really does with the call. */
export type McpToolCallEffect = "reads" | "changes" | "unknown";

export type McpToolCallField = {
  label: string;
  value: string;
  /** IDs, paths and URLs read better in a fixed-width face. */
  mono: boolean;
};

export type McpToolCallView = {
  /** "X Ads", or null when the name carries no server. */
  server: string | null;
  /** "List ads" */
  tool: string;
  /** "list ads in X Ads" — reads after "<app> wants to". */
  sentence: string;
  effect: McpToolCallEffect;
  fields: McpToolCallField[];
  /** Inputs left out of `fields`; they are still in `rawInput`. */
  hiddenFieldCount: number;
  /** The name the agent called, exactly. */
  technicalName: string;
  /** The tool's input as indented JSON, or null when it sent none. */
  rawInput: string | null;
};

const MAX_FIELDS = 12;
const MAX_VALUE_LENGTH = 160;
const MAX_LIST_ITEMS = 5;
const MAX_DEPTH = 2;

const READ_VERBS = new Set([
  "browse", "check", "count", "describe", "download", "export", "fetch", "find", "get", "inspect",
  "list", "lookup", "preview", "query", "read", "retrieve", "search", "show", "summarize", "view",
]);
const CHANGE_VERBS = new Set([
  "add", "approve", "archive", "assign", "book", "buy", "cancel", "charge", "close", "comment",
  "create", "delete", "deploy", "disable", "edit", "enable", "execute", "grant", "import", "insert",
  "invite", "merge", "modify", "move", "patch", "pause", "pay", "post", "publish", "purchase", "put",
  "refund", "remove", "rename", "reply", "revoke", "run", "schedule", "send", "set", "share", "start",
  "stop", "submit", "transfer", "update", "upload", "upsert", "write",
]);
const ACRONYMS = new Set([
  "ai", "api", "aws", "csv", "dm", "dns", "gcp", "html", "http", "id", "ids", "ip", "json", "mcp",
  "pdf", "pr", "sdk", "sms", "sql", "ssh", "ui", "uri", "url", "urls", "uuid",
]);
const BRANDS: Record<string, string> = {
  github: "GitHub",
  gitlab: "GitLab",
  hubspot: "HubSpot",
  linkedin: "LinkedIn",
  openai: "OpenAI",
  posthog: "PostHog",
  youtube: "YouTube",
};
const INPUT_KEYS = ["tool_input", "toolInput", "arguments", "input", "params"] as const;
const WRAPPER_INPUT_KEYS = ["tool_input", "toolInput", "arguments"] as const;
/** Keys only a hook payload carries next to its input; a tool's own arguments never need them. */
const WRAPPER_KEYS = new Set(["tool_name", "toolName", "hook_event_name"]);
const MONO_KEY = /(?:^|_)(?:id|ids|key|hash|sha|url|uri|path|file|dir|email)$/i;

function words(raw: string): string[] {
  return raw
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[\s_\-.:/]+/)
    .map((word) => word.trim().toLowerCase())
    .filter((word) => word.length > 0);
}

const PLURAL_ACRONYMS: Record<string, string> = { ids: "IDs", urls: "URLs" };

function displayWord(word: string): string {
  if (PLURAL_ACRONYMS[word] !== undefined) return PLURAL_ACRONYMS[word];
  if (ACRONYMS.has(word)) return word.toUpperCase();
  return BRANDS[word] ?? word;
}

function sentenceCase(parts: string[]): string {
  const shown = parts.map(displayWord);
  if (shown.length === 0) return "";
  const [first, ...rest] = shown;
  return [first.charAt(0).toUpperCase() + first.slice(1), ...rest].join(" ");
}

function titleCase(parts: string[]): string {
  return parts
    .map((word) => {
      const shown = displayWord(word);
      return shown === word ? word.charAt(0).toUpperCase() + word.slice(1) : shown;
    })
    .join(" ");
}

/** Split a tool name into its server and tool parts, in the spellings harnesses use. */
export function splitMcpToolName(
  raw: string,
  server: string | null = null,
): { server: string | null; tool: string } {
  const name = raw.trim();
  if (server !== null && server.trim().length > 0) {
    return { server: server.trim(), tool: stripServerPrefix(name, server.trim()) };
  }
  if (name.startsWith("mcp__")) {
    const parts = name.slice(5).split("__").filter((part) => part.length > 0);
    if (parts.length >= 3 && parts[0] === "codex_apps") {
      return { server: parts[1], tool: stripServerPrefix(parts.slice(2).join("__"), parts[1]) };
    }
    if (parts.length >= 2) {
      return { server: parts[0], tool: stripServerPrefix(parts.slice(1).join("__"), parts[0]) };
    }
  }
  const doubled = name.indexOf("__");
  if (doubled > 0 && doubled < name.length - 2) {
    const head = name.slice(0, doubled);
    return { server: head, tool: stripServerPrefix(name.slice(doubled + 2), head) };
  }
  const separator = name.match(/^([^/:·]+?)\s*(?:\/|:|·)\s*(.+)$/);
  if (separator) {
    return { server: separator[1], tool: stripServerPrefix(separator[2], separator[1]) };
  }
  return { server: null, tool: name };
}

function stripServerPrefix(tool: string, server: string): string {
  const prefix = `${server.toLowerCase()}_`;
  return tool.toLowerCase().startsWith(prefix) && tool.length > prefix.length ? tool.slice(prefix.length) : tool;
}

export function classifyMcpToolEffect(tool: string): McpToolCallEffect {
  const first = words(tool)[0];
  if (first === undefined) return "unknown";
  if (READ_VERBS.has(first)) return "reads";
  if (CHANGE_VERBS.has(first)) return "changes";
  return "unknown";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parsedJson(value: unknown): unknown {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return value;
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return value;
  }
}

/**
 * The arguments the agent passed to the tool. Some harnesses nest the whole hook
 * payload (`{tool_name, tool_input}`) inside the input; that wrapper is peeled off.
 */
export function mcpToolInput(payload: Record<string, unknown>): unknown {
  let input: unknown = null;
  for (const key of INPUT_KEYS) {
    if (payload[key] !== undefined && payload[key] !== null) {
      input = parsedJson(payload[key]);
      break;
    }
  }
  for (let depth = 0; depth < 3 && isRecord(input); depth += 1) {
    const record = input;
    const inner = WRAPPER_INPUT_KEYS.find((key) => record[key] !== undefined && record[key] !== null);
    if (inner === undefined) break;
    const others = Object.keys(record).filter((key) => key !== inner);
    if (others.length === 0 || !others.every((key) => WRAPPER_KEYS.has(key))) break;
    const unwrapped = parsedJson(record[inner]);
    if (!isRecord(unwrapped)) break;
    input = unwrapped;
  }
  return input;
}

function shorten(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > MAX_VALUE_LENGTH ? `${flat.slice(0, MAX_VALUE_LENGTH - 1)}…` : flat;
}

function scalarText(value: unknown): string | null {
  if (value === null || value === undefined) return "Empty";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (typeof value === "string") return value.trim().length === 0 ? "Empty" : shorten(value);
  return null;
}

function fieldLabel(path: string[]): string {
  return path.map((part) => sentenceCase(words(part)) || part).join(" › ");
}

function isMono(key: string, value: string): boolean {
  if (MONO_KEY.test(key.replace(/([a-z0-9])([A-Z])/g, "$1_$2"))) return true;
  return value.length >= 6 && !/\s/.test(value) && /\d/.test(value) && /[a-z]/i.test(value);
}

function countText(count: number, noun: string): string {
  if (count === 0) return "Empty";
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function collectFields(value: unknown, path: string[], out: McpToolCallField[]): void {
  const key = path.at(-1) ?? "";
  const scalar = scalarText(value);
  if (scalar !== null) {
    out.push({ label: fieldLabel(path), value: scalar, mono: scalar !== "Empty" && isMono(key, scalar) });
    return;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      out.push({ label: fieldLabel(path), value: "None", mono: false });
      return;
    }
    const scalars = value.map(scalarText);
    if (scalars.every((item): item is string => item !== null)) {
      const shown = scalars.slice(0, MAX_LIST_ITEMS).join(", ");
      const more = scalars.length > MAX_LIST_ITEMS ? ` and ${scalars.length - MAX_LIST_ITEMS} more` : "";
      out.push({ label: fieldLabel(path), value: shorten(`${shown}${more}`), mono: isMono(key, scalars[0]) });
      return;
    }
    out.push({ label: fieldLabel(path), value: countText(value.length, "item"), mono: false });
    return;
  }
  if (isRecord(value)) {
    const entries = Object.entries(value);
    if (path.length >= MAX_DEPTH || entries.length === 0) {
      const count = entries.length;
      out.push({ label: fieldLabel(path), value: countText(count, "setting"), mono: false });
      return;
    }
    for (const [childKey, child] of entries) collectFields(child, [...path, childKey], out);
  }
}

function rawJson(input: unknown): string | null {
  if (input === null || input === undefined) return null;
  if (typeof input === "string") return input.trim().length > 0 ? input : null;
  try {
    const text = JSON.stringify(input, null, 2);
    return text === undefined || text === "{}" ? null : text;
  } catch {
    return null;
  }
}

function toolNameOf(envelope: GuardActionEnvelope): string | null {
  for (const candidate of [envelope.mcp_tool, envelope.tool_name]) {
    if (typeof candidate === "string" && candidate.trim().length > 0) return candidate.trim();
  }
  const raw = envelope.raw_payload_redacted?.tool_name;
  return typeof raw === "string" && raw.trim().length > 0 ? raw.trim() : null;
}

function isMcpToolCall(item: GuardApprovalRequest, envelope: GuardActionEnvelope): boolean {
  if (envelope.action_type === "mcp_tool") return true;
  return item.artifact_type === "tool_call" && item.changed_fields.includes("runtime_tool_call");
}

/** A plain-language reading of a paused MCP tool call, or null for any other action. */
export function resolveMcpToolCallView(item: GuardApprovalRequest): McpToolCallView | null {
  const envelope = item.action_envelope_json;
  if (!envelope || !isMcpToolCall(item, envelope)) return null;
  const technicalName = toolNameOf(envelope);
  if (technicalName === null) return null;
  const split = splitMcpToolName(
    envelope.mcp_server && envelope.mcp_tool ? envelope.mcp_tool : technicalName,
    envelope.mcp_tool ? envelope.mcp_server : null,
  );
  const toolWords = words(split.tool);
  const tool = sentenceCase(toolWords) || split.tool;
  const server = split.server === null ? null : titleCase(words(split.server)) || split.server;
  const effect = classifyMcpToolEffect(split.tool);
  const where = server === null ? "" : ` in ${server}`;
  let sentence = `${toolWords.map(displayWord).join(" ")}${where}`;
  if (effect === "unknown") {
    sentence = server === null ? `use “${tool}”` : `use “${tool}” from ${server}`;
  }
  const input = mcpToolInput(envelope.raw_payload_redacted ?? {});
  const fields: McpToolCallField[] = [];
  if (isRecord(input)) {
    for (const [key, value] of Object.entries(input)) collectFields(value, [key], fields);
  } else if (input !== null && input !== undefined) {
    collectFields(input, ["input"], fields);
  }
  const fullName = envelope.mcp_server && envelope.mcp_tool
    ? `${envelope.mcp_server} / ${envelope.mcp_tool}`
    : technicalName;
  return {
    server,
    tool,
    sentence,
    effect,
    fields: fields.slice(0, MAX_FIELDS),
    hiddenFieldCount: Math.max(0, fields.length - MAX_FIELDS),
    technicalName: fullName,
    rawInput: rawJson(input),
  };
}
