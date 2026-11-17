import { harnessDisplayName } from "../approval-center-utils";
import type { GuardActionEnvelope, GuardApprovalRequest } from "../guard-types";
import { explainComposioTool, THOUGHT_CAPTION, type McpCallBody } from "./composio-calls";
import type { McpCallExplanation } from "./mcp-call-types";
import { consequenceFor } from "./mcp-consequence";
import { classifyMcpEffect, type McpEffectKind } from "./mcp-effects";
import {
  CORE_STRING_LIMIT,
  joinList,
  recordOf,
  scalarFacts,
  selectToolInput,
  textOf,
  type SelectedToolInput,
} from "./mcp-input";
import {
  isPlainNamePart,
  parseNamespacedMcpName,
  sentenceCase,
  serviceDisplayName,
  shortToolName,
  type McpServerRef,
} from "./mcp-services";

const UNKNOWN_SERVER = "a connected server";
const CODEX_APPS_SERVER = "codex_apps";
const AGENT_TEXT_KEYS = ["thought", "use_case"];

/**
 * Turns an MCP tool review into plain English from the call's own data: the
 * server and tool names Core recorded and the tool input. Nothing the agent
 * wrote about itself reaches the headline, the effect or the summary.
 *
 * Returns null when the request is not an MCP tool call.
 */
export function explainMcpCall(item: GuardApprovalRequest): McpCallExplanation | null {
  const envelope = item.action_envelope_json;
  if (!envelope) return null;
  const ref = resolveMcpRef(envelope);
  if (ref === null) return null;

  const harness = harnessDisplayName(item.harness);
  const raw = recordOf(envelope.raw_payload_redacted);
  const selected = selectToolInput(raw);
  const input = selected.record;
  const connector = ref.server.length > 0 ? serviceDisplayName(ref.server) : UNKNOWN_SERVER;
  const shortTool = shortToolName(ref.server, ref.tool);
  const body =
    (ref.server.toLowerCase() === "composio" ? explainComposioTool(shortTool, { harness, input }) : null) ??
    explainGenericTool({ harness, connector, shortTool, input });

  return {
    ...body,
    consequence: consequenceFor(body.effect, whereItActs(body, connector)),
    connector,
    rawInput: selected.text,
    truncated: wasTruncated(item, selected),
    toolId: ref.server.length > 0 ? `${ref.server} / ${ref.tool}` : ref.tool,
    whyAsked: `Guard has not reviewed ${ref.server.length > 0 ? `${connector}'s` : "this"} tool yet, and your policy asks before any unreviewed tool runs.`,
  };
}

/** The services the call's effect lands in: the apps of the actions that carry it, else the connector it goes through. */
function whereItActs(body: McpCallBody, connector: string): string {
  const apps = body.effectApps ?? [];
  return apps.length > 0 ? joinList(apps) : connector;
}

/** Replaces the policy-setting name Core gives for an unreviewed MCP tool with the reason in plain words. */
export function plainMcpReason(item: GuardApprovalRequest, text: string | null): string | null {
  if (text === null || !text.includes("unreviewed MCP tool")) {
    return text;
  }
  return explainMcpCall(item)?.whyAsked ?? text;
}

function resolveMcpRef(envelope: GuardActionEnvelope): McpServerRef | null {
  const fromToolName = parseNamespacedMcpName(envelope.tool_name);
  const fromMcpTool = parseNamespacedMcpName(envelope.mcp_tool);
  const isMcp =
    envelope.action_type === "mcp_tool" || fromToolName !== null || fromMcpTool !== null || isPlainNamePart(envelope.mcp_server);
  if (!isMcp) return null;
  const tool = recordedTool(envelope, fromToolName, fromMcpTool);
  if (tool === null) return null;
  return unwrapCodexApps({ server: recordedServer(envelope, fromToolName, fromMcpTool), tool });
}

function recordedTool(envelope: GuardActionEnvelope, fromToolName: McpServerRef | null, fromMcpTool: McpServerRef | null): string | null {
  if (fromMcpTool !== null) return fromMcpTool.tool;
  if (isPlainNamePart(envelope.mcp_tool)) return envelope.mcp_tool;
  return fromToolName?.tool ?? null;
}

function recordedServer(envelope: GuardActionEnvelope, fromToolName: McpServerRef | null, fromMcpTool: McpServerRef | null): string {
  // `mcp_tool` can carry the whole `mcp__codex_apps__<connector>__<tool>` name next to the wrapper server.
  if (envelope.mcp_server === CODEX_APPS_SERVER && fromMcpTool !== null) return fromMcpTool.server;
  if (isPlainNamePart(envelope.mcp_server)) return envelope.mcp_server;
  return fromMcpTool?.server ?? fromToolName?.server ?? "";
}

/**
 * Codex reaches connectors through `codex_apps`, and Core records that as the
 * server with `connector__tool` as the tool. The connector is the service the
 * user knows, so it takes the server's place.
 */
function unwrapCodexApps(ref: McpServerRef): McpServerRef {
  if (ref.server !== CODEX_APPS_SERVER) return ref;
  const separator = ref.tool.indexOf("__");
  if (separator <= 0 || separator + 2 >= ref.tool.length) return ref;
  return { server: ref.tool.slice(0, separator), tool: ref.tool.slice(separator + 2) };
}

function explainGenericTool(context: {
  harness: string;
  connector: string;
  shortTool: string;
  input: Record<string, unknown> | null;
}): McpCallBody {
  const { harness, connector, shortTool, input } = context;
  const effect = classifyMcpEffect(shortTool);
  const title = sentenceCase(shortTool);
  // `thought` and `use_case` are the agent's own account of the call. They are quoted, never shown as a fact.
  const { facts } = scalarFacts(input, { skip: AGENT_TEXT_KEYS, tool: shortTool });
  const thought = textOf(input?.thought, 300);
  const firstValue = facts[0]?.value ?? null;
  return {
    headline: `${harness} wants to ${effectPhrase(effect, connector)}`,
    title,
    aside: null,
    effect,
    effectBasis:
      effect === "unknown"
        ? "Guard cannot tell what this does from its name. Read the inputs below."
        : "Read from the tool's name. Guard has not checked what it does.",
    facts,
    steps: [],
    quotes: thought !== null ? { caption: THOUGHT_CAPTION, items: [thought] } : null,
    code: null,
    queueTitle: `${connector} · ${title}`,
    queueDetail: firstValue !== null && firstValue.length > 0 ? firstValue : null,
  };
}

function effectPhrase(effect: McpEffectKind, connector: string): string {
  switch (effect) {
    case "read":
      return `look something up in ${connector}`;
    case "write":
      return `make a change in ${connector}`;
    case "send":
      return `send something with ${connector}`;
    case "delete":
      return `delete something in ${connector}`;
    case "run-code":
      return `run code with ${connector}`;
    case "connect":
      return `change a connection in ${connector}`;
    case "unknown":
      return `use ${connector}`;
  }
}

function wasTruncated(item: GuardApprovalRequest, selected: SelectedToolInput): boolean {
  if ((item.action_explanation?.redaction.truncated_fields.length ?? 0) > 0) return true;
  // An input Core recorded as text is cut when it reaches the limit. Its rows are not read, so only its length says.
  if (selected.record === null) return selected.text !== null && selected.text.length >= CORE_STRING_LIMIT;
  return JSON.stringify(selected.record).length >= CORE_STRING_LIMIT && containsLongString(selected.record);
}

function containsLongString(value: unknown): boolean {
  if (typeof value === "string") return value.length >= CORE_STRING_LIMIT;
  if (Array.isArray(value)) return value.some(containsLongString);
  const record = recordOf(value);
  return record !== null && Object.values(record).some(containsLongString);
}
