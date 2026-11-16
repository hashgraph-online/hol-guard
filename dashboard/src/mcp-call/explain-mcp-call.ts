import { harnessDisplayName } from "../approval-center-utils";
import type { GuardActionEnvelope, GuardApprovalRequest } from "../guard-types";
import { explainComposioTool, type McpCallBody } from "./composio-calls";
import type { McpCallExplanation } from "./mcp-call-types";
import { classifyMcpEffect, MCP_EFFECT_COPY, type McpEffectKind } from "./mcp-effects";
import { rawInputText, recordOf, scalarFacts, toolInputRecord } from "./mcp-input";
import {
  isPlainNamePart,
  parseNamespacedMcpName,
  sentenceCase,
  serviceDisplayName,
  shortToolName,
  type McpServerRef,
} from "./mcp-services";

const UNKNOWN_SERVER = "a connected server";
// Core cuts every string in the recorded input at this length.
const CORE_STRING_LIMIT = 240;

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
  const input = toolInputRecord(raw);
  const connector = ref.server.length > 0 ? serviceDisplayName(ref.server) : UNKNOWN_SERVER;
  const shortTool = shortToolName(ref.server, ref.tool);
  const body =
    (ref.server.toLowerCase() === "composio" ? explainComposioTool(shortTool, { harness, input }) : null) ??
    explainGenericTool({ harness, connector, shortTool, input });

  return {
    ...body,
    connector,
    rawInput: rawInputText(raw),
    truncated: wasTruncated(item, input),
    toolId: ref.server.length > 0 ? `${ref.server} / ${ref.tool}` : ref.tool,
    whyAsked: `Guard has not reviewed ${ref.server.length > 0 ? `${connector}'s` : "this"} tool yet, and your policy asks before any unreviewed tool runs.`,
  };
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
  const tool =
    fromMcpTool?.tool ?? (isPlainNamePart(envelope.mcp_tool) ? envelope.mcp_tool : (fromToolName?.tool ?? null));
  if (tool === null) return null;
  const server =
    (isPlainNamePart(envelope.mcp_server) ? envelope.mcp_server : null) ?? fromMcpTool?.server ?? fromToolName?.server ?? "";
  return { server, tool };
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
  const { facts } = scalarFacts(input);
  const firstValue = facts[0]?.value ?? null;
  return {
    headline: `${harness} wants to ${effectPhrase(effect, connector)}`,
    title,
    summary: `${harness} is calling ${connector}'s “${title}” tool. ${MCP_EFFECT_COPY[effect].meaning}`,
    effect,
    effectBasis:
      effect === "unknown"
        ? "Guard cannot tell what this does from its name. Read the inputs below."
        : "Read from the tool's name. Guard has not checked what it does.",
    facts,
    steps: [],
    quotes: null,
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

function wasTruncated(item: GuardApprovalRequest, input: Record<string, unknown> | null): boolean {
  if ((item.action_explanation?.redaction.truncated_fields.length ?? 0) > 0) return true;
  return input !== null && JSON.stringify(input).length >= CORE_STRING_LIMIT && containsLongString(input);
}

function containsLongString(value: unknown): boolean {
  if (typeof value === "string") return value.length >= CORE_STRING_LIMIT;
  if (Array.isArray(value)) return value.some(containsLongString);
  const record = recordOf(value);
  return record !== null && Object.values(record).some(containsLongString);
}
