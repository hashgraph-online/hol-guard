import { harnessDisplayName } from "../approval-center-utils";
import type { GuardApprovalRequest } from "../guard-types";
import { explainMcpCall } from "./explain-mcp-call";
import { composioToolTitle } from "./composio-calls";
import { hostAppTool } from "./host-app-tools";
import { mcpMarkName } from "./mcp-brand";
import {
  parseNamespacedMcpName,
  sentenceCase,
  serviceDisplayName,
  shortToolName,
  toolTitle,
  type McpServerRef,
} from "./mcp-services";

const TOOL_ID_PREFIX = "tool:";

/**
 * The tool a list row is about, for a row that arrives without its action
 * envelope. The list payload leaves the envelope out, but the daemon still
 * names the tool in `artifact_id` (`tool:mcp__server__tool`) and in the
 * launch target, so the name can be read from those.
 */
export function listedMcpRef(item: GuardApprovalRequest): McpServerRef | null {
  if (item.action_envelope_json != null) return null;
  const candidates = [item.artifact_id, item.launch_target, item.queue_preview, item.artifact_name];
  for (const candidate of candidates) {
    if (typeof candidate !== "string") continue;
    const name = candidate.startsWith(TOOL_ID_PREFIX) ? candidate.slice(TOOL_ID_PREFIX.length) : candidate;
    const ref = parseNamespacedMcpName(name);
    if (ref !== null) return ref;
  }
  return null;
}

/**
 * The app that asked, for a list row. A tool built into one agent app can only
 * come from that app, so its name wins over the hook's label.
 */
export function queueRequesterName(item: GuardApprovalRequest): string {
  const fromCall = explainMcpCall(item)?.requester;
  if (fromCall !== undefined) return fromCall;
  const ref = listedMcpRef(item);
  const host = ref !== null ? hostAppTool(ref.server, shortToolName(ref.server, ref.tool), { harness: item.harness }) : null;
  return host?.requester ?? harnessDisplayName(item.harness);
}

/** `Gmail · Send email`, for a list row that has only the tool's name. */
export function listedMcpPreview(item: GuardApprovalRequest): string | null {
  const ref = listedMcpRef(item);
  if (ref === null) return null;
  const short = shortToolName(ref.server, ref.tool);
  const host = hostAppTool(ref.server, short, { harness: item.harness });
  if (host !== null) return `${host.requester} · ${host.title}`;
  const service = serviceDisplayName(ref.server);
  const title = ref.server.toLowerCase() === "composio" ? (composioToolTitle(short) ?? sentenceCase(short)) : toolTitle(service, short);
  return `${service} · ${title}`;
}

/** The app whose mark a list row shows for an MCP call, or null when the row is not one. */
export function queueMcpMarkName(item: GuardApprovalRequest): string | null {
  const explanation = explainMcpCall(item);
  if (explanation !== null) return mcpMarkName(explanation);
  const ref = listedMcpRef(item);
  if (ref === null) return null;
  const host = hostAppTool(ref.server, shortToolName(ref.server, ref.tool), { harness: item.harness });
  return host?.requester ?? serviceDisplayName(ref.server);
}
