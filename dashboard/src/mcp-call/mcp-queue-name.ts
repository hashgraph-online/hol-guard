import type { GuardApprovalRequest } from "../guard-types";
import { composioToolTitle } from "./composio-calls";
import {
  parseNamespacedMcpName,
  sentenceCase,
  serviceDisplayName,
  shortToolName,
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
    const ref = unwrapConnector(parseNamespacedMcpName(name));
    if (ref !== null) return ref;
  }
  return null;
}

/** `Gmail · Send email`, for a list row that has only the tool's name. */
export function listedMcpPreview(item: GuardApprovalRequest): string | null {
  const ref = listedMcpRef(item);
  if (ref === null) return null;
  const short = shortToolName(ref.server, ref.tool);
  const title = ref.server.toLowerCase() === "composio" ? (composioToolTitle(short) ?? sentenceCase(short)) : sentenceCase(short);
  return `${serviceDisplayName(ref.server)} · ${title}`;
}

/** Codex reaches a connector through `codex_apps`. The connector is the service the user knows. */
function unwrapConnector(ref: McpServerRef | null): McpServerRef | null {
  if (ref === null || ref.server !== "codex_apps") return ref;
  const separator = ref.tool.indexOf("__");
  if (separator <= 0 || separator + 2 >= ref.tool.length) return ref;
  return { server: ref.tool.slice(0, separator), tool: ref.tool.slice(separator + 2) };
}
