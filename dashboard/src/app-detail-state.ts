import {
  fetchRequest,
  fetchDiff,
  fetchLatestReceipt,
  fetchPolicy,
  fetchMcpPolicyRequest,
} from "./guard-api";
import type { DetailState } from "./app-state-types";

export async function loadDetail(requestId: string): Promise<Exclude<DetailState, { kind: "idle" | "loading" }>> {
  try {
    const item = await fetchRequest(requestId);
    const [diff, receipt, policy] = await Promise.all([
      shouldFetchArtifactDiff(item.artifact_type)
        ? fetchDiff(item.artifact_id, item.harness)
        : Promise.resolve(null),
      fetchLatestReceipt(item.artifact_id, item.harness),
      fetchPolicy(item.harness)
    ]);
    return { kind: "ready", item, diff, receipt, policy };
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (message.includes("404")) {
      // VPC045-047/056: a 404 on /v1/requests/<id> may mean this is a staged
      // MCP policy creation request rather than a regular approval. Probe the
      // MCP endpoint; if it exists, render the MCP panel. Otherwise fall back
      // to the stale state so the inbox shows an honest "gone" message.
      try {
        const mcpRequest = await fetchMcpPolicyRequest(requestId);
        if (mcpRequest !== null) {
          return { kind: "mcp-policy", requestId };
        }
      } catch {
        // Swallow the MCP probe error; the original 404 is the source of truth here.
      }
      return { kind: "stale" };
    }
    return {
      kind: "error",
      message: message.length > 0 ? message : "Unable to load the approval request."
    };
  }
}

export async function refreshStaleScopeContractSelection<T>({
  requestId,
  refreshQueue,
  loadSelectedDetail,
  applySelectedDetail,
}: {
  requestId: string | null;
  refreshQueue: () => Promise<void>;
  loadSelectedDetail: (requestId: string) => Promise<T>;
  applySelectedDetail: (detail: T) => void;
}): Promise<void> {
  await refreshQueue();
  if (requestId === null) return;
  applySelectedDetail(await loadSelectedDetail(requestId));
}

export function shouldFetchArtifactDiff(artifactType: string): boolean {
  return new Set(["mcp_server", "skill", "skill_file"]).has(artifactType);
}
