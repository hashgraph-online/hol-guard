import { DiscoveryFailure } from "./discovery-failure";
import { fetchLocalCliApi } from "./guard-api";
import { isRecord } from "./local-cli-fields";

/** The guidance for one failed discovery stage. Every entry names a next action. */
function stageFailure(code: unknown): DiscoveryFailure {
  switch (code) {
    case "mcp_refresh_unavailable":
      return new DiscoveryFailure("mcp_refresh_unavailable", "Guard cannot list this connection directly. Refresh it in its host app.");
    case "mcp_launch_failed":
      return new DiscoveryFailure("mcp_launch_failed", "Guard could not launch this MCP server. Check its configured executable and dependencies in the host app. Known tools and choices were kept.");
    case "mcp_transport_failed":
      return new DiscoveryFailure("mcp_transport_failed", "Guard could not communicate with this MCP server. Check its executable, dependencies, and server logs in the host app. Known tools and choices were kept.");
    case "mcp_initialize_failed":
      return new DiscoveryFailure("mcp_initialize_failed", "The MCP server did not complete initialization. Check that it starts in the host app and uses stdio MCP. Known tools and choices were kept.");
    case "mcp_protocol_unsupported":
      return new DiscoveryFailure("mcp_protocol_unsupported", "This server uses an MCP protocol version Guard does not support. Check the server and Guard versions. Known tools and choices were kept.");
    case "mcp_capability_rejected":
      return new DiscoveryFailure("mcp_capability_rejected", "The MCP server rejected Guard's discovery capabilities. Check the server's client requirements and Guard version. Known tools and choices were kept.");
    case "catalog_revision_conflict":
      return new DiscoveryFailure("catalog_revision_conflict", "A newer discovery finished first. Reload the inventory.");
    case "configured_host_scan_failed":
      return new DiscoveryFailure("configured_host_scan_failed", "Guard could not read this device's configured connections. Check that your agent apps' MCP settings are valid, then choose Check for connectors again. Known connections were kept.");
    case "configured_host_persist_failed":
      return new DiscoveryFailure("configured_host_persist_failed", "Guard read this device's connections but could not save them. Choose Check for connectors again; if that keeps failing, restart Guard. Known connections were kept.");
    case "codex_host_changed":
      return new DiscoveryFailure("codex_host_changed", "The Codex app restarted while Guard was reading it. Choose Check for connectors again. Known connections were kept.");
    case "codex_host_untrusted":
      return new DiscoveryFailure("codex_host_untrusted", "Guard will not read this Codex app inventory because the app's control socket is not the one Guard trusts. Reopen the Codex app, then check again. Known connections were kept.");
    case "codex_host_invalid":
      return new DiscoveryFailure("codex_host_invalid", "Guard could not make sense of the Codex app's inventory. Update or reopen the Codex app, then choose Check for connectors again. Known connections were kept.");
    case "codex_host_limit":
      return new DiscoveryFailure("codex_host_limit", "The Codex app reported more connections than Guard can read safely. Remove connections you do not use in the Codex app, then check again. Known connections were kept.");
    case "codex_host_timeout":
      return new DiscoveryFailure("codex_host_timeout", "The Codex app did not answer in time. Choose Check for connectors again; if that keeps failing, reopen the Codex app. Known connections were kept.");
    case "codex_host_unavailable":
      return new DiscoveryFailure("codex_host_unavailable", "Guard could not reach the Codex app. Open or reopen the Codex app, then choose Check for connectors again. Known connections were kept.");
    case "observed_provider_scan_failed":
      return new DiscoveryFailure("observed_provider_scan_failed", "Guard could not merge observed provider tools. Known tools and choices were kept; choose Check for connectors again.");
    case "catalog_limit_reached":
      return new DiscoveryFailure("catalog_limit_reached", "This connector has more tools than Guard can catalog safely. Existing choices were kept; remove tools you do not use in the host app, then check again.");
    case "discovery_failed":
      return new DiscoveryFailure("discovery_failed", "The connector scan stopped on an unexpected error. Known tools and choices were kept. Choose Check for connectors again; if that keeps failing, restart Guard. Guard recorded the reason in its log for support.");
    default:
      console.warn("Unknown discovery error code:", code);
      return new DiscoveryFailure("discovery_failed", "Discovery did not finish. Known tools and choices were kept. Try again shortly.");
  }
}

export async function waitForDiscoveryJob(cliId: string, initialJob: unknown, signal: AbortSignal, readJson: (response: Response) => Promise<unknown>): Promise<void> {
  const normalize = (body: unknown): Record<string, unknown> => {
    if (!isRecord(body) || typeof body.job_id !== "string" || !/^[a-f0-9]{32}$/.test(body.job_id)
      || body.cli_id !== cliId || !["running", "cancelling", "complete", "cancelled", "failed"].includes(String(body.state))) {
      throw new DiscoveryFailure("discovery_progress_invalid", "Guard could not read this discovery's progress. Reload this page, then try again.");
    }
    return body;
  };
  const request = async (payload: Record<string, unknown>) => {
    const body = await readJson(await fetchLocalCliApi("/v1/local-clis/refresh-job", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    }));
    const next = normalize(body);
    if (payload.job_id !== next.job_id) {
      throw new DiscoveryFailure("discovery_identity_changed", "A different discovery replaced this one. Known tools and choices were kept; try again.");
    }
    return next;
  };
  let job = normalize(initialJob);
  let finished = false;
  try {
    for (let poll = 0; poll < 120; poll += 1) {
      if (signal.aborted) return;
      if (job.state === "complete" || job.state === "cancelled") { finished = true; return; }
      if (job.state === "failed") {
        finished = true;
        throw stageFailure(job.error);
      }
      await new Promise<void>((resolve) => {
        const done = () => { window.clearTimeout(timer); signal.removeEventListener("abort", done); resolve(); };
        const timer = window.setTimeout(done, 500);
        signal.addEventListener("abort", done, { once: true });
      });
      if (!signal.aborted) job = await request({ job_id: job.job_id });
    }
    throw new DiscoveryFailure("discovery_timeout", "Discovery took too long. Known tools and choices were kept. Try again shortly.");
  } finally {
    // Cancelling is cleanup. A daemon that already lost this job answers the
    // cancel with its own failure, and throwing it here would replace the
    // reason the scan failed with one about cleanup, sending the reader to
    // the wrong fix.
    if (!finished) {
      try {
        await request({ job_id: job.job_id, cancel: true });
      } catch {
        // The polling failure above is the one worth showing.
      }
    }
  }
}
