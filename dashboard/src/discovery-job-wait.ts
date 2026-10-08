import { fetchLocalCliApi } from "./guard-api";
import { isRecord } from "./local-cli-fields";

export async function waitForDiscoveryJob(cliId: string, initialJob: unknown, signal: AbortSignal, readJson: (response: Response) => Promise<unknown>): Promise<void> {
  const normalize = (body: unknown): Record<string, unknown> => {
    if (!isRecord(body) || typeof body.job_id !== "string" || !/^[a-f0-9]{32}$/.test(body.job_id)
      || body.cli_id !== cliId || !["running", "cancelling", "complete", "cancelled", "failed"].includes(String(body.state))) {
      throw new Error("Invalid discovery progress");
    }
    return body;
  };
  const request = async (payload: Record<string, unknown>) => {
    const body = await readJson(await fetchLocalCliApi("/v1/local-clis/refresh-job", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    }));
    const next = normalize(body);
    if (payload.job_id !== next.job_id) throw new Error("Discovery identity changed");
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
        let message: string;
        switch (job.error) {
          case "mcp_refresh_unavailable":
            message = "Guard cannot list this connection directly. Refresh it in its host app."; break;
          case "mcp_launch_failed":
            message = "Guard could not launch this MCP server. Check its configured executable and dependencies in the host app. Known tools and choices were kept."; break;
          case "mcp_transport_failed":
            message = "Guard could not communicate with this MCP server. Check its executable, dependencies, and server logs in the host app. Known tools and choices were kept."; break;
          case "mcp_initialize_failed":
            message = "The MCP server did not complete initialization. Check that it starts in the host app and uses stdio MCP. Known tools and choices were kept."; break;
          case "mcp_protocol_unsupported":
            message = "This server uses an MCP protocol version Guard does not support. Check the server and Guard versions. Known tools and choices were kept."; break;
          case "mcp_capability_rejected":
            message = "The MCP server rejected Guard's discovery capabilities. Check the server's client requirements and Guard version. Known tools and choices were kept."; break;
          case "catalog_revision_conflict":
            message = "A newer discovery finished first. Reload the inventory."; break;
          case "configured_host_scan_failed":
            message = "Guard could not read the host's configured connections. Check the host app and retry."; break;
          case "observed_provider_scan_failed":
            message = "Guard could not merge observed provider tools. Known tools and choices were kept; retry discovery."; break;
          case "catalog_limit_reached":
            message = "This connector has more tools than Guard can catalog safely. Existing choices were kept."; break;
          default:
            console.warn("Unknown discovery error code:", job.error);
            message = "Discovery did not finish. Known tools and choices were kept. Try again shortly.";
        }
        throw new Error(message);
      }
      await new Promise<void>((resolve) => {
        const done = () => { window.clearTimeout(timer); signal.removeEventListener("abort", done); resolve(); };
        const timer = window.setTimeout(done, 500);
        signal.addEventListener("abort", done, { once: true });
      });
      if (!signal.aborted) job = await request({ job_id: job.job_id });
    }
    throw new Error("Discovery took too long. Known tools and choices were kept.");
  } finally {
    if (!finished) await request({ job_id: job.job_id, cancel: true });
  }
}
