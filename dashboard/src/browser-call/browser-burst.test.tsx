import { renderToStaticMarkup } from "react-dom/server";
import type { GuardApprovalRequest, GuardBrowserCardV1 } from "../guard-types";
import { PrimaryActionCard } from "../review-states";
import { BROWSER_BURST_WINDOW_MS, BrowserBurstContext, coalesceBrowserBursts } from "./browser-burst";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const START = Date.parse("2026-11-26T12:00:00Z");

function card(headline: string): GuardBrowserCardV1 {
  return {
    headline,
    verb: "click",
    site: { origin: "https://shop.example.test", first_visit_in_task: false, left_granted_site: false },
    profile_line: "isolated",
    detail: { element_preview: null, input_kind: null, input_length: null, input_masked: false },
    risk_chips: [],
    provider_findings: [],
    choices: ["allow_once", "always_allow", "deny"],
    steps: [],
  };
}

function row(
  id: string,
  offsetMs: number,
  key: string | null,
  extra: Partial<GuardApprovalRequest> = {},
): GuardApprovalRequest {
  const tool = "mcp__example-pilot__page_click";
  return {
    request_id: id,
    harness: "codex",
    artifact_id: `tool:${tool}`,
    artifact_name: tool,
    artifact_type: "tool_call",
    artifact_hash: `sha256-${id}`,
    publisher: null,
    policy_action: "require-reapproval",
    recommended_scope: "artifact",
    changed_fields: ["runtime_tool_call"],
    source_scope: "project",
    config_path: "./mcp.json",
    launch_target: tool,
    transport: "stdio",
    review_command: `hol-guard approvals approve ${id}`,
    approval_url: `http://127.0.0.1:4781/approvals/${id}`,
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: new Date(START + offsetMs).toISOString(),
    resolved_at: null,
    browser_card: card(`Codex wants to click step ${id}`),
    action_envelope_json: {
      schema_version: 1,
      action_id: `act-${id}`,
      harness: "codex",
      event_name: "PreToolUse",
      action_type: "mcp_tool",
      workspace: "/workspace/project",
      workspace_hash: null,
      tool_name: tool,
      command: null,
      prompt_excerpt: null,
      prompt_text: null,
      target_paths: [],
      network_hosts: [],
      mcp_server: "example-pilot",
      mcp_tool: "page_click",
      package_manager: null,
      package_name: null,
      script_name: null,
      raw_payload_redacted: { hook_event_name: "PreToolUse", tool_name: tool, tool_input: { element: "Next" } },
    },
    ...(key === null ? {} : { browser_burst_key: key }),
    ...extra,
  } as GuardApprovalRequest;
}

const ids = (items: GuardApprovalRequest[]) => items.map((item) => item.request_id).join(",");

// One session on one site within the window: one card, its first step, a count and the steps.
{
  const queue = [row("c", 60_000, "k1"), row("other", 30_000, null), row("a", 0, "k1"), row("b", 30_000, "k1")];
  const { items, bursts } = coalesceBrowserBursts(queue);
  assert(ids(items) === "a,other", `T-BURST-1: burst folds into its first step where it first appears (${ids(items)})`);
  const burst = bursts.get("a");
  assert(burst?.count === 3, "T-BURST-2: the card counts every step");
  assert(burst?.steps.map((step) => step.requestId).join(",") === "a,b,c", "T-BURST-3: steps list oldest first");
  assert(bursts.get("b") === undefined, "T-BURST-4: only the first step carries the burst");
}

// A gap longer than the review window starts a new card.
{
  const late = BROWSER_BURST_WINDOW_MS + 1;
  const queue = [row("a", 0, "k1"), row("b", 1_000, "k1"), row("c", 1_000 + late, "k1"), row("d", 2_000 + late, "k1")];
  const { items, bursts } = coalesceBrowserBursts(queue);
  assert(ids(items) === "a,c", `T-BURST-5: each run is its own card (${ids(items)})`);
  assert(bursts.get("a")?.count === 2 && bursts.get("c")?.count === 2, "T-BURST-6: each run counts its own steps");
}

// Rows with no key, another key, a lone step, or a settled row stay on their own cards.
{
  const queue = [
    row("a", 0, "k1"),
    row("b", 1_000, "k2"),
    row("c", 2_000, null),
    row("d", 3_000, "k1", { status: "approved" }),
    row("e", 4_000, "k3", { browser_card: null }),
    row("f", 5_000, "k3"),
  ];
  const { items, bursts } = coalesceBrowserBursts(queue);
  assert(ids(items) === "a,b,c,d,e,f", `T-BURST-7: nothing coalesces without a shared pending key (${ids(items)})`);
  assert(bursts.size === 0, "T-BURST-8: no burst without two pending carded rows");
  assert(coalesceBrowserBursts(queue).items === queue, "T-BURST-9: an unchanged queue is kept as it is");
}

// When the first step is answered, the rows left form the next card.
{
  const queue = [row("a", 0, "k1", { status: "approved" }), row("b", 1_000, "k1"), row("c", 2_000, "k1")];
  const { items, bursts } = coalesceBrowserBursts(queue);
  assert(ids(items) === "a,b", `T-BURST-10: the uncovered rows stay pending as one card (${ids(items)})`);
  assert(bursts.get("b")?.count === 2, "T-BURST-11: the next card counts what is left");
}

// The browser card shows the step list for its burst, and nothing for a lone step.
{
  const queue = [row("a", 0, "k1"), row("b", 1_000, "k1")];
  const { items, bursts } = coalesceBrowserBursts(queue);
  const withBurst = renderToStaticMarkup(
    <BrowserBurstContext.Provider value={bursts}>
      <PrimaryActionCard item={items[0]} />
    </BrowserBurstContext.Provider>,
  );
  assert(withBurst.includes('data-browser-burst="2"'), "T-BURST-12: the card marks its burst");
  assert(withBurst.includes("2 steps on this site"), "T-BURST-13: the card names the count");
  assert(withBurst.includes("Codex wants to click step b"), "T-BURST-14: the card lists every step");
  const alone = renderToStaticMarkup(<PrimaryActionCard item={row("z", 0, "k9")} />);
  assert(!alone.includes("data-browser-burst"), "T-BURST-16: a lone step has no step list");
}
