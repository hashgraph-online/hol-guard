import { renderToStaticMarkup } from "react-dom/server";
import { deriveFrontendAuditResults } from "./audit-workspace";
import { GUARD_ORIGIN_COPY, GUARD_ORIGIN_SIGNAL, isGuardOriginBlock } from "./browser-guard-origin";
import type { GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import { BlockReasonBreakdown } from "./history-charts";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

// The shape `mcp_relay_receipt_event.rs` writes: a fixed capabilities summary, and the decision's
// signals after the runtime marker and decision source in `changed_capabilities`.
const GUARD_ORIGIN_SIGNALS = ["browser MCP navigation", GUARD_ORIGIN_SIGNAL];

function receipt(decision: "block" | "allow", signals: string[]): GuardReceipt {
  return {
    receipt_id: `receipt-${decision}-${signals.length}`,
    harness: "claude-code",
    artifact_id: "mcp:playwright:browser_navigate",
    artifact_name: "playwright:browser_navigate",
    artifact_hash: "hash",
    source_scope: null,
    policy_decision: decision,
    timestamp: "2026-11-26T00:00:00Z",
    capabilities_summary: "mcp tool call \u2022 playwright:browser_navigate",
    changed_capabilities: ["runtime_tool_call", "policy-block", ...signals],
    provenance_summary: "",
    user_override: null,
  };
}

const snapshot = {} as GuardRuntimeSnapshot;

assert(isGuardOriginBlock(receipt("block", GUARD_ORIGIN_SIGNALS)), "the native R-SELF signal is recognized");
assert(!isGuardOriginBlock(receipt("block", ["browser MCP navigation"])), "other blocks are not");
assert(!isGuardOriginBlock(receipt("allow", GUARD_ORIGIN_SIGNALS)), "only a block is an R-SELF block");

const [selfBlock] = deriveFrontendAuditResults([receipt("block", GUARD_ORIGIN_SIGNALS)], snapshot);
assert(selfBlock?.title === GUARD_ORIGIN_COPY.title, "an R-SELF block gets its own title");
assert(selfBlock?.remediation === GUARD_ORIGIN_COPY.remediation, "an R-SELF block offers no policy change");
assert(selfBlock?.remediation.includes("No approval, grant or setting") === true, "the copy says nothing overrides it");

const [ordinary] = deriveFrontendAuditResults([receipt("block", ["tool name implies shell or command execution"])], snapshot);
assert(ordinary?.title === "Blocked: playwright:browser_navigate", "ordinary blocks keep their title");

// Neither the copy nor the rendered breakdown may point anyone at an address for the approval center.
for (const text of Object.values(GUARD_ORIGIN_COPY)) {
  for (const leak of ["://", "localhost", "127.0.0.1", "[::1]"]) {
    assert(!text.includes(leak), `copy names an address: ${text}`);
  }
}
const markup = renderToStaticMarkup(<BlockReasonBreakdown receipts={[receipt("block", GUARD_ORIGIN_SIGNALS)]} />);
assert(markup.includes("Guard&#x27;s approval center"), `breakdown labels R-SELF blocks: ${markup}`);

console.log("browser-guard-origin tests passed");
