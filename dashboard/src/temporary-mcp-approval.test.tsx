import { renderToStaticMarkup } from "react-dom/server";
import type { GuardApprovalRequest } from "./guard-types";
import { TemporaryMcpApprovalControls } from "./temporary-mcp-approval-controls";
import {
  buildTemporaryMcpResolutionFields,
  defaultTemporaryMcpDuration,
  defaultTemporaryMcpTarget,
  temporaryMcpAllowButtonLabel,
  temporaryMcpApprovalOptions,
  temporaryMcpExpiryLabel,
  temporaryMcpSummary,
} from "./temporary-mcp-approval";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const request = {
  request_id: "mcp-request",
  temporary_mcp_approval: {
    eligible: true,
    server_name: "chrome-devtools",
    server_identity_hash: "sha256-secret-binding",
    category: "browser_inspection",
    target_label: "hol.org",
    allowed_targets: ["exact", "category", "server"],
    allowed_durations: ["once", "15m", "1h", "5h"],
    hard_risk_exclusions: ["browser_privileged", "browser_transfer"],
  },
} as GuardApprovalRequest;

const options = temporaryMcpApprovalOptions(request);
assert(options !== null, "eligible backend metadata produces temporary approval options");
if (options === null) throw new Error("options unexpectedly unavailable");
assert(defaultTemporaryMcpTarget(options) === "category", "capability is the bounded default target");
assert(defaultTemporaryMcpDuration(options) === "1h", "one hour is the bounded default duration");
assert(temporaryMcpAllowButtonLabel("5h") === "Allow for 5 hours", "CTA mirrors selected duration");
assert(
  temporaryMcpSummary(options, "category", "5h") === "Allow · chrome-devtools · Inspect · hol.org · 5 hours",
  "summary names server, capability, target, and duration",
);
assert(
  temporaryMcpExpiryLabel("1h", new Date("2026-07-21T12:00:00Z")) !== null,
  "bounded duration exposes an absolute expiry preview",
);
assert(temporaryMcpExpiryLabel("once") === null, "one-time approval has no expiry preview");

const fields = buildTemporaryMcpResolutionFields(options, "server", "5h");
assert(fields.mcp_grant_target === "server", "resolution binds the selected MCP target");
assert(fields.mcp_grant_duration === "5h", "resolution binds the selected duration");
assert(
  Object.keys(buildTemporaryMcpResolutionFields(options, "category", "once")).length === 0,
  "one-time approval uses the existing exact one-shot path",
);

const malformed = {
  ...request,
  temporary_mcp_approval: { ...request.temporary_mcp_approval, server_identity_hash: "" },
} as GuardApprovalRequest;
assert(temporaryMcpApprovalOptions(malformed) === null, "missing stable server identity fails closed");
assert(
  temporaryMcpApprovalOptions({ ...request, temporary_mcp_approval: null }) === null,
  "legacy requests omit temporary controls",
);

const html = renderToStaticMarkup(
  <TemporaryMcpApprovalControls
    options={options}
    target="category"
    duration="5h"
    onTargetChange={() => undefined}
    onDurationChange={() => undefined}
  />,
);
assert(html.includes("<fieldset"), "duration and coverage use native fieldset semantics");
assert(html.includes('type="radio"'), "duration and coverage use keyboard-operable native radios");
assert(html.includes("How long should this choice last?"), "duration question is explicit");
assert(html.includes("What should it cover?"), "coverage question is explicit");
assert(html.includes("Privileged browser access"), "hard-risk boundary stays visible");
assert(html.includes("min-h-11"), "controls preserve 44px touch targets");
assert(!html.includes("sha256-secret-binding"), "stable server fingerprint is never rendered");

console.log("temporary-mcp-approval.test.tsx: all tests passed");
