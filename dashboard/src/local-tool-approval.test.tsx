import { renderToStaticMarkup } from "react-dom/server";
import type {
  GuardApprovalRequest,
  GuardLocalToolGrantDuration,
  GuardLocalToolGrantTarget,
} from "./guard-types";
import { LocalToolApprovalControls } from "./local-tool-approval-controls";
import {
  buildLocalToolResolutionFields,
  defaultLocalToolDuration,
  defaultLocalToolTarget,
  localToolAllowButtonLabel,
  localToolApprovalOptions,
  localToolExpiryLabel,
  localToolReadOnlyReasonLabel,
  localToolSummary,
  validLocalToolSelection,
} from "./local-tool-approval";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const request = {
  request_id: "local-tool-request",
  local_tool_approval: {
    eligible: true,
    tool_name: "xads.mjs",
    tool_identity_hash: "sha256-private-binding",
    capability: "request",
    read_only_reason: "HTTP method GET",
    trust_basis: "verified-files",
    indefinite_allowed: false,
    allowed_targets: ["capability", "version"],
    allowed_durations: ["once", "15m", "1h", "5h", "version"],
    hard_risk_exclusions: ["shell_chaining", "mutating_capability"],
  },
} as GuardApprovalRequest;

const options = localToolApprovalOptions(request);
assert(options !== null, "eligible backend metadata produces local tool approval options");
if (options === null) throw new Error("options unexpectedly unavailable");
assert(defaultLocalToolTarget(options) === "capability", "narrow capability is the default target");
assert(defaultLocalToolDuration(options) === "once", "reusable trust requires an explicit duration");
assert(localToolAllowButtonLabel("5h") === "Allow for 5 hours", "CTA mirrors bounded duration");
assert(localToolAllowButtonLabel("version") === "Trust this version", "version trust is explicit");
assert(localToolAllowButtonLabel("always") === "Always trust safe calls", "indefinite trust remains conditional");
assert(
  localToolSummary(options, "capability", "5h") === "Allow · xads.mjs · request · 5 hours",
  "summary names the tool, capability, and duration",
);
assert(localToolExpiryLabel("1h", new Date("2026-07-28T12:00:00Z")) !== null, "bounded grants show expiry");
assert(localToolExpiryLabel("version") === null, "version trust does not claim a time expiry");
assert(
  localToolReadOnlyReasonLabel("http_get") === "an HTTP GET request",
  "machine reason renders as clear user copy",
);

const fields = buildLocalToolResolutionFields(options, "version", "version");
assert(fields.local_tool_grant_target === "version", "resolution binds selected coverage");
assert(fields.local_tool_grant_duration === "version", "resolution binds selected duration");
assert(
  Object.keys(buildLocalToolResolutionFields(options, "capability", "once")).length === 0,
  "one-time approval uses the existing exact approval path",
);

const refreshedOptions = {
  ...options,
  allowed_targets: ["capability"] as GuardLocalToolGrantTarget[],
  allowed_durations: ["15m"] as GuardLocalToolGrantDuration[],
};
const refreshedSelection = validLocalToolSelection(refreshedOptions, "version", "version");
assert(refreshedSelection.target === "capability", "refreshed options replace stale coverage");
assert(refreshedSelection.duration === "15m", "refreshed options replace stale duration");

const malformed = {
  ...request,
  local_tool_approval: { ...request.local_tool_approval, tool_identity_hash: "" },
} as GuardApprovalRequest;
assert(localToolApprovalOptions(malformed) === null, "missing stable tool identity fails closed");
assert(
  localToolApprovalOptions({ ...request, local_tool_approval: null }) === null,
  "legacy requests omit trusted local tool controls",
);

const html = renderToStaticMarkup(
  <LocalToolApprovalControls
    options={options}
    target="capability"
    duration="version"
    onTargetChange={() => undefined}
    onDurationChange={() => undefined}
  />,
);
assert(html.includes("<fieldset"), "duration and coverage use native fieldsets");
assert(html.includes('type="radio"'), "choices use keyboard-operable native radios");
assert(html.includes("Until tool changes"), "version-bound duration is visible");
assert(html.includes("different IDs, filters, and timestamps"), "variable argument behavior is clear");
assert(html.includes("option names"), "changed option sets are excluded from reusable trust");
assert(html.includes("Writes, shell chaining"), "hard-risk boundary remains visible");
assert(html.includes("executable, script, or approved output processor changes"), "digest invalidation is clear");
assert(html.includes("min-h-11"), "controls preserve 44px touch targets");
assert(!html.includes("sha256-private-binding"), "stable tool fingerprint is never rendered");

const packageOptions = localToolApprovalOptions({
  ...request,
  local_tool_approval: {
    ...request.local_tool_approval,
    tool_name: "impeccable",
    capability: "scan",
    read_only_reason: "profile_impeccable_scan",
    trust_basis: "package-profile",
    indefinite_allowed: true,
    allowed_targets: ["capability"],
    allowed_durations: ["once", "5h", "always"],
  },
} as GuardApprovalRequest);
assert(packageOptions !== null, "package profile trust metadata is accepted");
if (packageOptions === null) throw new Error("package options unexpectedly unavailable");
const packageHtml = renderToStaticMarkup(
  <LocalToolApprovalControls
    options={packageOptions}
    target="capability"
    duration="always"
    onTargetChange={() => undefined}
    onDurationChange={() => undefined}
  />,
);
assert(packageHtml.includes("Always"), "indefinite profile trust is visible");
assert(packageHtml.includes("checks package safety"), "indefinite trust explains continuous package checks");
assert(packageHtml.includes("URLs, writes, unsafe paths"), "package profile exclusions stay visible");

console.log("local-tool-approval.test.tsx: all tests passed");
