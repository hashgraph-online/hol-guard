import { renderToStaticMarkup } from "react-dom/server";
import { GuardHarnessActionError } from "./guard-api";
import { ConnectFlowCard } from "./supply-chain-firewall-views";
import {
  isSupplyChainAuditConnectError,
  packageAuditNeedsCloudConnect,
  resolveSupplyChainAuditConnectGate,
  supplyChainAuditConnectUserMessage,
  supplyChainAuditUserMessage,
} from "./supply-chain-audit-connect";
import type { PackageFirewallStatusResponse } from "./guard-types";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const connectRequiredStatus: PackageFirewallStatusResponse = {
  operation: "status",
  status: "completed",
  supported_managers: ["npm"],
  detected_managers: ["npm"],
  last_audit_proof_at: null,
  protection: null,
  package_shims: [],
  entitlement: {
    allowed: false,
    reason: "guard_cloud_connect_required",
    tier: "unknown",
    upgrade_cta: "Connect HOL Guard Cloud to check package firewall access and run package firewall actions.",
    upgrade_url: null,
  },
  actions: {
    install: "connect_required",
    repair: "disabled",
    test: "connect_required",
    audit: "connect_required",
    sync: "connect_required",
    remove: "disabled",
  },
  cli_fallback: {
    connect: "hol-guard connect",
  },
  connect_flow: {
    state: "idle",
    title: "Connect HOL Guard Cloud to enable package firewall",
    detail: "Connect HOL Guard Cloud here so the daemon can verify package-firewall access.",
    action_label: "Connect HOL Guard Cloud",
    connect_url: "https://hol.org/guard/connect",
    authorize_url: null,
    browser_opened: null,
    request_id: null,
    poll_after_ms: null,
  },
};

assert(packageAuditNeedsCloudConnect(connectRequiredStatus), "audit action should require cloud connect");
const gate = resolveSupplyChainAuditConnectGate(connectRequiredStatus, { resumeAfterConnect: true });
assert(gate !== null, "audit connect gate should resolve for connect-required status");
assert(
  gate?.headline.includes("Sign in"),
  "audit connect gate should use human-readable sign-in copy",
);
assert(
  !gate?.headline.includes("guard_cloud_connect_required"),
  "audit connect gate should not surface raw daemon error codes",
);

const connectError = new GuardHarnessActionError(403, {
  error: "guard_cloud_connect_required",
  message: "Connect HOL Guard Cloud on this machine before running package firewall actions.",
  operation: "audit",
});
assert(isSupplyChainAuditConnectError(connectError), "structured audit connect errors should be detectable");
assert(
  supplyChainAuditConnectUserMessage(connectError)?.includes("Sign in"),
  "audit connect user message should guide sign-in before retry",
);

const workspaceError = new GuardHarnessActionError(400, {
  error: "workspace_dir_required",
  message:
    "Guard needs a project folder with package manifests before it can run the workspace audit.",
  operation: "audit",
});
assert(
  supplyChainAuditUserMessage(workspaceError)?.includes("project folder"),
  "workspace audit errors should surface actionable copy instead of raw codes",
);
assert(
  !isSupplyChainAuditConnectError(workspaceError),
  "workspace_dir_required should not be treated as a cloud connect gate",
);

const auditConnectMarkup = renderToStaticMarkup(
  <ConnectFlowCard
    compact
    connectError={null}
    connectStarting={false}
    connectFlow={connectRequiredStatus.connect_flow!}
    detail={gate!.detail}
    headline={gate!.headline}
    mode="connect"
    onStartConnect={() => undefined}
    purpose="audit"
  />,
);

assert(
  auditConnectMarkup.includes("Run workspace audit"),
  "audit connect card should show audit-specific final step",
);
assert(
  auditConnectMarkup.includes("Connect HOL Guard Cloud"),
  "audit connect card should keep the primary connect action",
);
assert(
  !auditConnectMarkup.includes("guard_cloud_connect_required"),
  "audit connect card markup should not expose raw error codes",
);

console.log("supply-chain-audit-connect.test.ts: all assertions passed");
