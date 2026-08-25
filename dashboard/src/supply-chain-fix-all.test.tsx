import { renderToStaticMarkup } from "react-dom/server";
import { SupplyChainRecovery } from "./supply-chain-recovery";
import {
  IDLE_SUPPLY_CHAIN_FIX_ALL_STATE,
  supplyChainFixAllButtonLabel,
  supplyChainFixAllIsPending,
  supplyChainFixAllRequiresConnection,
} from "./supply-chain-fix-all";
import type { PackageFirewallStatusResponse } from "./guard-types";
import type { SupplyChainIssue } from "./supply-chain-issues";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const issues: SupplyChainIssue[] = [
  {
    id: "unprotected_tools",
    title: "Package installs are not protected yet",
    detail: "Protect npm and bun before installs run.",
    tone: "attention",
    actionLabel: "Protect package tools",
    action: { kind: "firewall_unprotected" },
  },
  {
    id: "stale_intel",
    title: "Safety check data looks old",
    detail: "Refresh package warnings.",
    tone: "attention",
    actionLabel: "Run workspace audit",
    action: { kind: "firewall_audit" },
  },
];

const markup = renderToStaticMarkup(
  <SupplyChainRecovery
    issues={issues}
    state={IDLE_SUPPLY_CHAIN_FIX_ALL_STATE}
    onFixAll={() => undefined}
  />,
);

assert(markup.includes("Restore supply-chain protection"), "recovery heading is visible");
assert(markup.includes("Fix all"), "one aggregate repair action is visible");
assert(markup.includes("Fix 2 open issues"), "summary reports the bounded repair scope");
assert(markup.includes("View issue details"), "issues remain available through progressive disclosure");
assert(!markup.includes("Package installs are not protected yet"), "details start collapsed");
assert(markup.includes('aria-live="polite"'), "the result live region exists before repair starts");
assert(supplyChainFixAllButtonLabel("incomplete") === "Retry remaining", "partial repair remains actionable");
assert(
  supplyChainFixAllButtonLabel("incomplete", "connect", 0) === "Connect Guard Cloud",
  "cloud remaining work uses a connect action instead of retry",
);
assert(supplyChainFixAllIsPending("approval"), "approval phase prevents duplicate submissions");

const cloudRemainingMarkup = renderToStaticMarkup(
  <SupplyChainRecovery
    issues={issues}
    state={{
      phase: "incomplete",
      message: "Package protection is on. Connect Guard Cloud to refresh safety intelligence.",
      completedSteps: ["package_shims", "runtime_activation"],
      failedSteps: [],
      remainingAction: "connect",
      remainingSteps: ["Connect Guard Cloud to refresh safety intelligence."],
    }}
    onFixAll={() => undefined}
  />,
);
assert(cloudRemainingMarkup.includes("Connect Guard Cloud"), "connect remaining work is the primary action");
assert(!cloudRemainingMarkup.includes("Retry remaining"), "connect remaining work does not look like a failed retry loop");

const duplicateFailureMarkup = renderToStaticMarkup(
  <SupplyChainRecovery
    issues={issues}
    state={{
      phase: "incomplete",
      message: "Two steps need another attempt.",
      completedSteps: [],
      failedSteps: ["Retry this step.", "Retry this step."],
    }}
    onFixAll={() => undefined}
  />,
);
assert(
  duplicateFailureMarkup.match(/Retry this step\./g)?.length === 2,
  "duplicate failure messages render as distinct rows",
);

function firewallStatus(
  reason: string,
  options: { allowed?: boolean; installed?: boolean } = {},
): PackageFirewallStatusResponse {
  return {
    operation: "status",
    status: "ready",
    supported_managers: ["npm"],
    detected_managers: ["npm"],
    last_audit_proof_at: null,
    protection: null,
    package_shims: [
      {
        active: options.installed === true,
        activation_state: options.installed === true ? "repair_required" : "uninstalled",
        detected: true,
        installed: options.installed === true,
        integrity: "ok",
        last_intercept_proof_at: null,
        manager: "npm",
        path_broken: false,
        path_index: null,
        path_summary: null,
        real_binary_found: true,
        real_binary_path: null,
        real_binary_path_index: null,
        shim_path: null,
        tested: false,
      },
    ],
    entitlement: {
      allowed: options.allowed === true,
      reason,
      tier: "local",
      upgrade_cta: null,
      upgrade_url: null,
    },
    actions: {},
    cli_fallback: null,
    connect_flow: null,
  };
}

assert(
  !supplyChainFixAllRequiresConnection(firewallStatus("paid_guard_cloud_required")),
  "paid access does not enter a dead-end connect flow",
);
assert(
  !supplyChainFixAllRequiresConnection(
    firewallStatus("guard_cloud_connect_required", { installed: true }),
  ),
  "installed shims remain locally repairable before initial cloud connect",
);
assert(
  supplyChainFixAllRequiresConnection(firewallStatus("guard_cloud_connect_required")),
  "new shim installation requests cloud connect",
);
assert(
  supplyChainFixAllRequiresConnection(
    firewallStatus("guard_cloud_reconnect_required", { installed: true }),
  ),
  "expired authorization requires reconnect",
);
assert(
  !supplyChainFixAllRequiresConnection(
    firewallStatus("paid_entitlement_active", { allowed: true }),
  ),
  "active access runs repair immediately",
);

console.log("supply-chain-fix-all.test.tsx: all assertions passed");
