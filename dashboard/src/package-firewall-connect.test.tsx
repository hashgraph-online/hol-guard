import { renderToStaticMarkup } from "react-dom/server";
import { ConnectFlowCard, EntitlementNotice } from "./supply-chain-firewall-views";
import type { PackageFirewallStatusResponse } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

Object.assign(globalThis, {
  window: {
    location: {
      hash: "",
      origin: "http://127.0.0.1:5474",
      pathname: "/supply-chain",
      search: "",
    },
    localStorage: {
      getItem: () => null,
      removeItem: () => undefined,
      setItem: () => undefined,
    },
    sessionStorage: {
      getItem: () => null,
      removeItem: () => undefined,
      setItem: () => undefined,
    },
  },
});

const runningMarkup = renderToStaticMarkup(
  <ConnectFlowCard
    compact
    connectError={null}
    connectStarting={false}
    connectFlow={{
      state: "running",
      title: "Finish Guard Cloud sign-in in your browser",
      detail: "HOL Guard opened the secure sign-in flow in your browser.",
      action_label: "Repair Guard Cloud access",
      connect_url: "https://hol.org/guard/connect",
      authorize_url: "https://hol.org/mock-authorize",
      browser_opened: true,
      request_id: "guard-connect-1",
      poll_after_ms: 1500,
    }}
    mode="repair"
    onStartConnect={() => undefined}
  />,
);

assert(
  runningMarkup.includes("Waiting for browser approval"),
  "PF1: running connect card should show waiting button label",
);
assert(
  runningMarkup.includes("Open sign-in page"),
  "PF1: running connect card should keep manual sign-in fallback visible",
);
assert(
  runningMarkup.includes("Waiting for approval"),
  "PF1: running reconnect card should show waiting state badge",
);
assert(
  !runningMarkup.includes("Security"),
  "PF1: compact connect state should not render the nested security card",
);

const startingMarkup = renderToStaticMarkup(
  <ConnectFlowCard
    compact
    connectError={null}
    connectStarting={false}
    connectFlow={{
      state: "starting",
      title: "Finish Guard Cloud sign-in in your browser",
      detail: "HOL Guard is opening the secure sign-in flow in your browser.",
      action_label: "Repair Guard Cloud access",
      connect_url: "https://hol.org/guard/connect",
      authorize_url: null,
      browser_opened: false,
      request_id: "guard-connect-2",
      poll_after_ms: 1500,
    }}
    mode="repair"
    onStartConnect={() => undefined}
  />,
);

assert(
  !startingMarkup.includes("Open sign-in page"),
  "PF2: starting connect card should not link to generic connect before authorize URL exists",
);

const connectRequiredStatus: PackageFirewallStatusResponse = {
  operation: "status",
  status: "completed",
  supported_managers: ["npm", "pnpm"],
  detected_managers: ["pnpm"],
  last_audit_proof_at: null,
  protection: null,
  package_shims: [
    {
      active: false,
      activation_state: "repair_required",
      detected: true,
      installed: true,
      integrity: "ok",
      last_intercept_proof_at: null,
      manager: "pnpm",
      path_broken: false,
      path_index: null,
      path_summary: "/guard-home/package-shims/bin/pnpm precedes /opt/homebrew/bin/pnpm",
      real_binary_found: true,
      real_binary_path: "/opt/homebrew/bin/pnpm",
      real_binary_path_index: 2,
      shim_path: "/guard-home/package-shims/bin/pnpm",
      tested: false,
    },
  ],
  entitlement: {
    allowed: false,
    reason: "guard_cloud_connect_required",
    tier: "unknown",
    upgrade_cta: "Connect HOL Guard Cloud to check package firewall access and run package firewall actions.",
    upgrade_url: null,
  },
  actions: {
    install: "connect_required",
    repair: "connect_required",
    test: "connect_required",
    audit: "connect_required",
    sync: "connect_required",
    remove: "connect_required",
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

const freeViewMarkup = renderToStaticMarkup(
  <EntitlementNotice
    connectError={null}
    connectStarting={false}
    data={connectRequiredStatus}
    onStartConnect={() => undefined}
  />,
);

assert(
  freeViewMarkup.includes("Connect HOL Guard Cloud to enable package firewall"),
  "PF2: connect-required free view should render connect guidance instead of upgrade copy",
);
assert(
  !freeViewMarkup.includes("Upgrade to enable active protection"),
  "PF2: connect-required free view should not render upgrade upsell",
);
assert(
  freeViewMarkup.includes("Existing shims on this machine can still be fixed or removed locally."),
  "PF2: connect-required view should explain that local recovery still works",
);
assert(
  !freeViewMarkup.includes("AVAILABLE NOW"),
  "PF2: staged local recovery view should stay compact instead of nesting extra helper cards",
);
assert(
  freeViewMarkup.includes("What still works locally"),
  "PF2: local recovery hint should live in progressive disclosure",
);
assert(
  freeViewMarkup.includes("Connect progress"),
  "PF2: compact connect view should render the progressive step rail",
);
assert(
  !freeViewMarkup.includes("SECURITY"),
  "PF2: staged local recovery view should not render the large nested security card",
);
const routingCopy = "Guard changes routing only after this machine receives signed cloud access.";
assert(
  freeViewMarkup.split(routingCopy).length - 1 === 1,
  "PF2: compact staged recovery view should not duplicate the shared routing hint",
);

const upgradeRequiredStatus: PackageFirewallStatusResponse = {
  ...connectRequiredStatus,
  entitlement: {
    allowed: false,
    reason: "paid_guard_cloud_required",
    tier: "free",
    upgrade_cta: "Upgrade to HOL Guard Cloud to run package firewall actions.",
    upgrade_url: "https://hol.org/guard/pricing",
  },
  actions: {
    install: "paid_required",
    repair: "paid_required",
    test: "paid_required",
    audit: "paid_required",
    sync: "paid_required",
    remove: "paid_required",
  },
  connect_flow: null,
};

const upgradeMarkup = renderToStaticMarkup(
  <EntitlementNotice
    connectError={null}
    connectStarting={false}
    data={upgradeRequiredStatus}
    onStartConnect={() => undefined}
  />,
);

assert(
  !upgradeMarkup.includes("Protected after connect"),
  "PF3: upgrade-required free view should not imply connect alone unlocks protection",
);
assert(
  upgradeMarkup.includes("Upgrade to enable active protection"),
  "PF3: upgrade-required view should render the upgrade CTA",
);

const reconnectLikeStatus: PackageFirewallStatusResponse = {
  ...connectRequiredStatus,
  entitlement: {
    ...connectRequiredStatus.entitlement,
    tier: "team",
  },
};

const reconnectLikeMarkup = renderToStaticMarkup(
  <EntitlementNotice
    connectError={null}
    connectStarting={false}
    data={reconnectLikeStatus}
    onStartConnect={() => undefined}
  />,
);

assert(
  reconnectLikeMarkup.includes("Repair required"),
  "PF4: broken post-connect local auth should render repair guidance instead of a first-connect badge",
);

const failedConnectMarkup = renderToStaticMarkup(
  <ConnectFlowCard
    compact
    connectError="HTTP Error 500: Internal Server Error"
    connectStarting={false}
    connectFlow={{
      state: "failed",
      title: "Guard Cloud sign-in needs attention",
      detail: "Reconnect HOL Guard Cloud to restore package firewall access.",
      action_label: "Repair Guard Cloud access",
      connect_url: "https://hol.org/guard/connect",
      authorize_url: "https://hol.org/mock-authorize",
      browser_opened: false,
      request_id: "guard-connect-2",
      poll_after_ms: 1500,
    }}
    mode="repair"
    onStartConnect={() => undefined}
  />,
);

assert(
  failedConnectMarkup.includes("Cloud sign-in is temporarily unavailable"),
  "PF5: connect errors should surface human guidance instead of raw HTTP text",
);
assert(
  !failedConnectMarkup.includes("HTTP Error 500"),
  "PF5: raw HTTP errors should not appear in the connect card",
);
assert(
  !failedConnectMarkup.includes("What still works locally"),
  "PF5: omitted localRecoveryHint should not render an empty disclosure",
);
assert(
  failedConnectMarkup.includes("Connect progress"),
  "PF5: failed connect card should keep the progressive step rail",
);

const authExpiredMarkup = renderToStaticMarkup(
  <ConnectFlowCard
    compact
    connectError="HTTP Error 401: Unauthorized"
    connectStarting={false}
    connectFlow={{
      state: "failed",
      title: "Guard Cloud sign-in needs attention",
      detail: "Reconnect HOL Guard Cloud to restore package firewall access.",
      action_label: "Repair Guard Cloud access",
      connect_url: "https://hol.org/guard/connect",
      authorize_url: null,
      browser_opened: null,
      request_id: null,
      poll_after_ms: null,
    }}
    mode="repair"
    onStartConnect={() => undefined}
  />,
);
assert(
  authExpiredMarkup.includes("Guard Cloud authorization expired"),
  "PF6: 401 connect errors should map to reconnect guidance",
);

const networkMarkup = renderToStaticMarkup(
  <ConnectFlowCard
    compact
    connectError="Failed to fetch"
    connectStarting={false}
    connectFlow={{
      state: "failed",
      title: "Guard Cloud sign-in needs attention",
      detail: "Reconnect HOL Guard Cloud to restore package firewall access.",
      action_label: "Repair Guard Cloud access",
      connect_url: "https://hol.org/guard/connect",
      authorize_url: null,
      browser_opened: null,
      request_id: null,
      poll_after_ms: null,
    }}
    mode="repair"
    onStartConnect={() => undefined}
  />,
);
assert(
  networkMarkup.includes("Guard lost contact with the local daemon"),
  "PF6: network connect errors should map to daemon guidance",
);

const unknownMarkup = renderToStaticMarkup(
  <ConnectFlowCard
    compact
    connectError="traceback at /tmp/guard-connect.log line 42"
    connectStarting={false}
    connectFlow={{
      state: "failed",
      title: "Guard Cloud sign-in needs attention",
      detail: "Reconnect HOL Guard Cloud to restore package firewall access.",
      action_label: "Repair Guard Cloud access",
      connect_url: "https://hol.org/guard/connect",
      authorize_url: null,
      browser_opened: null,
      request_id: null,
      poll_after_ms: null,
    }}
    mode="repair"
    onStartConnect={() => undefined}
  />,
);
assert(
  unknownMarkup.includes("Guard could not connect right now"),
  "PF6: unknown connect errors should fall back to generic guidance",
);
assert(
  !unknownMarkup.includes("/tmp/guard-connect.log"),
  "PF6: unknown connect errors should not leak raw diagnostics",
);

console.log("package-firewall-connect.test.tsx: all assertions passed");
