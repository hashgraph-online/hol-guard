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
  runningMarkup.includes("Repair required"),
  "PF1: running reconnect card should show repair state badge",
);

const connectRequiredStatus: PackageFirewallStatusResponse = {
  operation: "status",
  status: "completed",
  supported_managers: ["npm", "pnpm"],
  protection: null,
  package_shims: [
    {
      active: false,
      activation_state: "repair_required",
      installed: true,
      integrity: "ok",
      manager: "pnpm",
      path_index: null,
      real_binary_found: true,
      real_binary_path: "/opt/homebrew/bin/pnpm",
      real_binary_path_index: 2,
      shim_path: "/guard-home/package-shims/bin/pnpm",
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
