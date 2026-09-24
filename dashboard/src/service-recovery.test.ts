import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ServiceRecoveryPanel } from "./service-recovery-panel";
import {
  SERVICE_RECOVERY_BRIDGE_SCHEMA,
  SERVICE_RECOVERY_PROTOCOL,
  RECOVERY_HANDOFF_PATH,
  getRecoveryCapabilities,
  normalizeRecoveryInstallMode,
  openRecoveryView,
  resolveRecoveryInstructions,
} from "./service-recovery";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const nativeBridge = {
  schema: SERVICE_RECOVERY_BRIDGE_SCHEMA,
  protocol: SERVICE_RECOVERY_PROTOCOL,
  capabilities: ["open_recovery"],
  installMode: "desktop-bundled",
  openRecovery: () => undefined,
};

const native = getRecoveryCapabilities({ bridge: nativeBridge });
assert(native.kind === "native", "T06: explicit recovery bridge exposes native handoff capability");
assert(native.installMode === "desktop-bundled", "T06: bridge install mode is preserved");

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    location: {
      href: "http://127.0.0.1:43123/?desktop_embed=1",
      search: "?desktop_embed=1",
      hash: "",
    },
  },
});
const queryOnly = getRecoveryCapabilities();
assert(
  queryOnly.kind === "fallback" && queryOnly.reason === "bridge_missing",
  "T06: desktop_embed is only a display hint and cannot create a trusted recovery bridge",
);
if (originalWindow) {
  Object.defineProperty(globalThis, "window", originalWindow);
} else {
  Reflect.deleteProperty(globalThis, "window");
}

const missing = getRecoveryCapabilities({ bridge: null, installMode: "browser-only" });
assert(
  missing.kind === "fallback" && missing.reason === "bridge_missing",
  "T06: a null bridge is classified as missing rather than malformed",
);
assert(missing.installMode === "browser-only", "T06: browser-only fallback preserves install mode");

const daemonProtocolBridge = {
  ...nativeBridge,
  schema: SERVICE_RECOVERY_PROTOCOL,
};
const daemonProtocol = getRecoveryCapabilities({ bridge: daemonProtocolBridge });
assert(
  daemonProtocol.kind === "fallback" && daemonProtocol.reason === "unsupported_protocol",
  "T06: daemon protocol IDs are not accepted as dashboard bridge schemas",
);

const missingProtocol = getRecoveryCapabilities({
  bridge: {
    schema: SERVICE_RECOVERY_BRIDGE_SCHEMA,
    capabilities: ["open_recovery"],
    openRecovery: () => undefined,
  },
});
assert(
  missingProtocol.kind === "fallback" && missingProtocol.reason === "unsupported_protocol",
  "T06: a missing bridge protocol cannot expose native recovery",
);

const unsupported = getRecoveryCapabilities({
  bridge: { schema: "old-recovery.v0", capabilities: ["open_recovery"], openRecovery: () => undefined },
  installMode: "desktop-bundled",
});
assert(unsupported.kind === "fallback" && unsupported.reason === "unsupported_protocol", "T06: old bridge protocol is unsupported");

assert(normalizeRecoveryInstallMode("bundled") === "desktop-bundled", "T06: bundled alias maps to the bundled Desktop mode");
assert(normalizeRecoveryInstallMode("cli") === "cli", "T06: CLI install mode is recognized");
assert(RECOVERY_HANDOFF_PATH === "/__hol_guard_recovery__", "T06: native handoff uses the fixed code-owned sentinel path");
assert(resolveRecoveryInstructions("desktop-bundled").command === null, "T06/R13: bundled Desktop fallback never invents a global CLI command");
assert(resolveRecoveryInstructions("cli").command === "hol-guard daemon recovery restart", "T06/R13: CLI fallback uses the supported recovery command");

let opened = false;
const handoff = await openRecoveryView({
  bridge: { ...nativeBridge, openRecovery: () => { opened = true; } },
});
assert(handoff.kind === "opened" && opened, "T06: native handoff invokes only the explicit openRecovery callback");

const noHandoff = await openRecoveryView({ bridge: null, installMode: "browser-only" });
assert(noHandoff.kind === "fallback", "T06: unsupported browser handoff does not claim recovery started");

let daemonProtocolOpened = false;
const rejectedDaemonProtocolHandoff = await openRecoveryView({
  bridge: {
    ...daemonProtocolBridge,
    openRecovery: () => { daemonProtocolOpened = true; },
  },
});
assert(
  rejectedDaemonProtocolHandoff.kind === "fallback" && !daemonProtocolOpened,
  "T06: incompatible daemon protocol callbacks are never invoked",
);

const nativeMarkup = renderToStaticMarkup(createElement(ServiceRecoveryPanel, {
  bridge: nativeBridge,
  onRetryConnection: () => undefined,
}));
assert(nativeMarkup.includes("Open recovery"), "T06: native-capable panel renders the handoff action");
assert(!nativeMarkup.includes("Restart Guard</button>"), "T06: dashboard handoff is not labeled as the native restart action");

const bundledMarkup = renderToStaticMarkup(createElement(ServiceRecoveryPanel, {
  bridge: null,
  installMode: "desktop-bundled",
  onRetryConnection: () => undefined,
}));
assert(bundledMarkup.includes('data-testid="service-recovery-instructions"'), "T06/R13: browser fallback exposes local steps");
assert(!bundledMarkup.includes("hol-guard daemon recovery restart"), "T06/R13: bundled-only fallback does not assume a global CLI");

const cliMarkup = renderToStaticMarkup(createElement(ServiceRecoveryPanel, {
  bridge: null,
  installMode: "cli",
  onRetryConnection: () => undefined,
}));
assert(cliMarkup.includes("hol-guard daemon recovery restart"), "T06/R13: CLI fallback shows the supported local command");
assert(cliMarkup.includes("Retry connection"), "T06: fallback retains a connection-only retry action");

console.log("service-recovery.test.ts: all assertions passed");
