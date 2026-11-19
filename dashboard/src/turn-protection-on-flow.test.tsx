import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  GuardApprovalGatePublicConfig,
  GuardSettings,
  GuardSettingsPayload,
} from "./guard-types";
import type { GuardSettingsUpdate } from "./guard-api";
import {
  finishTurnProtectionOn,
  startTurnProtectionOn,
  turnProtectionOnErrorMessage,
  turnProtectionOnLocked,
  type TurnProtectionOnDeps,
} from "./turn-protection-on-flow";
import { WatchProtectionBanner } from "./watch-protection-banner";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function settings(overrides: Partial<GuardSettings> = {}): GuardSettings {
  return {
    mode: "enforce",
    protection_posture: "protected",
    security_level: "balanced",
    harness_postures: {},
    ...overrides,
  } as GuardSettings;
}

function gate(overrides: Partial<GuardApprovalGatePublicConfig> = {}): GuardApprovalGatePublicConfig {
  return {
    enabled: true,
    configured: true,
    cooldown_seconds: 0,
    cooldown_active: false,
    cooldown_expires_at: null,
    locked_until: null,
    fail_closed: false,
    strict_all_decisions: false,
    totp_enabled: true,
    totp_pending: false,
    ...overrides,
  } as GuardApprovalGatePublicConfig;
}

function fakeDeps(saved: GuardSettings, failUpdate?: Error) {
  const updates: GuardSettingsUpdate[] = [];
  const deps: TurnProtectionOnDeps = {
    fetchSettings: async () => ({ settings: saved } as GuardSettingsPayload),
    updateSettings: async (update) => {
      updates.push(update);
      if (failUpdate) throw failUpdate;
      return { settings: { ...saved, protection_posture: "protected", harness_postures: {} } } as GuardSettingsPayload;
    },
  };
  return { deps, updates };
}

async function main(): Promise<void> {
  // Gate off: one click saves the change in place, no trip to Settings.
  {
    const { deps, updates } = fakeDeps(settings({ protection_posture: "watch" }));
    const step = await startTurnProtectionOn(deps);
    assert(step.kind === "saved" && step.payload !== null, "gate off saves right away");
    assert(updates.length === 1 && updates[0].protection_posture === "protected", "gate off sends the posture change");
    assert(updates[0].approval_gate === undefined, "gate off sends no approval proof");
  }

  // Per-app Watch entries are cleared, the machine posture is left alone.
  {
    const { deps, updates } = fakeDeps(settings({ harness_postures: { codex: "watch", cursor: "protected" } }));
    await startTurnProtectionOn(deps);
    assert(updates[0].protection_posture === undefined, "per-app Watch leaves the machine posture alone");
    assert(
      JSON.stringify(updates[0].harness_postures) === JSON.stringify({ codex: null }),
      "per-app Watch clears only the apps in Watch",
    );
  }

  // Gate on: the banner asks for the password and code before saving anything.
  {
    const saved = settings({ protection_posture: "watch", approval_gate: gate() });
    const { deps, updates } = fakeDeps(saved);
    const step = await startTurnProtectionOn(deps);
    assert(step.kind === "needs-proof", "gate on asks for approval proof");
    assert(updates.length === 0, "gate on saves nothing before the proof");
    if (step.kind !== "needs-proof") return;
    await finishTurnProtectionOn(deps, step.settings, { currentPassword: "pw", totpCode: "123456" });
    assert(updates.length === 1, "proof saves once");
    const sent = updates[0];
    const sentGate = sent.approval_gate as Record<string, unknown> | undefined;
    assert(sent.protection_posture === "protected", "proof save carries the posture change");
    assert(sentGate?.current_password === "pw", "proof save carries the password");
    assert(sentGate?.totp_code === "123456", "proof save carries the authenticator code");
    assert(sentGate?.enabled === true, "proof save keeps the gate on");
  }

  // Nothing left in Watch: settle without a write.
  {
    const { deps, updates } = fakeDeps(settings());
    const step = await startTurnProtectionOn(deps);
    assert(step.kind === "saved" && step.payload === null, "nothing in Watch settles without a save");
    assert(updates.length === 0, "nothing in Watch sends no update");
  }

  // Organization-managed posture cannot change here.
  {
    const lockedApps = settings({ harness_postures: { codex: "watch" }, harness_postures_locked: true });
    assert(turnProtectionOnLocked(lockedApps, { harness_postures: { codex: null } }), "locked per-app posture is locked");
    const { deps, updates } = fakeDeps(lockedApps);
    const step = await startTurnProtectionOn(deps);
    assert(step.kind === "locked" && updates.length === 0, "locked per-app posture saves nothing");
    const managedMachine = settings({ protection_posture: "watch", managed_locked_settings: ["protection_posture"] });
    assert(
      turnProtectionOnLocked(managedMachine, { protection_posture: "protected" }),
      "managed machine posture is locked",
    );
  }

  // Failures surface their message; nothing navigates away.
  {
    const { deps } = fakeDeps(settings({ protection_posture: "watch" }), new Error("Guard is restarting."));
    let caught: unknown = null;
    try {
      await startTurnProtectionOn(deps);
    } catch (cause) {
      caught = cause;
    }
    assert(turnProtectionOnErrorMessage(caught) === "Guard is restarting.", "save failure keeps the daemon message");
    assert(
      turnProtectionOnErrorMessage(new Error("  ")) === "Guard couldn't turn protection on. Try again.",
      "empty failure gets a recovery message",
    );
  }

  // Rendered states.
  const model = {
    globalWatch: false,
    appNames: ["Codex"],
    message: "Guard is only recording in Codex. Other apps are protected.",
    confirmMessage: "Guard will start stopping dangerous actions in Codex.",
  };
  const idle = renderToStaticMarkup(createElement(WatchProtectionBanner, { model }));
  assert(idle.includes("Turn protection on for these apps"), "idle banner offers the per-app action");
  const proof = renderToStaticMarkup(createElement(WatchProtectionBanner, {
    model,
    initialState: { kind: "proof", settings: settings(), gate: gate(), pending: false, error: null },
  }));
  assert(proof.includes("Waiting for approval"), "proof step shows the banner is waiting on approval");
  const error = renderToStaticMarkup(createElement(WatchProtectionBanner, {
    model,
    onOpenSettings: () => undefined,
    initialState: { kind: "error", message: "Guard is restarting." },
  }));
  assert(error.includes("Guard is restarting.") && error.includes("Try again"), "error step offers a retry");
  assert(error.includes("Open settings"), "error step offers Settings only as a fallback");
  const locked = renderToStaticMarkup(createElement(WatchProtectionBanner, { model, initialState: { kind: "locked" } }));
  assert(locked.includes("organization manages") && !locked.includes("<button"), "locked step has no dead button");
  const heldIdle = renderToStaticMarkup(createElement(WatchProtectionBanner, { model, disabled: true }));
  assert(/<button[^>]*disabled=""[^>]*>Turn protection on for these apps/.test(heldIdle), "banner cannot start while the page saves");
  const heldConfirm = renderToStaticMarkup(createElement(WatchProtectionBanner, {
    model,
    disabled: true,
    initialState: { kind: "confirming" },
  }));
  assert(/<button[^>]*disabled=""[^>]*>Turn on</.test(heldConfirm), "banner confirm is held while the page saves");
  const settingsSource = readFileSync(new URL("./settings-workspace.tsx", import.meta.url), "utf8");
  assert(
    settingsSource.includes("onBusyChange={setWatchBannerBusy}")
      && settingsSource.includes("disabled={saving || proofModalOpen}\n        />")
      && settingsSource.includes("if (draft === null || watchBannerBusy)")
      && settingsSource.includes("contextAssistanceBusy || watchBannerBusy}"),
    "Settings and the banner never save at the same time",
  );
  const done = renderToStaticMarkup(createElement(WatchProtectionBanner, { model, initialState: { kind: "done" } }));
  assert(done.includes("Protection is on."), "done step confirms the change");

  // No banner host sends the user to Settings after a successful turn-on.
  for (const file of ["home-dashboard.tsx", "approval-center-layout.tsx", "settings-workspace.tsx"]) {
    const source = readFileSync(new URL(`./${file}`, import.meta.url), "utf8");
    assert(!source.includes("onTurnProtectionOn"), `${file} uses the in-place turn-on flow`);
  }
  const home = readFileSync(new URL("./home-dashboard.tsx", import.meta.url), "utf8");
  const homeHandler = home.slice(home.indexOf("handleProtectionTurnedOn = useCallback"), home.indexOf("handleClearPasswordChange"));
  assert(homeHandler.length > 0 && !homeHandler.includes("onOpenSettings"), "home stays on home after turning protection on");

  console.log("turn-protection-on-flow tests passed");
}

await main();
