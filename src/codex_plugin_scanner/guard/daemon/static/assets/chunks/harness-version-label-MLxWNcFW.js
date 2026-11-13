import { ed as fetchGuardApi, r as reactExports, x as isConnectableAppHarness, bq as isGuardDemoMode, j as jsxRuntimeExports, c6 as fetchSettings, aQ as harnessPostureRows, ew as appModesUpdate, U as updateSettings, ex as appModesStatusMessage, ef as appModes, ey as needsConfirm, aD as harnessRowTone, ez as cigarReady, eA as cigarSupported, c1 as guardAwareHref, h as harnessDisplayName, aO as PROTECTION_POSTURE_COPY, eB as guardOffPrompt, eC as cigarUnavailableReason, aV as globalPosture, eD as HiMiniCheckBadge, ag as HiMiniExclamationTriangle, aj as HiMiniMinusCircle, ad as HiMiniQuestionMarkCircle } from "../guard-dashboard.js";
import { S as SettingsSaveProofModal } from "./settings-save-proof-modal-_wjRK7LN.js";
const STATES = /* @__PURE__ */ new Set(["tested", "untested", "version_unknown", "coverage_unavailable"]);
const SCHEMA = "hol-guard-harness-version-compatibility.v1";
function record(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
}
function text(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}
function texts(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}
function httpsLinks(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const link = record(item);
    const label = text(link?.label);
    const url = text(link?.url);
    return label && url && url.startsWith("https://") ? [{ label, url }] : [];
  });
}
function evidenceList(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const entry = record(item);
    const suite = record(entry?.suite);
    const harnessVersion = text(entry?.harness_version);
    const guardVersion = text(entry?.guard_version);
    const suiteId = text(suite?.id);
    const reference = text(entry?.evidence_reference);
    const platforms = texts(entry?.platforms);
    const events = texts(entry?.events);
    if (!entry || !harnessVersion || !guardVersion || !suiteId || suite?.result !== "passed" || !reference?.startsWith("https://") || platforms.length === 0 || events.length === 0) {
      return [];
    }
    return [{
      harness_version: harnessVersion,
      guard_version: guardVersion,
      platforms,
      transport: text(entry.transport) ?? "",
      events,
      suite: { id: suiteId, result: "passed" },
      evidence_level: text(entry.evidence_level) ?? "",
      evidence_reference: reference,
      observed_at: text(entry.observed_at) ?? ""
    }];
  });
}
function unknownCompatibility(harness, reason) {
  return {
    harness,
    state: "version_unknown",
    reason,
    detectedVersion: null,
    versionIsPrerelease: false,
    versionSource: null,
    observedAt: null,
    observationFresh: false,
    guardVersion: null,
    platform: null,
    coverageRevision: null,
    testedVersions: [],
    testedScope: null,
    testedEvents: [],
    declaredEvents: [],
    evidence: [],
    limitations: [],
    remediation: [],
    acknowledgement: { eligible: false, acknowledged: false, key: null }
  };
}
function normalizeVersionCompatibility(harness, raw) {
  const payload = record(raw);
  if (!payload) return unknownCompatibility(harness, "legacy_daemon");
  const state = text(payload.state);
  if (payload.schema !== SCHEMA || !state || !STATES.has(state) || payload.enforcement_effect !== "none") {
    return unknownCompatibility(harness, "legacy_daemon");
  }
  const evidence = evidenceList(payload.evidence);
  const detectedVersion = text(payload.detected_version);
  if (state === "tested" && (!detectedVersion || !evidence.some((item) => item.harness_version === detectedVersion))) {
    return unknownCompatibility(harness, "malformed_payload");
  }
  const ack = record(payload.acknowledgement);
  const ackKey = text(ack?.key);
  const ackEligible = state === "untested" && ack?.eligible === true && ackKey !== null;
  const scope = payload.tested_scope;
  return {
    harness,
    state,
    reason: text(payload.reason),
    detectedVersion,
    versionIsPrerelease: payload.version_is_prerelease === true,
    versionSource: text(payload.version_source),
    observedAt: text(payload.observed_at),
    observationFresh: payload.observation_fresh === true,
    guardVersion: text(payload.guard_version),
    platform: text(payload.platform),
    coverageRevision: text(payload.coverage_revision),
    testedVersions: texts(payload.tested_versions),
    testedScope: scope === "all_declared_events" || scope === "partial" ? scope : null,
    testedEvents: texts(payload.tested_events),
    declaredEvents: texts(payload.declared_events),
    evidence,
    limitations: texts(payload.limitations),
    remediation: httpsLinks(payload.remediation),
    acknowledgement: {
      eligible: ackEligible,
      acknowledged: ackEligible && ack?.acknowledged === true,
      key: ackEligible ? ackKey : null
    }
  };
}
function versionCheckUnsupported(compatibility) {
  return compatibility.state === "version_unknown" && compatibility.reason === "discovery_unsupported";
}
function versionRowLabel(compatibility) {
  if (compatibility.state === "tested") {
    return compatibility.testedScope === "partial" ? "Tested · some events" : "Tested version";
  }
  if (compatibility.state === "untested") {
    return compatibility.acknowledgement.acknowledged ? "Untested · acknowledged" : "Untested version";
  }
  if (compatibility.state === "coverage_unavailable") return "Coverage unavailable";
  return "Version unknown";
}
const REASON_COPY = {
  executable_missing: "Guard could not find this app's executable.",
  metadata_unavailable: "Guard could not find this app's package metadata.",
  metadata_malformed: "This app's package metadata does not name an exact version.",
  probe_timeout: "This app took too long to report its version.",
  probe_failed: "This app did not report its version.",
  banner_malformed: "This app reported its version in an unexpected format.",
  multiple_installations: "More than one installation reports a different version, so Guard cannot tell which one runs.",
  observation_stale: "The last version check is out of date. Refresh to check again.",
  discovery_failed: "Guard could not check this app's version.",
  legacy_daemon: "The running Guard daemon does not report version coverage. Update or restart Guard.",
  malformed_payload: "Guard returned version coverage it could not read.",
  manifest_missing: "This Guard build has no version coverage data.",
  manifest_invalid: "This Guard build's version coverage data is invalid.",
  harness_not_covered: "This Guard build has no tested versions recorded for this app yet.",
  no_evidence_for_this_build: "No tested versions are recorded for this Guard release on this platform.",
  version_not_in_evidence: "This exact version is not in Guard's tested set. Protection still runs; it has not been verified against this version."
};
function versionReasonCopy(compatibility) {
  return compatibility.reason ? REASON_COPY[compatibility.reason] ?? null : null;
}
async function postVersionAction(path, body) {
  const harness = String(body.harness);
  const response = await fetchGuardApi(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const payload = record(await response.json().catch(() => null));
  if (!response.ok) {
    const error = text(payload?.error);
    throw new Error(error === "acknowledgement_stale" ? "The installed version changed. Review the current version before acknowledging." : `Guard could not update version coverage (${response.status}).`);
  }
  return normalizeVersionCompatibility(harness, payload?.version_compatibility);
}
function refreshVersionCompatibility(harness) {
  return postVersionAction("/v1/harness-versions/refresh", { harness });
}
function acknowledgeUntestedVersion(harness, key) {
  return postVersionAction("/v1/harness-versions/acknowledge", { harness, acknowledgement_key: key });
}
function clearVersionAcknowledgement(harness) {
  return postVersionAction("/v1/harness-versions/clear-acknowledgement", { harness });
}
async function fetchHarnessSetupItems() {
  if (isGuardDemoMode()) return [];
  const response = await fetchGuardApi("/v1/harnesses");
  if (!response.ok) throw new Error(`Unable to detect local AI apps (${response.status}).`);
  const payload = await response.json();
  return Array.isArray(payload.items) ? payload.items : [];
}
function useHarnessDetection() {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  reactExports.useEffect(() => {
    let cancelled = false;
    void fetchHarnessSetupItems().then((items) => {
      if (!cancelled) setState({ kind: "ready", items });
    }).catch((error) => {
      if (!cancelled) {
        setState({ kind: "error", message: error instanceof Error ? error.message : "Unable to detect local AI apps." });
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);
  return state;
}
function detectedHarnesses(state) {
  if (state.kind !== "ready") return [];
  return state.items.filter((item) => item.status !== "not_found" && isConnectableAppHarness(item.harness)).map((item) => item.harness);
}
function visibleHarnessesFor(input) {
  return Array.from(new Set([
    ...input.managed,
    ...input.observed,
    ...input.inventory,
    ...input.detected,
    ...input.policies
  ].filter(isConnectableAppHarness))).sort((a, b) => a.localeCompare(b));
}
function isHarnessDetected(state, harness) {
  return state.kind === "ready" && isHarnessDetectedItems(state.items, harness);
}
function isHarnessDetectedItems(items, harness) {
  return items.some((item) => item.harness === harness && item.status !== "not_found");
}
function inactiveInstallNeedsRepair(install, setupStatus) {
  return install.active !== true && setupStatus !== "found" && setupStatus !== "not_found";
}
function resolveDetectedAppStatus(install, protectionHealth, hasInventory, hasReceipts, detected, setupStatus) {
  if (setupStatus === "needs_repair") return "needs_repair";
  if (install !== void 0 && (install.active === true || inactiveInstallNeedsRepair(install, setupStatus))) {
    const hookCheck = protectionHealth.checks.find((check) => check.check_id === "harness_hooks");
    if (!install.active || hookCheck?.status !== "pass") return "needs_repair";
    if (protectionHealth.state === "protected") return "protected";
    return "partial";
  }
  if (setupStatus === "protected") return "protected";
  return hasInventory || hasReceipts || detected ? "found_unprotected" : "not_found";
}
function setupStatusFor(state, harness) {
  return state.kind === "ready" ? state.items.find((item) => item.harness === harness)?.status : void 0;
}
function versionCompatibilityFor(state, harness) {
  if (state.kind !== "ready") return null;
  const item = state.items.find((candidate) => candidate.harness === harness);
  return item ? normalizeVersionCompatibility(harness, item.version_compatibility) : null;
}
function trackClass(checked, attentionWhenOff) {
  if (checked) return "bg-brand-blue";
  if (attentionWhenOff) return "bg-brand-attention/40";
  return "bg-slate-200";
}
function FleetAppModeSwitch(props) {
  const reasonId = reactExports.useId();
  const { checked, disabled } = props;
  const track = trackClass(checked, props.attentionWhenOff === true);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "label",
    {
      className: `inline-flex min-h-11 items-center gap-2 rounded-lg px-1 ${disabled ? "cursor-not-allowed" : "cursor-pointer"}`,
      title: props.unavailableReason,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `text-xs font-semibold ${disabled ? "text-slate-400" : "text-brand-dark"}`, children: props.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            role: "switch",
            "aria-checked": checked,
            "aria-label": props.accessibleName,
            "aria-describedby": props.unavailableReason ? reasonId : void 0,
            disabled,
            onClick: props.onToggle,
            "data-testid": props.testId,
            className: `relative h-6 w-10 shrink-0 rounded-full transition-colors duration-200 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/60 focus-visible:ring-offset-2 disabled:opacity-50 ${track}`,
            children: /* @__PURE__ */ jsxRuntimeExports.jsx(
              "span",
              {
                "aria-hidden": "true",
                className: `absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white shadow-[0_1px_2px_rgba(15,23,42,0.2)] transition-transform duration-200 ease-out ${checked ? "translate-x-4" : "translate-x-0"}`
              }
            )
          }
        ),
        props.unavailableReason ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { id: reasonId, className: "sr-only", children: props.unavailableReason }) : null
      ]
    }
  );
}
function fleetMachinePosture(settings) {
  return globalPosture(settings);
}
function fleetMachinePostureLabel(settings) {
  return PROTECTION_POSTURE_COPY[fleetMachinePosture(settings)].label;
}
function fleetManagedCapabilities(capabilities, apps) {
  const managed = new Set(apps.filter((app) => app.active).map((app) => app.harness));
  const kept = capabilities.filter((capability) => managed.has(capability.harness));
  const known = new Set(kept.map((capability) => capability.harness));
  const synthesized = [...managed].filter((harness) => !known.has(harness)).map((harness) => ({
    harness,
    display_name: harnessDisplayName(harness),
    can_pre_block: false,
    can_ask_inline: false,
    has_native_remember: false,
    fail_open_on_hook_failure: true,
    can_pre_block_limited: false,
    honesty_sentence: "",
    limited: false
  }));
  return [...kept, ...synthesized];
}
function fleetManagedRows(rows, apps) {
  const managed = new Set(apps.filter((app) => app.active).map((app) => app.harness));
  const byName = (a, b) => a.displayName.localeCompare(b.displayName);
  const watching = rows.filter((row) => managed.has(row.harness) && row.effective === "watch").sort(byName);
  const rest = rows.filter((row) => managed.has(row.harness) && row.effective !== "watch").sort(byName);
  return [...watching, ...rest];
}
function gateProofUpdate(gate, proof) {
  return {
    enabled: gate?.enabled ?? false,
    configured: gate?.configured ?? false,
    cooldown_seconds: gate?.cooldown_seconds ?? 0,
    cooldown_active: gate?.cooldown_active ?? false,
    cooldown_expires_at: gate?.cooldown_expires_at ?? null,
    locked_until: gate?.locked_until ?? null,
    fail_closed: gate?.fail_closed ?? false,
    strict_all_decisions: gate?.strict_all_decisions ?? false,
    totp_enabled: gate?.totp_enabled ?? false,
    totp_pending: gate?.totp_pending ?? false,
    ...proof?.currentPassword ? { current_password: proof.currentPassword } : {},
    ...proof?.totpCode ? { totp_code: proof.totpCode } : {}
  };
}
function useFleetAppPosture(props) {
  const { onChanged } = props;
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [pendingWatch, setPendingWatch] = reactExports.useState(null);
  const [savingHarness, setSavingHarness] = reactExports.useState(null);
  const [proofRequest, setProofRequest] = reactExports.useState(null);
  const [proofPending, setProofPending] = reactExports.useState(false);
  const [proofError, setProofError] = reactExports.useState(null);
  const [statusMessage, setStatusMessage] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  reactExports.useEffect(() => {
    let cancelled = false;
    fetchSettings().then((payload) => {
      if (cancelled) return;
      setState({
        kind: "ready",
        settings: payload.settings,
        capabilities: payload.protection_capabilities ?? []
      });
    }).catch((cause) => {
      if (cancelled) return;
      setState({ kind: "error", message: cause instanceof Error ? cause.message : "Unable to load app protection." });
    });
    return () => {
      cancelled = true;
    };
  }, []);
  const gate = state.kind === "ready" ? state.settings.approval_gate ?? null : null;
  const gateEnabled = gate?.enabled === true;
  const rows = reactExports.useMemo(() => {
    if (state.kind !== "ready") return [];
    return fleetManagedRows(
      harnessPostureRows(state.settings, fleetManagedCapabilities(state.capabilities, props.apps)),
      props.apps
    );
  }, [state, props.apps]);
  const commit = reactExports.useCallback(async (harness, next, proof) => {
    if (state.kind !== "ready") return "App protection is still loading.";
    const saved = state.settings;
    const update = appModesUpdate(saved, harness, next);
    if (update === null) {
      setPendingWatch(null);
      return null;
    }
    if (gateEnabled) {
      update.approval_gate = gateProofUpdate(saved.approval_gate, proof);
    }
    setSavingHarness(harness);
    setError(null);
    try {
      const payload = await updateSettings(update);
      setState((current) => current.kind === "ready" ? { ...current, settings: payload.settings } : current);
      const name = rows.find((row) => row.harness === harness)?.displayName ?? harness;
      setStatusMessage(appModesStatusMessage(next, name));
      setPendingWatch(null);
      onChanged?.();
      return null;
    } catch (cause) {
      return cause instanceof Error ? cause.message : "Unable to change Guard or CIGAR for this app.";
    } finally {
      setSavingHarness(null);
    }
  }, [state, gateEnabled, rows, onChanged]);
  const save = reactExports.useCallback((change) => {
    if (gateEnabled) {
      const displayName = rows.find((row) => row.harness === change.harness)?.displayName ?? change.harness;
      setProofError(null);
      setProofRequest({ ...change, displayName });
      return;
    }
    void commit(change.harness, change.next).then((failure) => {
      if (failure !== null) setError(failure);
    });
  }, [gateEnabled, rows, commit]);
  const handleToggle = reactExports.useCallback((harness, part) => {
    if (state.kind !== "ready") return;
    const current = appModes(state.settings, harness);
    const next = { ...current, [part]: !current[part] };
    if (part === "guard" && state.settings.harness_postures_locked === true) return;
    setError(null);
    setStatusMessage(null);
    if (needsConfirm(current, next, state.settings.harness_postures_locked === true)) {
      setPendingWatch({ harness, next });
      return;
    }
    setPendingWatch(null);
    save({ harness, next });
  }, [state, save]);
  const handleConfirmWatch = reactExports.useCallback((change) => {
    setPendingWatch(null);
    save(change);
  }, [save]);
  const handleProofConfirm = reactExports.useCallback(async (proof) => {
    if (proofRequest === null) return;
    setProofPending(true);
    setProofError(null);
    const failure = await commit(proofRequest.harness, proofRequest.next, proof);
    setProofPending(false);
    if (failure === null) {
      setProofRequest(null);
    } else {
      setProofError(failure);
    }
  }, [proofRequest, commit]);
  const handleCancelWatch = reactExports.useCallback(() => setPendingWatch(null), []);
  const rowFor = reactExports.useCallback((harness) => rows.find((row) => row.harness === harness), [rows]);
  if (state.kind !== "ready") {
    return {
      kind: state.kind,
      rowFor,
      control: () => null,
      watchConfirm: () => null,
      summary: null,
      settings: null,
      footer: state.kind === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-slate-500", children: "Per-app protection settings are unavailable right now." }) : null
    };
  }
  const settings = state.settings;
  const locked = settings.harness_postures_locked === true;
  const watchingCount = rows.filter((row) => harnessRowTone(row) === "watch").length;
  const control = (harness) => {
    const row = rowFor(harness);
    if (!row) return null;
    const saving = savingHarness === harness;
    const modes = appModes(settings, harness);
    const cigarReason = cigarUnavailableReason(settings, harness, row.displayName);
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        role: "group",
        "aria-label": `Guard and CIGAR in ${row.displayName}`,
        className: "flex shrink-0 items-center gap-3",
        "data-testid": "fleet-app-modes",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            FleetAppModeSwitch,
            {
              label: "Guard",
              accessibleName: `Guard in ${row.displayName}`,
              checked: modes.guard,
              disabled: saving || locked,
              unavailableReason: locked ? "Your organization manages protection for this app." : void 0,
              attentionWhenOff: true,
              onToggle: () => handleToggle(harness, "guard"),
              testId: `fleet-app-guard-${harness}`
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            FleetAppModeSwitch,
            {
              label: "CIGAR",
              accessibleName: `CIGAR in ${row.displayName}`,
              checked: modes.cigar,
              disabled: saving || cigarReason !== void 0,
              unavailableReason: cigarReason,
              onToggle: () => handleToggle(harness, "cigar"),
              testId: `fleet-app-cigar-${harness}`
            }
          ),
          saving ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Saving…" }) : null
        ]
      }
    );
  };
  const watchConfirm = (harness) => {
    if (pendingWatch?.harness !== harness) return null;
    const row = rowFor(harness);
    if (!row) return null;
    const change = pendingWatch;
    const guardWasOn = appModes(settings, harness).guard;
    const confirmLabel = guardWasOn ? "Turn Guard off" : "Turn CIGAR on";
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: "mt-2 flex flex-col gap-2 rounded-xl bg-brand-attention/[0.06] px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between",
        role: "alertdialog",
        "aria-label": guardWasOn ? `Turn Guard off in ${row.displayName}` : `Turn CIGAR on in ${row.displayName}`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark", children: guardOffPrompt(settings, harness, change.next, row.displayName) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: () => handleConfirmWatch(change),
                className: "inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white",
                children: confirmLabel
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: handleCancelWatch,
                className: "inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark",
                children: guardWasOn ? "Keep Guard on" : "Cancel"
              }
            )
          ] })
        ]
      }
    );
  };
  const summary = rows.length === 0 ? null : /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-500", "data-testid": "fleet-machine-posture", children: [
    "Machine:",
    " ",
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-dark", children: fleetMachinePostureLabel(settings) }),
    watchingCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-semibold text-brand-attention", children: [
      " · Guard off in ",
      watchingCount
    ] }) : null
  ] });
  const footer = /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    error !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 rounded-lg bg-brand-attention/[0.05] px-3 py-2 text-xs text-brand-dark", children: error }) : null,
    !cigarReady(settings) && rows.some((row) => cigarSupported(row.harness)) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-xs text-slate-500", "data-testid": "fleet-cigar-setup", children: [
      "CIGAR is off on this machine, so it can't add project context or save tokens in any app yet.",
      " ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("a", { className: "font-medium text-brand-blue underline underline-offset-2", href: guardAwareHref("/cigar"), children: "Set up CIGAR" })
    ] }) : null,
    locked && rows.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-slate-400", children: "Your organization manages Guard for each app, so Guard can't be turned on or off here. CIGAR can still be changed." }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { "aria-live": "polite", "aria-atomic": "true", className: "sr-only", children: statusMessage ?? "" }),
    proofRequest !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsSaveProofModal,
      {
        open: true,
        mode: "verify-save",
        gate,
        title: "Confirm before changing Guard or CIGAR",
        detail: `Enter your approval proof to change ${proofRequest.displayName}.`,
        confirmLabel: "Save change",
        error: proofError,
        pending: proofPending,
        onCancel: () => {
          if (proofPending) return;
          setProofRequest(null);
          setProofError(null);
        },
        onConfirm: handleProofConfirm
      }
    ) : null
  ] });
  return { kind: "ready", rowFor, control, watchConfirm, summary, settings, footer };
}
function toneFor(compatibility) {
  if (compatibility.state === "tested") return { className: "text-emerald-600", Icon: HiMiniCheckBadge };
  if (compatibility.state === "untested") {
    return compatibility.acknowledgement.acknowledged ? { className: "text-slate-500", Icon: HiMiniExclamationTriangle } : { className: "text-amber-700", Icon: HiMiniExclamationTriangle };
  }
  if (compatibility.state === "coverage_unavailable") return { className: "text-slate-500", Icon: HiMiniMinusCircle };
  return { className: "text-slate-500", Icon: HiMiniQuestionMarkCircle };
}
function HarnessVersionLabel({ compatibility }) {
  if (!compatibility || versionCheckUnsupported(compatibility)) return null;
  const { className, Icon } = toneFor(compatibility);
  const label = versionRowLabel(compatibility);
  const version = compatibility.detectedVersion;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "span",
    {
      className: `inline-flex items-center gap-1 text-xs font-medium ${className}`,
      "data-version-state": compatibility.state,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-3.5 w-3.5 shrink-0", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: version ? `${label} · ${version}` : label })
      ]
    }
  );
}
export {
  HarnessVersionLabel as H,
  useHarnessDetection as a,
  versionCompatibilityFor as b,
  versionCheckUnsupported as c,
  detectedHarnesses as d,
  versionReasonCopy as e,
  refreshVersionCompatibility as f,
  acknowledgeUntestedVersion as g,
  clearVersionAcknowledgement as h,
  inactiveInstallNeedsRepair as i,
  isHarnessDetected as j,
  resolveDetectedAppStatus as r,
  setupStatusFor as s,
  useFleetAppPosture as u,
  visibleHarnessesFor as v
};
