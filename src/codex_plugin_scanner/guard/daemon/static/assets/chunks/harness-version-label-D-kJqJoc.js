import { c7 as fetchGuardApi, r as reactExports, k as isConnectableAppHarness, b9 as isGuardDemoMode, j as jsxRuntimeExports, cq as HiMiniCheckBadge, T as HiMiniExclamationTriangle, X as HiMiniMinusCircle, P as HiMiniQuestionMarkCircle } from "../guard-dashboard.js";
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
function resolveDetectedAppStatus(install, protectionHealth, hasInventory, hasReceipts, detected) {
  if (install !== void 0) {
    const hookCheck = protectionHealth.checks.find((check) => check.check_id === "harness_hooks");
    if (!install.active || hookCheck?.status !== "pass") return "needs_repair";
    if (protectionHealth.state === "protected") return "protected";
    return "partial";
  }
  return hasInventory || hasReceipts || detected ? "found_unprotected" : "not_found";
}
function versionCompatibilityFor(state, harness) {
  if (state.kind !== "ready") return null;
  const item = state.items.find((candidate) => candidate.harness === harness);
  return item ? normalizeVersionCompatibility(harness, item.version_compatibility) : null;
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
  versionCompatibilityFor as a,
  versionCheckUnsupported as b,
  versionReasonCopy as c,
  detectedHarnesses as d,
  refreshVersionCompatibility as e,
  acknowledgeUntestedVersion as f,
  clearVersionAcknowledgement as g,
  isHarnessDetected as i,
  resolveDetectedAppStatus as r,
  useHarnessDetection as u,
  visibleHarnessesFor as v
};
