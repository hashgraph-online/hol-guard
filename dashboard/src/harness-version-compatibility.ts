import { fetchGuardApi } from "./guard-api";

// The daemon decides compatibility. This module only checks the payload's
// shape: anything missing, unknown, or malformed renders as "version unknown",
// so an older daemon can never make an app look tested.

export type HarnessVersionState = "tested" | "untested" | "version_unknown" | "coverage_unavailable";

export type HarnessVersionEvidence = {
  harness_version: string;
  guard_version: string;
  platforms: string[];
  transport: string;
  events: string[];
  suite: { id: string; result: string };
  evidence_level: string;
  evidence_reference: string;
  observed_at: string;
};

export type HarnessVersionCompatibility = {
  harness: string;
  state: HarnessVersionState;
  reason: string | null;
  detectedVersion: string | null;
  versionIsPrerelease: boolean;
  versionSource: string | null;
  observedAt: string | null;
  observationFresh: boolean;
  guardVersion: string | null;
  platform: string | null;
  coverageRevision: string | null;
  testedVersions: string[];
  testedScope: "all_declared_events" | "partial" | null;
  testedEvents: string[];
  declaredEvents: string[];
  evidence: HarnessVersionEvidence[];
  limitations: string[];
  remediation: { label: string; url: string }[];
  acknowledgement: { eligible: boolean; acknowledged: boolean; key: string | null };
};

const STATES: ReadonlySet<string> = new Set(["tested", "untested", "version_unknown", "coverage_unavailable"]);
const SCHEMA = "hol-guard-harness-version-compatibility.v1";

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function texts(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function httpsLinks(value: unknown): { label: string; url: string }[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const link = record(item);
    const label = text(link?.label);
    const url = text(link?.url);
    return label && url && url.startsWith("https://") ? [{ label, url }] : [];
  });
}

// Evidence counts only when every field the daemon guarantees is present; a partial entry is dropped.
function evidenceList(value: unknown): HarnessVersionEvidence[] {
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
    if (
      !entry || !harnessVersion || !guardVersion || !suiteId || suite?.result !== "passed"
      || !reference?.startsWith("https://") || platforms.length === 0 || events.length === 0
    ) {
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
      observed_at: text(entry.observed_at) ?? "",
    }];
  });
}

export function unknownCompatibility(harness: string, reason: string): HarnessVersionCompatibility {
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
    acknowledgement: { eligible: false, acknowledged: false, key: null },
  };
}

export function normalizeVersionCompatibility(harness: string, raw: unknown): HarnessVersionCompatibility {
  const payload = record(raw);
  if (!payload) return unknownCompatibility(harness, "legacy_daemon");
  const state = text(payload.state);
  if (payload.schema !== SCHEMA || !state || !STATES.has(state) || payload.enforcement_effect !== "none") {
    return unknownCompatibility(harness, "legacy_daemon");
  }
  const evidence = evidenceList(payload.evidence);
  const detectedVersion = text(payload.detected_version);
  // A tested claim needs evidence for the exact detected version.
  if (state === "tested" && (!detectedVersion || !evidence.some((item) => item.harness_version === detectedVersion))) {
    return unknownCompatibility(harness, "malformed_payload");
  }
  const ack = record(payload.acknowledgement);
  const ackKey = text(ack?.key);
  const ackEligible = state === "untested" && ack?.eligible === true && ackKey !== null;
  const scope = payload.tested_scope;
  return {
    harness,
    state: state as HarnessVersionState,
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
      key: ackEligible ? ackKey : null,
    },
  };
}

/** Guard has no version source for this app, so there is nothing to show. */
export function versionCheckUnsupported(compatibility: HarnessVersionCompatibility): boolean {
  return compatibility.state === "version_unknown" && compatibility.reason === "discovery_unsupported";
}

export function versionRowLabel(compatibility: HarnessVersionCompatibility): string {
  if (compatibility.state === "tested") {
    return compatibility.testedScope === "partial" ? "Tested · some events" : "Tested version";
  }
  if (compatibility.state === "untested") {
    return compatibility.acknowledgement.acknowledged ? "Untested · acknowledged" : "Untested version";
  }
  if (compatibility.state === "coverage_unavailable") return "Coverage unavailable";
  return "Version unknown";
}

const REASON_COPY: Record<string, string> = {
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
  version_not_in_evidence: "This exact version is not in Guard's tested set. Protection still runs; it has not been verified against this version.",
};

export function versionReasonCopy(compatibility: HarnessVersionCompatibility): string | null {
  return compatibility.reason ? REASON_COPY[compatibility.reason] ?? null : null;
}

async function postVersionAction(path: string, body: Record<string, unknown>): Promise<HarnessVersionCompatibility> {
  const harness = String(body.harness);
  const response = await fetchGuardApi(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = record(await response.json().catch(() => null));
  if (!response.ok) {
    const error = text(payload?.error);
    throw new Error(error === "acknowledgement_stale"
      ? "The installed version changed. Review the current version before acknowledging."
      : `Guard could not update version coverage (${response.status}).`);
  }
  return normalizeVersionCompatibility(harness, payload?.version_compatibility);
}

export function refreshVersionCompatibility(harness: string): Promise<HarnessVersionCompatibility> {
  return postVersionAction("/v1/harness-versions/refresh", { harness });
}

export function acknowledgeUntestedVersion(harness: string, key: string): Promise<HarnessVersionCompatibility> {
  return postVersionAction("/v1/harness-versions/acknowledge", { harness, acknowledgement_key: key });
}

export function clearVersionAcknowledgement(harness: string): Promise<HarnessVersionCompatibility> {
  return postVersionAction("/v1/harness-versions/clear-acknowledgement", { harness });
}
