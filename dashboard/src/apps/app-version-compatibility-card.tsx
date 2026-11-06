import { useCallback, useEffect, useRef, useState } from "react";

import { ActionButton, SectionLabel } from "../approval-center-primitives";
import { formatRelativeTime } from "../approval-center-utils";
import {
  acknowledgeUntestedVersion,
  clearVersionAcknowledgement,
  refreshVersionCompatibility,
  versionCheckUnsupported,
  versionReasonCopy,
  type HarnessVersionCompatibility,
} from "../harness-version-compatibility";
import { HarnessVersionLabel } from "../harness-version-label";

const SOURCE_LABELS: Record<string, string> = {
  "package-metadata": "Package metadata",
  "version-probe": "Version check",
};

const LEVEL_LABELS: Record<string, string> = {
  unit_test: "Contract test",
  live_block: "Full-task run",
};

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-wide text-slate-400">{label}</dt>
      <dd className="mt-0.5 break-words text-sm text-brand-dark">{children}</dd>
    </div>
  );
}

function EvidenceSummary({ compatibility }: { compatibility: HarnessVersionCompatibility }) {
  if (compatibility.state !== "tested") return null;
  const levels = Array.from(new Set(compatibility.evidence.map((item) => LEVEL_LABELS[item.evidence_level] ?? item.evidence_level)));
  const untested = compatibility.declaredEvents.filter((event) => !compatibility.testedEvents.includes(event));
  return (
    <div className="mt-4 space-y-1 text-sm text-slate-600">
      <p>
        Evidence: {levels.join(", ")} on Guard {compatibility.guardVersion} ({compatibility.platform}).{" "}
        {compatibility.evidence.map((item) => (
          <a
            key={`${item.suite.id}-${item.evidence_reference}`}
            href={item.evidence_reference}
            target="_blank"
            rel="noreferrer noopener"
            className="text-brand-blue underline-offset-2 hover:underline"
          >
            View run
          </a>
        ))}
      </p>
      {untested.length > 0 ? <p>Not covered by this evidence: {untested.join(", ")}.</p> : null}
    </div>
  );
}

export function AppVersionCompatibilityCard({ initial }: { initial: HarnessVersionCompatibility | null }) {
  const [compatibility, setCompatibility] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Responses for an app the user has since navigated away from are dropped.
  const currentHarness = useRef(initial?.harness ?? null);
  useEffect(() => {
    currentHarness.current = initial?.harness ?? null;
    setCompatibility(initial);
    setBusy(false);
    setError(null);
  }, [initial]);

  const run = useCallback(async (action: () => Promise<HarnessVersionCompatibility>) => {
    const requested = currentHarness.current;
    setBusy(true);
    setError(null);
    try {
      const next = await action();
      if (currentHarness.current === requested) setCompatibility(next);
    } catch (caught) {
      if (currentHarness.current === requested) {
        setError(caught instanceof Error ? caught.message : "Guard could not update version coverage.");
      }
    } finally {
      if (currentHarness.current === requested) setBusy(false);
    }
  }, []);

  if (!compatibility || versionCheckUnsupported(compatibility)) return null;
  const harness = compatibility.harness;
  const reason = versionReasonCopy(compatibility);
  const ack = compatibility.acknowledgement;
  const collapsed = compatibility.state === "untested" && ack.acknowledged;

  return (
    <section className="rounded-xl border border-slate-100 p-4 sm:p-5" aria-labelledby="app-version-heading">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <SectionLabel>
            <span id="app-version-heading">Version coverage</span>
          </SectionLabel>
          <div className="mt-2">
            <HarnessVersionLabel compatibility={compatibility} />
          </div>
        </div>
        <ActionButton
          variant="ghost"
          disabled={busy}
          onClick={() => void run(() => refreshVersionCompatibility(harness))}
        >
          {busy ? "Checking…" : "Check again"}
        </ActionButton>
      </div>

      {compatibility.state === "untested" && !collapsed ? (
        <div className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900" role="status">
          <p className="font-medium">Guard has not been tested with {compatibility.detectedVersion}.</p>
          <p className="mt-1">
            Protection still runs, but Guard has no evidence that every check works with this exact version.
            {compatibility.testedVersions.length > 0
              ? ` Tested versions: ${compatibility.testedVersions.join(", ")}.`
              : ""}
          </p>
          {ack.eligible && ack.key ? (
            <div className="mt-3">
              <ActionButton
                variant="outline"
                disabled={busy}
                onClick={() => void run(() => acknowledgeUntestedVersion(harness, ack.key as string))}
              >
                Acknowledge for this version
              </ActionButton>
            </div>
          ) : null}
        </div>
      ) : reason ? (
        <p className="mt-3 text-sm text-slate-600">{reason}</p>
      ) : null}

      {collapsed ? (
        <p className="mt-3 text-sm text-slate-600">
          You acknowledged that {compatibility.detectedVersion} is untested. The warning returns if the version,
          installation, or Guard's coverage changes.{" "}
          <button
            type="button"
            className="text-brand-blue underline-offset-2 hover:underline disabled:opacity-50"
            disabled={busy}
            onClick={() => void run(() => clearVersionAcknowledgement(harness))}
          >
            Show warning again
          </button>
        </p>
      ) : null}

      <EvidenceSummary compatibility={compatibility} />

      <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
        <Fact label="Detected">
          {compatibility.detectedVersion ?? "Unknown"}
          {compatibility.versionIsPrerelease ? " (pre-release)" : ""}
        </Fact>
        <Fact label="Source">
          {(compatibility.versionSource && SOURCE_LABELS[compatibility.versionSource]) ?? "None"}
        </Fact>
        <Fact label="Checked">
          {compatibility.observedAt ? formatRelativeTime(compatibility.observedAt) : "Never"}
          {compatibility.observedAt && !compatibility.observationFresh ? " (out of date)" : ""}
        </Fact>
        <Fact label="Tested versions">
          {compatibility.testedVersions.length > 0 ? compatibility.testedVersions.join(", ") : "None recorded"}
        </Fact>
        {compatibility.coverageRevision ? <Fact label="Coverage data">{compatibility.coverageRevision}</Fact> : null}
      </dl>

      {compatibility.limitations.length > 0 ? (
        <ul className="mt-4 list-disc space-y-1 pl-5 text-xs text-slate-500">
          {compatibility.limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      ) : null}

      {compatibility.remediation.length > 0 && compatibility.state !== "tested" ? (
        <p className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs">
          {compatibility.remediation.map((link) => (
            <a
              key={link.url}
              href={link.url}
              target="_blank"
              rel="noreferrer noopener"
              className="text-brand-blue underline-offset-2 hover:underline"
            >
              {link.label}
            </a>
          ))}
        </p>
      ) : null}

      <p className="mt-3 text-xs text-slate-400">Version coverage is informational. It never changes what Guard allows or blocks.</p>
      {error ? (
        <p className="mt-2 text-xs text-brand-attention" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
