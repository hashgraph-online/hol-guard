import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { HiMiniEye, HiMiniShieldCheck } from "react-icons/hi2";

import { SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import { fetchSettings, updateSettings, type GuardSettingsUpdate } from "./guard-api";
import type { GuardApprovalGatePublicConfig, GuardProtectionCapability, GuardSettings } from "./guard-types";
import {
  globalPosture,
  harnessPostureOptions,
  harnessPosturePatch,
  harnessPostureRows,
  harnessRowStatus,
  harnessRowTone,
  selectHarnessPosture,
  type HarnessPostureChoice,
  type HarnessPostureRow,
} from "./harness-posture-ui";
import { HarnessPostureChoiceLabel } from "./harness-posture-card";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "./settings-save-proof-modal";
import { PROTECTION_POSTURE_COPY, type ProtectionPosture } from "./protection-posture-copy";

/** One app the Protect screen knows about: its id and whether Guard manages its hooks. */
export type FleetPostureApp = { harness: string; active: boolean };

type FleetPostureState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; settings: GuardSettings; capabilities: GuardProtectionCapability[] };

type ProofRequest = {
  harness: string;
  displayName: string;
  choice: HarnessPostureChoice;
};

export type GateProofUpdate = GuardApprovalGatePublicConfig & { current_password?: string; totp_code?: string };

/**
 * The machine posture the Protect-screen header states. Delegates to the
 * shared derivation so the header can never disagree with the rows, including
 * the legacy observe-mode fallback.
 */
export function fleetMachinePosture(settings: GuardSettings): ProtectionPosture {
  return globalPosture(settings);
}

export function fleetMachinePostureLabel(settings: GuardSettings): string {
  return PROTECTION_POSTURE_COPY[fleetMachinePosture(settings)].label;
}

/**
 * Capability entries for the apps Guard manages on this machine. Capabilities
 * cover every harness Guard supports; a managed app missing from the catalog
 * still gets an entry so its row is never silently dropped.
 */
export function fleetManagedCapabilities(
  capabilities: GuardProtectionCapability[],
  apps: FleetPostureApp[],
): GuardProtectionCapability[] {
  const managed = new Set(apps.filter((app) => app.active).map((app) => app.harness));
  const kept = capabilities.filter((capability) => managed.has(capability.harness));
  const known = new Set(kept.map((capability) => capability.harness));
  const synthesized = [...managed]
    .filter((harness) => !known.has(harness))
    .map((harness) => ({
      harness,
      display_name: harnessDisplayName(harness),
      can_pre_block: false,
      can_ask_inline: false,
      has_native_remember: false,
      fail_open_on_hook_failure: true,
      can_pre_block_limited: false,
      honesty_sentence: "",
      limited: false,
    }));
  return [...kept, ...synthesized];
}

/**
 * Posture rows for the apps Guard manages, Watch first so a weaker posture
 * cannot hide in the list. Apps without Guard hooks are absent: their posture
 * setting protects nothing yet and must not read as Protected.
 */
export function fleetManagedRows(rows: HarnessPostureRow[], apps: FleetPostureApp[]): HarnessPostureRow[] {
  const managed = new Set(apps.filter((app) => app.active).map((app) => app.harness));
  const byName = (a: HarnessPostureRow, b: HarnessPostureRow) => a.displayName.localeCompare(b.displayName);
  const watching = rows.filter((row) => managed.has(row.harness) && row.effective === "watch").sort(byName);
  const rest = rows.filter((row) => managed.has(row.harness) && row.effective !== "watch").sort(byName);
  return [...watching, ...rest];
}

export function fleetInactiveAppCount(apps: FleetPostureApp[]): number {
  return apps.filter((app) => !app.active).length;
}

/** Plain-language confirmation for a saved posture change. */
export function fleetPostureStatusMessage(choice: HarnessPostureChoice, displayName: string): string {
  return choice === "watch" ? `Guard is only recording in ${displayName}.` : `Protection restored in ${displayName}.`;
}

/** Gate payload for a settings save, carrying the operator's proof credentials. */
export function gateProofUpdate(
  gate: GuardApprovalGatePublicConfig | null | undefined,
  proof?: SettingsSaveProofCredentials,
): GateProofUpdate {
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
    ...(proof?.currentPassword ? { current_password: proof.currentPassword } : {}),
    ...(proof?.totpCode ? { totp_code: proof.totpCode } : {}),
  };
}

type FleetAppProtectionProps = {
  apps: FleetPostureApp[];
  /** Called after a saved posture change so the parent can refresh the runtime snapshot. */
  onChanged?: () => Promise<void> | void;
};

/**
 * Compact per-app protection control for the Protect screen. Only apps whose
 * hooks Guard actually manages appear, so the card never claims Protected for
 * an app that is not intercepted. Choices save right away; Watch confirms
 * inline first and the approval gate uses the existing proof modal.
 */
export function FleetAppProtection(props: FleetAppProtectionProps) {
  const { onChanged } = props;
  const [state, setState] = useState<FleetPostureState>({ kind: "loading" });
  const [pendingWatch, setPendingWatch] = useState<string | null>(null);
  const [savingHarness, setSavingHarness] = useState<string | null>(null);
  const [proofRequest, setProofRequest] = useState<ProofRequest | null>(null);
  const [proofPending, setProofPending] = useState(false);
  const [proofError, setProofError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchSettings()
      .then((payload) => {
        if (cancelled) return;
        setState({
          kind: "ready",
          settings: payload.settings,
          capabilities: payload.protection_capabilities ?? [],
        });
      })
      .catch((cause: unknown) => {
        if (cancelled) return;
        setState({ kind: "error", message: cause instanceof Error ? cause.message : "Unable to load app protection." });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const gate: GuardApprovalGatePublicConfig | null = state.kind === "ready" ? state.settings.approval_gate ?? null : null;
  const gateEnabled = gate?.enabled === true;

  const rows = useMemo(() => {
    if (state.kind !== "ready") return [];
    return fleetManagedRows(
      harnessPostureRows(state.settings, fleetManagedCapabilities(state.capabilities, props.apps)),
      props.apps,
    );
  }, [state, props.apps]);

  const commit = useCallback(async (harness: string, choice: HarnessPostureChoice, proof?: SettingsSaveProofCredentials): Promise<string | null> => {
    if (state.kind !== "ready") return "App protection is still loading.";
    const saved = state.settings;
    const next = selectHarnessPosture(saved, harness, choice);
    const patch = harnessPosturePatch(next, saved);
    if (patch === null) {
      setPendingWatch(null);
      return null;
    }
    const update: GuardSettingsUpdate = { harness_postures: patch };
    if (gateEnabled) {
      update.approval_gate = gateProofUpdate(saved.approval_gate, proof);
    }
    setSavingHarness(harness);
    setError(null);
    try {
      const payload = await updateSettings(update);
      setState((current) => current.kind === "ready"
        ? { ...current, settings: payload.settings }
        : current);
      const name = rows.find((row) => row.harness === harness)?.displayName ?? harness;
      setStatusMessage(fleetPostureStatusMessage(choice, name));
      setPendingWatch(null);
      onChanged?.();
      return null;
    } catch (cause: unknown) {
      return cause instanceof Error ? cause.message : "Unable to change protection for this app.";
    } finally {
      setSavingHarness(null);
    }
  }, [state, gateEnabled, rows, onChanged]);

  const handleChoice = useCallback((harness: string, choice: HarnessPostureChoice) => {
    if (state.kind !== "ready" || state.settings.harness_postures_locked === true) return;
    setError(null);
    setStatusMessage(null);
    if (choice === "watch") {
      setPendingWatch(harness);
      return;
    }
    setPendingWatch(null);
    if (gateEnabled) {
      const displayName = rows.find((row) => row.harness === harness)?.displayName ?? harness;
      setProofError(null);
      setProofRequest({ harness, displayName, choice });
      return;
    }
    void commit(harness, choice).then((failure) => {
      if (failure !== null) setError(failure);
    });
  }, [state, gateEnabled, rows, commit]);

  const handleConfirmWatch = useCallback((harness: string) => {
    setPendingWatch(null);
    if (gateEnabled) {
      const displayName = rows.find((row) => row.harness === harness)?.displayName ?? harness;
      setProofError(null);
      setProofRequest({ harness, displayName, choice: "watch" });
      return;
    }
    void commit(harness, "watch").then((failure) => {
      if (failure !== null) setError(failure);
    });
  }, [gateEnabled, rows, commit]);

  const handleProofConfirm = useCallback(async (proof: SettingsSaveProofCredentials) => {
    if (proofRequest === null) return;
    setProofPending(true);
    setProofError(null);
    const failure = await commit(proofRequest.harness, proofRequest.choice, proof);
    setProofPending(false);
    if (failure === null) {
      setProofRequest(null);
    } else {
      setProofError(failure);
    }
  }, [proofRequest, commit]);

  const handleCancelWatch = useCallback(() => setPendingWatch(null), []);

  if (state.kind === "loading") {
    return <div className="guard-skeleton h-14 w-full" aria-hidden="true" />;
  }
  if (state.kind === "error") {
    return (
      <p className="rounded-xl border border-slate-100 bg-white px-4 py-2.5 text-xs text-slate-500">
        App protection settings are unavailable right now.
      </p>
    );
  }
  // Nothing is intercepted yet: the coverage list and setup guide own that
  // story, and a posture switch here would protect nothing.
  if (rows.length === 0) return null;

  const locked = state.settings.harness_postures_locked === true;
  const watchingCount = rows.filter((row) => harnessRowTone(row) === "watch").length;
  const inactiveCount = fleetInactiveAppCount(props.apps);
  const pendingRow = pendingWatch !== null
    ? rows.find((row) => row.harness === pendingWatch)
    : undefined;

  return (
    <section
      className="overflow-hidden rounded-2xl border border-slate-100 bg-white"
      data-testid="fleet-app-protection"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 px-4 pb-2 pt-3">
        <SectionLabel>Protection by app</SectionLabel>
        <p className="text-xs text-slate-500">
          Machine:{" "}
          <span className="font-semibold text-brand-dark">{fleetMachinePostureLabel(state.settings)}</span>
          {watchingCount > 0 ? (
            <span className="font-semibold text-brand-attention"> · {watchingCount} in Watch</span>
          ) : null}
        </p>
      </div>

      {error !== null ? (
        <p role="alert" className="border-t border-brand-attention/20 bg-brand-attention/[0.05] px-4 py-2 text-xs text-brand-dark">
          {error}
        </p>
      ) : null}

      <ul className="divide-y divide-slate-100 border-t border-slate-100">
        {rows.map((row) => {
          const tone = harnessRowTone(row);
          const saving = savingHarness === row.harness;
          const options = harnessPostureOptions(state.settings, row.harness);
          return (
            <Fragment key={row.harness}>
              <li
                className={`flex flex-col gap-2 px-4 py-2.5 sm:flex-row sm:items-center sm:justify-between ${
                  tone === "watch" ? "bg-brand-attention/[0.05]" : ""
                }`}
                data-harness={row.harness}
              >
                <div className="flex min-w-0 items-center gap-2">
                  {tone === "watch"
                    ? <HiMiniEye className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
                    : <HiMiniShieldCheck className="h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />}
                  <span className="truncate text-sm font-semibold text-brand-dark">{row.displayName}</span>
                  <span className="hidden truncate text-xs text-slate-400 lg:inline">{harnessRowStatus(row)}</span>
                  {saving ? <span className="text-xs text-slate-400">Saving…</span> : null}
                </div>
                <fieldset className="border-0 p-0">
                  <legend className="sr-only">{`Protection for ${row.displayName}`}</legend>
                  <div className="inline-flex gap-1 rounded-xl bg-slate-100 p-1">
                    {options.map((option) => (
                      <HarnessPostureChoiceLabel
                        key={option.choice}
                        groupName={`fleet-posture-${row.harness}`}
                        choice={option.choice}
                        label={option.label}
                        selected={row.selected === option.choice}
                        disabled={locked || saving}
                        harness={row.harness}
                        onChoose={handleChoice}
                        compact
                      />
                    ))}
                  </div>
                </fieldset>
              </li>
              {pendingRow?.harness === row.harness ? (
                <li
                  className="bg-brand-attention/[0.06]"
                  role="alertdialog"
                  aria-label={`Switch ${pendingRow.displayName} to Watch`}
                >
                  <div className="flex flex-col gap-2 px-4 py-2.5 sm:flex-row sm:items-center sm:justify-between">
                    <p className="text-sm text-brand-dark">
                      Guard will only record in {pendingRow.displayName} until you switch it back.
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => handleConfirmWatch(pendingRow.harness)}
                        className="inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white"
                      >
                        Switch to Watch
                      </button>
                      <button
                        type="button"
                        onClick={handleCancelWatch}
                        className="inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark"
                      >
                        Keep protection on
                      </button>
                    </div>
                  </div>
                </li>
              ) : null}
            </Fragment>
          );
        })}
      </ul>

      {inactiveCount > 0 ? (
        <p className="border-t border-slate-100 px-4 py-2 text-xs text-slate-400">
          {inactiveCount === 1
            ? "1 more app isn't connected yet — see App coverage below."
            : `${inactiveCount} more apps aren't connected yet — see App coverage below.`}
        </p>
      ) : null}

      {locked ? (
        <p className="border-t border-slate-100 px-4 py-2 text-xs text-slate-400">
          Your organization manages protection for each app, so these choices can't be changed here.
        </p>
      ) : null}

      <div aria-live="polite" aria-atomic="true" className="sr-only">{statusMessage ?? ""}</div>

      {proofRequest !== null ? (
        <SettingsSaveProofModal
          open
          mode="verify-save"
          gate={gate}
          title="Confirm before changing protection"
          detail={`Enter your approval proof to switch ${proofRequest.displayName}.`}
          confirmLabel="Save change"
          error={proofError}
          pending={proofPending}
          onCancel={() => {
            if (proofPending) return;
            setProofRequest(null);
            setProofError(null);
          }}
          onConfirm={handleProofConfirm}
        />
      ) : null}
    </section>
  );
}
