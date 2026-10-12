import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { HiMiniEye, HiMiniShieldCheck } from "react-icons/hi2";

import { SectionLabel } from "./approval-center-primitives";
import { fetchSettings, updateSettings, type GuardSettingsUpdate } from "./guard-api";
import type { GuardApprovalGatePublicConfig, GuardProtectionCapability, GuardSettings } from "./guard-types";
import {
  harnessPostureOptions,
  harnessPosturePatch,
  harnessPostureRows,
  harnessRowStatus,
  harnessRowTone,
  selectHarnessPosture,
  sortHarnessRows,
  type HarnessPostureChoice,
} from "./harness-posture-ui";
import { HarnessPostureChoiceLabel } from "./harness-posture-card";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "./settings-save-proof-modal";

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
  /** Called after a saved posture change so the parent can refresh the runtime snapshot. */
  onChanged?: () => void;
};

/**
 * Quick per-app protection control for the Protect screen. Unlike the Apps
 * settings tab there is no draft: a choice here saves right away, and Watch
 * still confirms first because it stops Guard from blocking.
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

  const rows = useMemo(
    () => state.kind === "ready" ? sortHarnessRows(harnessPostureRows(state.settings, state.capabilities)) : [],
    [state],
  );

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
      const name = state.capabilities.find((item) => item.harness === harness)?.display_name ?? harness;
      setStatusMessage(fleetPostureStatusMessage(choice, name));
      setPendingWatch(null);
      onChanged?.();
      return null;
    } catch (cause: unknown) {
      return cause instanceof Error ? cause.message : "Unable to change protection for this app.";
    } finally {
      setSavingHarness(null);
    }
  }, [state, gateEnabled, onChanged]);

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
    return <div className="guard-skeleton h-24 w-full" aria-hidden="true" />;
  }
  if (state.kind === "error") {
    return (
      <p className="rounded-xl border border-slate-100 bg-white px-4 py-3 text-sm text-slate-500">
        {state.message}
      </p>
    );
  }
  if (rows.length === 0) return null;

  const locked = state.settings.harness_postures_locked === true;
  const pendingRow = pendingWatch !== null
    ? rows.find((row) => row.harness === pendingWatch)
    : undefined;

  return (
    <section className="space-y-3" data-testid="fleet-app-protection">
      <div>
        <SectionLabel>Protection by app</SectionLabel>
        <p className="mt-1 text-sm text-slate-500">
          Set Watch for one app while you debug it. Changes here apply right away.
        </p>
      </div>

      {locked ? (
        <p className="text-sm text-slate-500">
          Your organization manages protection for each app, so these choices can't be changed here.
        </p>
      ) : null}

      {error !== null ? (
        <p role="alert" className="rounded-xl border border-brand-attention/30 bg-brand-attention/[0.06] px-4 py-3 text-sm text-brand-dark">
          {error}
        </p>
      ) : null}
      <div aria-live="polite" aria-atomic="true" className="sr-only">{statusMessage ?? ""}</div>

      <ul className="divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white">
        {rows.map((row) => {
          const tone = harnessRowTone(row);
          const saving = savingHarness === row.harness;
          const options = harnessPostureOptions(state.settings, row.harness);
          return (
            <Fragment key={row.harness}>
              <li className={tone === "watch" ? "bg-brand-attention/[0.04]" : undefined} data-harness={row.harness}>
                <div className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-semibold text-brand-dark">
                      {tone === "watch"
                        ? <HiMiniEye className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
                        : <HiMiniShieldCheck className="h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />}
                      {row.displayName}
                    </p>
                    <p className="mt-0.5 text-xs text-slate-500">{harnessRowStatus(row)}</p>
                    {saving ? <p className="mt-0.5 text-xs text-slate-400">Saving…</p> : null}
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
                        />
                      ))}
                    </div>
                  </fieldset>
                </div>
              </li>
              {pendingRow?.harness === row.harness ? (
                <li
                  className="bg-brand-attention/[0.06]"
                  role="alertdialog"
                  aria-label={`Switch ${pendingRow.displayName} to Watch`}
                >
                  <div className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
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
