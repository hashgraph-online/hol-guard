import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";

import { harnessDisplayName } from "./approval-center-utils";
import { fetchSettings, updateSettings, type GuardSettingsUpdate } from "./guard-api";
import type { GuardApprovalGatePublicConfig, GuardProtectionCapability, GuardSettings } from "./guard-types";
import {
  globalPosture,
  harnessPostureOptions,
  harnessPosturePatch,
  harnessPostureRows,
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

type FleetAppPostureOptions = {
  apps: FleetPostureApp[];
  /** Called after a saved posture change so the parent can refresh the runtime snapshot. */
  onChanged?: () => Promise<void> | void;
};

export type FleetAppPosture = {
  kind: FleetPostureState["kind"];
  /** Posture row for an app Guard manages, or undefined when its hooks are not Guard's. */
  rowFor: (harness: string) => HarnessPostureRow | undefined;
  /** The per-app choice for one managed app, or null when it has none. */
  control: (harness: string) => ReactNode;
  /** Inline Watch confirmation under the app it affects, or null. */
  watchConfirm: (harness: string) => ReactNode;
  /** Machine posture and Watch count for the section header, or null before settings load. */
  summary: ReactNode;
  /** Save errors, the organization lock note, the live region and the proof modal. */
  footer: ReactNode;
};

/**
 * Per-app protection for the Protect screen's App coverage list. Only apps
 * whose hooks Guard actually manages get a choice, so the list never claims
 * Protected for an app that is not intercepted. Choices save right away; Watch
 * confirms inline first and the approval gate uses the existing proof modal.
 */
export function useFleetAppPosture(props: FleetAppPostureOptions): FleetAppPosture {
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

  const rowFor = useCallback((harness: string) => rows.find((row) => row.harness === harness), [rows]);

  if (state.kind !== "ready") {
    return {
      kind: state.kind,
      rowFor,
      control: () => null,
      watchConfirm: () => null,
      summary: null,
      footer: state.kind === "error" ? (
        <p className="mt-3 text-xs text-slate-500">Per-app protection settings are unavailable right now.</p>
      ) : null,
    };
  }

  const settings = state.settings;
  const locked = settings.harness_postures_locked === true;
  const watchingCount = rows.filter((row) => harnessRowTone(row) === "watch").length;

  const control = (harness: string): ReactNode => {
    const row = rowFor(harness);
    if (!row) return null;
    const saving = savingHarness === harness;
    return (
      <fieldset className="flex shrink-0 items-center gap-2 border-0 p-0" data-testid="fleet-app-posture">
        <legend className="sr-only">{`Protection for ${row.displayName}`}</legend>
        <div className="inline-flex items-center gap-1 rounded-xl bg-slate-100 p-1">
          {harnessPostureOptions(settings, harness).map((option) => (
            <HarnessPostureChoiceLabel
              key={option.choice}
              groupName={`fleet-posture-${harness}`}
              choice={option.choice}
              label={option.label}
              selected={row.selected === option.choice}
              disabled={locked || saving}
              harness={harness}
              onChoose={handleChoice}
              compact
            />
          ))}
        </div>
        {saving ? <span className="text-xs font-medium text-slate-500">Saving…</span> : null}
      </fieldset>
    );
  };

  const watchConfirm = (harness: string): ReactNode => {
    if (pendingWatch !== harness) return null;
    const row = rowFor(harness);
    if (!row) return null;
    return (
      <div
        className="mt-2 flex flex-col gap-2 rounded-xl bg-brand-attention/[0.06] px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between"
        role="alertdialog"
        aria-label={`Switch ${row.displayName} to Watch`}
      >
        <p className="text-sm text-brand-dark">
          Guard will only record in {row.displayName} until you switch it back.
        </p>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => handleConfirmWatch(harness)}
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
    );
  };

  const summary = rows.length === 0 ? null : (
    <p className="text-xs text-slate-500" data-testid="fleet-machine-posture">
      Machine:{" "}
      <span className="font-semibold text-brand-dark">{fleetMachinePostureLabel(settings)}</span>
      {watchingCount > 0 ? (
        <span className="font-semibold text-brand-attention"> · {watchingCount} in Watch</span>
      ) : null}
    </p>
  );

  const footer = (
    <>
      {error !== null ? (
        <p role="alert" className="mt-3 rounded-lg bg-brand-attention/[0.05] px-3 py-2 text-xs text-brand-dark">
          {error}
        </p>
      ) : null}
      {locked && rows.length > 0 ? (
        <p className="mt-3 text-xs text-slate-400">
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
    </>
  );

  return { kind: "ready", rowFor, control, watchConfirm, summary, footer };
}
