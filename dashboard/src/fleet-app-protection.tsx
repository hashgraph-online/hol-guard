import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";

import { harnessDisplayName } from "./approval-center-utils";
import { fetchSettings, guardAwareHref, updateSettings } from "./guard-api";
import type { GuardApprovalGatePublicConfig, GuardProtectionCapability, GuardSettings } from "./guard-types";
import {
  globalPosture,
  harnessPostureRows,
  harnessRowTone,
  type HarnessPostureChoice,
  type HarnessPostureRow,
} from "./harness-posture-ui";
import {
  appModes,
  appModesStatusMessage,
  appModesUpdate,
  cigarUnavailableReason,
  cigarReady,
  cigarSupported,
  guardOffPrompt,
  needsConfirm,
  type AppModes,
} from "./fleet-app-modes";
import { FleetAppModeSwitch } from "./fleet-app-mode-switch";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "./settings-save-proof-modal";
import { PROTECTION_POSTURE_COPY, type ProtectionPosture } from "./protection-posture-copy";

/** One app the Protect screen knows about: its id and whether Guard manages its hooks. */
export type FleetPostureApp = { harness: string; active: boolean };

type FleetPostureState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; settings: GuardSettings; capabilities: GuardProtectionCapability[] };

type ModeChange = {
  harness: string;
  next: AppModes;
};

type ProofRequest = ModeChange & { displayName: string };

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
  /** The per-app Guard and CIGAR switches for one managed app, or null when it has none. */
  control: (harness: string) => ReactNode;
  /** Inline confirmation for turning Guard off, under the app it affects, or null. */
  watchConfirm: (harness: string) => ReactNode;
  /** Machine posture and Watch count for the section header, or null before settings load. */
  summary: ReactNode;
  /** Settings as last loaded or saved, for row notes; null before they load. */
  settings: GuardSettings | null;
  /** Save errors, the organization lock note, the live region and the proof modal. */
  footer: ReactNode;
};

/**
 * Per-app Guard and CIGAR for the Protect screen's App coverage list. Only
 * apps whose hooks Guard actually manages get switches, so the list never
 * claims Protected for an app that is not intercepted. Changes save right
 * away; turning Guard off confirms inline first and the approval gate uses
 * the existing proof modal.
 */
export function useFleetAppPosture(props: FleetAppPostureOptions): FleetAppPosture {
  const { onChanged } = props;
  const [state, setState] = useState<FleetPostureState>({ kind: "loading" });
  const [pendingWatch, setPendingWatch] = useState<ModeChange | null>(null);
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

  const commit = useCallback(async (harness: string, next: AppModes, proof?: SettingsSaveProofCredentials): Promise<string | null> => {
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
      setState((current) => current.kind === "ready"
        ? { ...current, settings: payload.settings }
        : current);
      const name = rows.find((row) => row.harness === harness)?.displayName ?? harness;
      setStatusMessage(appModesStatusMessage(next, name));
      setPendingWatch(null);
      onChanged?.();
      return null;
    } catch (cause: unknown) {
      return cause instanceof Error ? cause.message : "Unable to change Guard or CIGAR for this app.";
    } finally {
      setSavingHarness(null);
    }
  }, [state, gateEnabled, rows, onChanged]);

  const save = useCallback((change: ModeChange) => {
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

  const handleToggle = useCallback((harness: string, part: keyof AppModes) => {
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

  const handleConfirmWatch = useCallback((change: ModeChange) => {
    setPendingWatch(null);
    save(change);
  }, [save]);

  const handleProofConfirm = useCallback(async (proof: SettingsSaveProofCredentials) => {
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

  const handleCancelWatch = useCallback(() => setPendingWatch(null), []);

  const rowFor = useCallback((harness: string) => rows.find((row) => row.harness === harness), [rows]);

  if (state.kind !== "ready") {
    return {
      kind: state.kind,
      rowFor,
      control: () => null,
      watchConfirm: () => null,
      summary: null,
      settings: null,
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
    const modes = appModes(settings, harness);
    const cigarReason = cigarUnavailableReason(settings, harness, row.displayName);
    return (
      <div
        role="group"
        aria-label={`Guard and CIGAR in ${row.displayName}`}
        className="flex shrink-0 items-center gap-3"
        data-testid="fleet-app-modes"
      >
        <FleetAppModeSwitch
          label="Guard"
          accessibleName={`Guard in ${row.displayName}`}
          checked={modes.guard}
          disabled={saving || locked}
          unavailableReason={locked ? "Your organization manages protection for this app." : undefined}
          attentionWhenOff
          onToggle={() => handleToggle(harness, "guard")}
          testId={`fleet-app-guard-${harness}`}
        />
        <FleetAppModeSwitch
          label="CIGAR"
          accessibleName={`CIGAR in ${row.displayName}`}
          checked={modes.cigar}
          disabled={saving || cigarReason !== undefined}
          unavailableReason={cigarReason}
          onToggle={() => handleToggle(harness, "cigar")}
          testId={`fleet-app-cigar-${harness}`}
        />
        {saving ? <span className="text-xs font-medium text-slate-500">Saving…</span> : null}
      </div>
    );
  };

  const watchConfirm = (harness: string): ReactNode => {
    if (pendingWatch?.harness !== harness) return null;
    const row = rowFor(harness);
    if (!row) return null;
    const change = pendingWatch;
    const guardWasOn = appModes(settings, harness).guard;
    const confirmLabel = guardWasOn ? "Turn Guard off" : "Keep CIGAR only";
    return (
      <div
        className="mt-2 flex flex-col gap-2 rounded-xl bg-brand-attention/[0.06] px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between"
        role="alertdialog"
        aria-label={guardWasOn ? `Turn Guard off in ${row.displayName}` : `Keep only CIGAR in ${row.displayName}`}
      >
        <p className="text-sm text-brand-dark">
          {guardOffPrompt(settings, harness, change.next, row.displayName)}
        </p>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => handleConfirmWatch(change)}
            className="inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white"
          >
            {confirmLabel}
          </button>
          <button
            type="button"
            onClick={handleCancelWatch}
            className="inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark"
          >
            {guardWasOn ? "Keep Guard on" : "Cancel"}
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
        <span className="font-semibold text-brand-attention"> · Guard off in {watchingCount}</span>
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
      {!cigarReady(settings) && rows.some((row) => cigarSupported(row.harness)) ? (
        <p className="mt-3 text-xs text-slate-500" data-testid="fleet-cigar-setup">
          CIGAR is off on this machine, so it can't add project context or save tokens in any app yet.{" "}
          <a className="font-medium text-brand-blue underline underline-offset-2" href={guardAwareHref("/cigar")}>
            Set up CIGAR
          </a>
        </p>
      ) : null}
      {locked && rows.length > 0 ? (
        <p className="mt-3 text-xs text-slate-400">
          Your organization manages Guard for each app, so Guard can't be turned on or off here. CIGAR can still be changed.
        </p>
      ) : null}
      <div aria-live="polite" aria-atomic="true" className="sr-only">{statusMessage ?? ""}</div>
      {proofRequest !== null ? (
        <SettingsSaveProofModal
          open
          mode="verify-save"
          gate={gate}
          title="Confirm before changing Guard or CIGAR"
          detail={`Enter your approval proof to change ${proofRequest.displayName}.`}
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

  return { kind: "ready", rowFor, control, watchConfirm, summary, settings, footer };
}
