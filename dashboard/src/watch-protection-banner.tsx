import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { HiMiniCheckCircle, HiMiniExclamationTriangle } from "react-icons/hi2";
import { fetchSettings, updateSettings } from "./guard-api";
import type { GuardApprovalGatePublicConfig, GuardSettings, GuardSettingsPayload } from "./guard-types";
import type { WatchBannerModel } from "./harness-posture-ui";
import { WATCH_BANNER_COPY } from "./protection-posture-copy";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "./settings-save-proof-modal";
import {
  finishTurnProtectionOn,
  startTurnProtectionOn,
  turnProtectionOnErrorMessage,
  type TurnProtectionOnDeps,
} from "./turn-protection-on-flow";

type WatchProtectionBannerProps = {
  /** Names which apps are in Watch. Without it the banner describes the whole machine. */
  model?: WatchBannerModel | null;
  /**
   * Called once Guard has saved the change, with the saved settings (null when
   * nothing was left in Watch). Refresh whatever drew the banner here.
   */
  onTurnedOn?: (payload: GuardSettingsPayload | null) => void | Promise<void>;
  /** Offered only after a failure, as a way to finish the change by hand. */
  onOpenSettings?: () => void;
  /**
   * True while the host page is saving its own changes. The banner will not
   * start a save then, so two writes never race.
   */
  disabled?: boolean;
  /** Reports when the banner is saving or waiting for approval, so the host can hold its own save. */
  onBusyChange?: (busy: boolean) => void;
  /** Test seam; defaults to the Guard API. */
  deps?: TurnProtectionOnDeps;
  /** Test seam for rendering a given step; defaults to idle. */
  initialState?: WatchBannerState;
};

export type WatchBannerState =
  | { kind: "idle" }
  | { kind: "confirming" }
  | { kind: "working" }
  | { kind: "proof"; settings: GuardSettings; gate: GuardApprovalGatePublicConfig; pending: boolean; error: string | null }
  | { kind: "error"; message: string }
  | { kind: "locked" }
  | { kind: "done" };

const DEFAULT_CONFIRM = "Guard will start stopping dangerous actions.";
const DEFAULT_DEPS: TurnProtectionOnDeps = { fetchSettings, updateSettings };
const LOCKED_COPY = "Your organization manages protection for these apps, so it can't be turned on here.";
const DONE_COPY = "Protection is on. Guard will stop dangerous actions again.";

const FOCUS_RING = "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-attention";
const PRIMARY_BUTTON = `inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-70 ${FOCUS_RING}`;
const SECONDARY_BUTTON = `inline-flex min-h-11 items-center justify-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark ${FOCUS_RING}`;

/**
 * Tells the user Guard is only recording, and turns protection back on right
 * here: one confirm, the approval gate's password and code when the gate is
 * on, then a saved change. It never sends the user to Settings to finish.
 */
export function WatchProtectionBanner(props: WatchProtectionBannerProps) {
  const { onTurnedOn, onOpenSettings, onBusyChange } = props;
  const disabled = props.disabled === true;
  const deps = props.deps ?? DEFAULT_DEPS;
  const [state, setState] = useState<WatchBannerState>(props.initialState ?? { kind: "idle" });
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const busy = state.kind === "working" || state.kind === "proof";
  useEffect(() => {
    onBusyChange?.(busy);
  }, [busy, onBusyChange]);
  useEffect(() => () => onBusyChange?.(false), [onBusyChange]);

  const settle = useCallback(async (payload: GuardSettingsPayload | null) => {
    if (mounted.current) setState({ kind: "done" });
    await onTurnedOn?.(payload);
  }, [onTurnedOn]);

  const handleAsk = useCallback(() => setState({ kind: "confirming" }), []);
  const handleCancel = useCallback(() => setState({ kind: "idle" }), []);

  const handleConfirm = useCallback(async () => {
    if (disabled) return;
    setState({ kind: "working" });
    try {
      const step = await startTurnProtectionOn(deps);
      if (!mounted.current) return;
      if (step.kind === "locked") {
        setState({ kind: "locked" });
      } else if (step.kind === "needs-proof") {
        setState({ kind: "proof", settings: step.settings, gate: step.gate, pending: false, error: null });
      } else {
        await settle(step.payload);
      }
    } catch (cause) {
      if (mounted.current) setState({ kind: "error", message: turnProtectionOnErrorMessage(cause) });
    }
  }, [deps, disabled, settle]);

  const handleProofCancel = useCallback(() => {
    setState((current) => (current.kind === "proof" && current.pending ? current : { kind: "idle" }));
  }, []);

  const handleProofConfirm = useCallback(async (proof: SettingsSaveProofCredentials) => {
    if (state.kind !== "proof" || state.pending) return;
    const { settings, gate } = state;
    setState({ kind: "proof", settings, gate, pending: true, error: null });
    try {
      const payload = await finishTurnProtectionOn(deps, settings, proof);
      await settle(payload);
    } catch (cause) {
      if (mounted.current) {
        setState({ kind: "proof", settings, gate, pending: false, error: turnProtectionOnErrorMessage(cause) });
      }
    }
  }, [deps, settle, state]);

  if (state.kind === "done") {
    return (
      <div
        className="flex items-center gap-3 rounded-xl border border-brand-green/25 bg-brand-green/[0.04] px-4 py-3"
        role="status"
        data-testid="watch-protection-banner"
      >
        <HiMiniCheckCircle className="h-5 w-5 shrink-0 text-brand-green-text" aria-hidden="true" />
        <p className="text-sm font-semibold text-brand-dark">{DONE_COPY}</p>
      </div>
    );
  }

  const message = props.model?.message ?? WATCH_BANNER_COPY;
  const confirmMessage = props.model?.confirmMessage ?? DEFAULT_CONFIRM;
  const perApp = props.model !== undefined && props.model !== null && !props.model.globalWatch;
  const actionLabel = perApp ? "Turn protection on for these apps" : "Turn protection on";

  let detail: ReactNode = null;
  let action: ReactNode;
  switch (state.kind) {
    case "confirming":
      detail = <p className="mt-1 text-sm text-slate-600">{confirmMessage}</p>;
      action = (
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void handleConfirm()} disabled={disabled} className={PRIMARY_BUTTON}>
            Turn on
          </button>
          <button type="button" onClick={handleCancel} className={SECONDARY_BUTTON}>
            Not now
          </button>
        </div>
      );
      break;
    case "working":
    case "proof":
      detail = <p className="mt-1 text-sm text-slate-600">{confirmMessage}</p>;
      action = (
        <button type="button" disabled aria-busy="true" className={PRIMARY_BUTTON}>
          {state.kind === "proof" ? "Waiting for approval…" : "Turning on…"}
        </button>
      );
      break;
    case "error":
      detail = (
        <p role="alert" className="mt-1 text-sm text-slate-600">
          {state.message}
        </p>
      );
      action = (
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void handleConfirm()} disabled={disabled} className={PRIMARY_BUTTON}>
            Try again
          </button>
          {onOpenSettings !== undefined ? (
            <button type="button" onClick={onOpenSettings} className={SECONDARY_BUTTON}>
              Open settings
            </button>
          ) : null}
        </div>
      );
      break;
    case "locked":
      detail = <p className="mt-1 text-sm text-slate-600">{LOCKED_COPY}</p>;
      action = null;
      break;
    default:
      action = (
        <button type="button" onClick={handleAsk} disabled={disabled} className={PRIMARY_BUTTON}>
          {actionLabel}
        </button>
      );
  }

  return (
    <div
      className="flex flex-col gap-3 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.06] px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
      role="status"
      data-testid="watch-protection-banner"
    >
      <div className="flex items-start gap-3">
        <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
        <div>
          <p className="text-sm font-semibold text-brand-dark">{message}</p>
          {detail}
        </div>
      </div>
      {action}
      {state.kind === "proof" ? (
        <SettingsSaveProofModal
          open
          mode="verify-save"
          gate={state.gate}
          title="Confirm turning protection on"
          detail={confirmMessage}
          confirmLabel="Turn protection on"
          error={state.error}
          pending={state.pending}
          onCancel={handleProofCancel}
          onConfirm={(proof) => void handleProofConfirm(proof)}
        />
      ) : null}
    </div>
  );
}
