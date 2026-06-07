import { useCallback, useEffect, useRef, useState } from "react";
import { HiMiniArrowPath } from "react-icons/hi2";

import {
  fetchGuardUpdateStatus,
  reconnectGuardDaemonAfterUpdate,
  scheduleGuardUpdate,
} from "./guard-api";
import type { GuardUpdatePhase, GuardUpdateStatus } from "./guard-types";

const UPDATE_STATUS_POLL_MS = 60_000;
const RECONNECT_POLL_MS = 1_500;
const RECONNECT_TIMEOUT_MS = 180_000;

export type GuardUpdatePanelProps = {
  guardVersion?: string | null;
  updateStatus?: GuardUpdateStatus | null;
  updatePhase?: GuardUpdatePhase;
  onUpdateGuard?: () => void;
  compact?: boolean;
};

function updateStatusLabel(status: GuardUpdateStatus | null | undefined): string {
  if (!status) {
    return "Checking version…";
  }
  if (status.update_available && status.latest_version) {
    return `Version ${status.latest_version} is ready`;
  }
  return `Version ${status.current_version}`;
}

function updateHelpCopy(status: GuardUpdateStatus | null | undefined, phase: GuardUpdatePhase): string | null {
  if (phase === "updating") {
    return "Guard is installing the update. The dashboard will pause briefly and reopen when ready.";
  }
  if (phase === "reconnecting") {
    return "Reconnecting to Guard after the update…";
  }
  if (phase === "error") {
    return "The update did not finish. Try again or run hol-guard update from your terminal.";
  }
  if (status?.update_available) {
    return "This restarts Guard for a moment. Open approvals will stay saved.";
  }
  if (status && !status.auto_updatable && status.blocked_reason) {
    return status.blocked_reason;
  }
  return null;
}

export function GuardUpdatePanel(props: GuardUpdatePanelProps) {
  const version = props.guardVersion ?? props.updateStatus?.current_version ?? null;
  const phase = props.updatePhase ?? "idle";
  const helpCopy = updateHelpCopy(props.updateStatus, phase);
  const showUpdateButton =
    props.updateStatus?.update_available === true &&
    props.updateStatus.auto_updatable &&
    phase !== "updating" &&
    phase !== "reconnecting";

  return (
    <div className={props.compact ? "space-y-1" : "space-y-2"}>
      {version ? (
        <p className="font-mono text-[10px] text-brand-dark/60" aria-label={`Guard version ${version}`}>
          v{version}
        </p>
      ) : null}
      {props.updateStatus?.update_available ? (
        <p className="text-[11px] leading-relaxed text-brand-dark/75">{updateStatusLabel(props.updateStatus)}</p>
      ) : null}
      {helpCopy ? (
        <p className="text-[11px] leading-relaxed text-brand-dark/70">{helpCopy}</p>
      ) : null}
      {showUpdateButton && props.onUpdateGuard ? (
        <button
          type="button"
          onClick={props.onUpdateGuard}
          className="inline-flex min-h-11 w-full items-center justify-center gap-1.5 rounded-lg border border-brand-blue/30 bg-white px-3 py-2 text-sm font-semibold text-brand-blue transition-colors hover:bg-brand-blue/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40"
        >
          <HiMiniArrowPath className="h-4 w-4 shrink-0" aria-hidden="true" />
          Update Guard
        </button>
      ) : null}
      {(phase === "updating" || phase === "reconnecting") && (
        <p className="inline-flex min-h-11 items-center gap-2 text-[11px] font-medium text-brand-blue" role="status">
          <HiMiniArrowPath className="h-4 w-4 animate-spin" aria-hidden="true" />
          {phase === "updating" ? "Updating Guard…" : "Reconnecting…"}
        </p>
      )}
    </div>
  );
}

export function useGuardUpdate(options?: { onReconnected?: () => void }) {
  const [updateStatus, setUpdateStatus] = useState<GuardUpdateStatus | null>(null);
  const [updatePhase, setUpdatePhase] = useState<GuardUpdatePhase>("checking");
  const reconnectStartedAt = useRef<number | null>(null);
  const updatePhaseRef = useRef<GuardUpdatePhase>("checking");

  useEffect(() => {
    updatePhaseRef.current = updatePhase;
  }, [updatePhase]);

  const refreshUpdateStatus = useCallback(async () => {
    try {
      const status = await fetchGuardUpdateStatus();
      setUpdateStatus(status);
      if (updatePhaseRef.current === "checking" || updatePhaseRef.current === "idle") {
        setUpdatePhase("idle");
      }
    } catch {
      if (updatePhaseRef.current === "checking") {
        setUpdatePhase("idle");
      }
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    void fetchGuardUpdateStatus()
      .then((status) => {
        if (!cancelled && (updatePhaseRef.current === "checking" || updatePhaseRef.current === "idle")) {
          setUpdateStatus(status);
          setUpdatePhase("idle");
        }
      })
      .catch(() => {
        if (!cancelled && updatePhaseRef.current === "checking") {
          setUpdatePhase("idle");
        }
      });
    const pollId = window.setInterval(() => {
      if (updatePhaseRef.current === "updating" || updatePhaseRef.current === "reconnecting") {
        return;
      }
      void refreshUpdateStatus();
    }, UPDATE_STATUS_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(pollId);
    };
  }, [refreshUpdateStatus]);

  const waitForReconnect = useCallback(
    async (expectedPreviousVersion: string, expectedLatestVersion: string | null): Promise<boolean> => {
      reconnectStartedAt.current = Date.now();
      while (Date.now() - (reconnectStartedAt.current ?? Date.now()) < RECONNECT_TIMEOUT_MS) {
        try {
          const origin = await reconnectGuardDaemonAfterUpdate({
            expectedPreviousVersion,
            expectedLatestVersion,
          });
          if (!origin) {
            throw new Error("Guard daemon not found");
          }
          if (origin !== window.location.origin) {
            return true;
          }
          const status = await fetchGuardUpdateStatus();
          setUpdateStatus(status);
          setUpdatePhase("idle");
          options?.onReconnected?.();
          return false;
        } catch {
          await new Promise<void>((resolve) => window.setTimeout(resolve, RECONNECT_POLL_MS));
        }
      }
      setUpdatePhase("error");
      throw new Error("Guard did not reconnect after the update.");
    },
    [options],
  );

  const onUpdateGuard = useCallback(async () => {
    if (!updateStatus?.update_available || !updateStatus.auto_updatable) {
      return;
    }
    const expectedPreviousVersion = updateStatus.current_version;
    const expectedLatestVersion = updateStatus.latest_version;
    setUpdatePhase("updating");
    try {
      const scheduleResult = await scheduleGuardUpdate();
      if (scheduleResult.scheduled === false && scheduleResult.error === "update_in_progress") {
        setUpdatePhase("reconnecting");
        const redirected = await waitForReconnect(expectedPreviousVersion, expectedLatestVersion);
        if (!redirected) {
          window.location.reload();
        }
        return;
      }
      if (scheduleResult.scheduled !== true) {
        throw new Error(scheduleResult.message ?? scheduleResult.error ?? "Guard update was not scheduled.");
      }
      setUpdatePhase("reconnecting");
      const redirected = await waitForReconnect(expectedPreviousVersion, expectedLatestVersion);
      if (!redirected) {
        window.location.reload();
      }
    } catch {
      setUpdatePhase("error");
    }
  }, [updateStatus, waitForReconnect]);

  return {
    guardVersion: updateStatus?.current_version ?? null,
    updateStatus,
    updatePhase,
    onUpdateGuard,
    refreshUpdateStatus,
  };
}
