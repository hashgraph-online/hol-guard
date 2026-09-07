import { useCallback, useEffect, useRef, useState, type ChangeEvent, type ReactNode } from "react";
import { HiMiniArrowPath } from "react-icons/hi2";

import {
  fetchGuardUpdateStatus,
  prepareGuardDaemonReconnect,
  readRememberedGuardUpdateChannel,
  reconnectGuardDaemonAfterUpdate,
  readGuardToken,
  redirectToGuardDaemonOrigin,
  scheduleGuardUpdate,
  setGuardUpdateChannel,
  type GuardUpdateChannelProof,
} from "./guard-api";
import { AlphaChannelDialog } from "./alpha-update-channel-dialog";
import { dashboardEmbedsInDesktop } from "./desktop-embed";
import { shouldPromptRecoveryReinstall, updateHelpCopy, updateStatusLabel } from "./guard-update-copy";
import { buildApprovalProofCredentials } from "./approval-proof-inline";
import type {
  GuardApprovalGatePublicConfig,
  GuardDaemonReconnectAuthorization,
  GuardUpdatePhase,
  GuardUpdateStatus,
} from "./guard-types";
import { GuardModalLayer } from "./guard-modal-layer";
import {
  GuardUpdateChannelSummary,
  GUARD_UPDATE_ACTION_BUTTON_CLASS,
} from "./guard-update-channel-summary";

const UPDATE_STATUS_POLL_MS = 60_000;
const RECONNECT_POLL_MS = 1_500;
const RECONNECT_TIMEOUT_MS = 180_000;

export type GuardUpdatePanelProps = {
  guardVersion?: string | null;
  updateStatus?: GuardUpdateStatus | null;
  updatePhase?: GuardUpdatePhase;
  updateError?: string | null;
  onUpdateGuard?: () => void;
  onReinstallGuard?: () => void;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onSetUpdateChannel?: (channel: "stable" | "alpha", proof?: GuardUpdateChannelProof) => void | Promise<void>;
  compact?: boolean;
};

export function GuardUpdatePanel(props: GuardUpdatePanelProps) {
  const version = props.guardVersion ?? props.updateStatus?.current_version ?? null;
  const phase = props.updatePhase ?? "idle";
  const embeddedInDesktop = dashboardEmbedsInDesktop();
  const helpCopy = updateHelpCopy(props.updateStatus, phase, props.updateError, embeddedInDesktop);
  // Inside the Desktop window, updates belong to the app's own updater;
  // a second button here would race it against the same runtime.
  const showUpdateButton =
    !embeddedInDesktop &&
    props.updateStatus?.update_available === true &&
    props.updateStatus.auto_updatable &&
    props.updateStatus.update_suppressed !== true &&
    phase !== "updating" &&
    phase !== "reconnecting";
  const showReinstallButton =
    !embeddedInDesktop &&
    shouldPromptRecoveryReinstall(props.updateStatus) &&
    phase !== "updating" &&
    phase !== "reconnecting";
  const busy = phase === "updating" || phase === "reconnecting";
  const useAlpha = props.updateStatus?.release_channel === "alpha" || (
    props.updateStatus == null && readRememberedGuardUpdateChannel() === "alpha"
  );
  const [alphaModalOpen, setAlphaModalOpen] = useState(false);
  const [alphaSavePending, setAlphaSavePending] = useState(false);
  const [alphaSaveError, setAlphaSaveError] = useState<string | null>(null);
  const [alphaApprovalPassword, setAlphaApprovalPassword] = useState("");
  const [alphaApprovalTotpCode, setAlphaApprovalTotpCode] = useState("");
  const targetChannel = useAlpha ? "stable" : "alpha";
  const modalTitle = useAlpha ? "Return to stable updates" : "Try alpha updates";

  const handleOpenAlphaModal = useCallback(() => {
    setAlphaSaveError(null);
    setAlphaApprovalPassword("");
    setAlphaApprovalTotpCode("");
    setAlphaModalOpen(true);
  }, []);
  const handleCloseAlphaModal = useCallback(() => {
    if (alphaSavePending) {
      return;
    }
    setAlphaModalOpen(false);
    setAlphaSaveError(null);
    setAlphaApprovalPassword("");
    setAlphaApprovalTotpCode("");
  }, [alphaSavePending]);
  const handleConfirmAlphaChannel = useCallback(async () => {
    if (!props.onSetUpdateChannel) {
      return;
    }
    setAlphaSavePending(true);
    setAlphaSaveError(null);
    try {
      const proof = props.approvalGate?.enabled
        ? buildApprovalProofCredentials(props.approvalGate, {
            approvalPassword: alphaApprovalPassword,
            approvalTotpCode: alphaApprovalTotpCode,
          })
        : undefined;
      await props.onSetUpdateChannel(targetChannel, proof);
      setAlphaModalOpen(false);
    } catch (error) {
      setAlphaSaveError(error instanceof Error ? error.message : "Guard could not change the update channel. Try again.");
    } finally {
      setAlphaSavePending(false);
    }
  }, [alphaApprovalPassword, alphaApprovalTotpCode, props.approvalGate, props.onSetUpdateChannel, targetChannel]);
  const handleApprovalPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setAlphaApprovalPassword(event.target.value);
  }, []);
  const handleApprovalTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setAlphaApprovalTotpCode(event.target.value);
  }, []);

  let updateChannelSummary: ReactNode = null;
  if (props.onSetUpdateChannel) {
    updateChannelSummary = (
      <GuardUpdateChannelSummary
        version={version}
        useAlpha={useAlpha}
        busy={busy}
        onManage={handleOpenAlphaModal}
      />
    );
  } else if (version) {
    updateChannelSummary = (
      <p className="font-mono text-[10px] text-brand-dark/70" aria-label={`Guard version ${version}`}>
        v{version}
      </p>
    );
  }

  return (
    <div className={props.compact ? "space-y-1" : "space-y-1.5"}>
      {updateChannelSummary}
      {props.updateStatus?.update_available ? (
        <div className="flex items-center justify-between gap-2">
          <p className="min-w-0 truncate text-[11px] leading-4 text-brand-dark/75">
            {updateStatusLabel(props.updateStatus)}
          </p>
          {showUpdateButton && props.onUpdateGuard ? (
            <button
              type="button"
              onClick={props.onUpdateGuard}
              aria-label="Update Guard to the latest version"
              className={GUARD_UPDATE_ACTION_BUTTON_CLASS}
            >
              <HiMiniArrowPath className="h-3 w-3 shrink-0" aria-hidden="true" />
              Update
            </button>
          ) : null}
        </div>
      ) : null}
      {helpCopy ? (
        <p className="text-[10px] leading-4 text-brand-dark/70">{helpCopy}</p>
      ) : null}
      {showReinstallButton && props.onReinstallGuard ? (
        <button
          type="button"
          onClick={props.onReinstallGuard}
          className={GUARD_UPDATE_ACTION_BUTTON_CLASS}
        >
          <HiMiniArrowPath className="h-3 w-3 shrink-0" aria-hidden="true" />
          Reinstall from PyPI
        </button>
      ) : null}
      {busy && (
        <p className="inline-flex items-center gap-1.5 text-[11px] font-medium leading-4 text-brand-blue" role="status">
          <HiMiniArrowPath className="h-3 w-3 animate-spin" aria-hidden="true" />
          {phase === "updating" ? "Updating Guard…" : "Reconnecting…"}
        </p>
      )}
      {alphaModalOpen ? (
        <GuardModalLayer ariaLabel={modalTitle} onClose={handleCloseAlphaModal} panelClassName="w-full max-w-md">
          <AlphaChannelDialog
            useAlpha={useAlpha}
            pending={alphaSavePending}
            error={alphaSaveError}
            approvalGate={props.approvalGate ?? null}
            approvalPassword={alphaApprovalPassword}
            approvalTotpCode={alphaApprovalTotpCode}
            onClose={handleCloseAlphaModal}
            onConfirm={handleConfirmAlphaChannel}
            onApprovalPasswordChange={handleApprovalPasswordChange}
            onApprovalTotpCodeChange={handleApprovalTotpCodeChange}
          />
        </GuardModalLayer>
      ) : null}
    </div>
  );
}

export function useGuardUpdate(options?: { onReconnected?: () => void; enabled?: boolean }) {
  const enabled = options?.enabled !== false;
  const [updateStatus, setUpdateStatus] = useState<GuardUpdateStatus | null>(null);
  const [updatePhase, setUpdatePhase] = useState<GuardUpdatePhase>(enabled ? "checking" : "idle");
  const [updateError, setUpdateError] = useState<string | null>(null);
  const reconnectStartedAt = useRef<number | null>(null);
  const updatePhaseRef = useRef<GuardUpdatePhase>("checking");
  const updateStatusEpoch = useRef(0);
  const channelMutationId = useRef(0);
  const channelMutationPending = useRef(false);
  const isMounted = useRef(false);

  useEffect(() => {
    updatePhaseRef.current = updatePhase;
  }, [updatePhase]);

  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const refreshUpdateStatus = useCallback(async () => {
    if (!enabled || !isMounted.current || channelMutationPending.current) {
      return;
    }
    const epoch = updateStatusEpoch.current;
    const mutationId = channelMutationId.current;
    try {
      const status = await fetchGuardUpdateStatus();
      if (
        !isMounted.current ||
        epoch !== updateStatusEpoch.current ||
        mutationId !== channelMutationId.current ||
        channelMutationPending.current
      ) {
        return;
      }
      setUpdateStatus(status);
      if (updatePhaseRef.current === "checking" || updatePhaseRef.current === "idle") {
        setUpdatePhase("idle");
      }
    } catch {
      if (isMounted.current && updatePhaseRef.current === "checking") {
        setUpdatePhase("idle");
      }
    }
  }, [enabled]);

  useEffect(() => {
    if (!enabled) {
      setUpdatePhase("idle");
      return;
    }
    let cancelled = false;
    const epoch = updateStatusEpoch.current;
    const mutationId = channelMutationId.current;
    void fetchGuardUpdateStatus()
      .then((status) => {
        if (
          cancelled ||
          epoch !== updateStatusEpoch.current ||
          mutationId !== channelMutationId.current ||
          channelMutationPending.current
        ) {
          return;
        }
        setUpdateStatus(status);
        if (updatePhaseRef.current === "checking" || updatePhaseRef.current === "idle") {
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
  }, [enabled, refreshUpdateStatus]);

  const waitForReconnect = useCallback(
    async (
      expectedPreviousVersion: string,
      expectedLatestVersion: string | null,
      authorization: GuardDaemonReconnectAuthorization,
    ): Promise<boolean> => {
      reconnectStartedAt.current = Date.now();
      let sawUpdateInProgress = false;
      while (Date.now() - (reconnectStartedAt.current ?? Date.now()) < RECONNECT_TIMEOUT_MS) {
        try {
          const reconnectResult = await reconnectGuardDaemonAfterUpdate({
            expectedPreviousVersion,
            expectedLatestVersion,
            sawUpdateInProgress,
            authorization,
          });
          if (!reconnectResult) {
            throw new Error("Guard daemon not found");
          }
          sawUpdateInProgress = reconnectResult.sawUpdateInProgress;
          if (!reconnectResult.origin) {
            throw new Error("Guard daemon not ready");
          }
          const { origin } = reconnectResult;
          if (origin !== window.location.origin) {
            redirectToGuardDaemonOrigin(origin, readGuardToken());
            return true;
          }
          updateStatusEpoch.current += 1;
          setUpdateStatus(reconnectResult.status);
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

  const scheduleAndWait = useCallback(
    async (params: {
      forcePypiReinstall?: boolean;
      expectedPreviousVersion: string;
      expectedLatestVersion: string | null;
    }): Promise<void> => {
      setUpdatePhase("updating");
      setUpdateError(null);
      try {
        const reconnectAuthorization = await prepareGuardDaemonReconnect();
        const scheduleResult = await scheduleGuardUpdate(
          params.forcePypiReinstall === true ? { forcePypiReinstall: true } : undefined,
        );
        if (scheduleResult.scheduled === false && scheduleResult.error === "update_in_progress") {
          setUpdatePhase("reconnecting");
          const redirected = await waitForReconnect(
            params.expectedPreviousVersion,
            params.expectedLatestVersion,
            reconnectAuthorization,
          );
          if (!redirected) {
            window.location.reload();
          }
          return;
        }
        if (scheduleResult.scheduled !== true) {
          throw new Error(
            scheduleResult.message ?? scheduleResult.error ?? "Guard update was not scheduled. The installed version stays in place.",
          );
        }
        setUpdatePhase("reconnecting");
        const redirected = await waitForReconnect(
          params.expectedPreviousVersion,
          params.expectedLatestVersion,
          reconnectAuthorization,
        );
        if (!redirected) {
          window.location.reload();
        }
      } catch (error) {
        setUpdatePhase("error");
        setUpdateError(error instanceof Error ? error.message : "The update did not finish. The installed version stays in place.");
      }
    },
    [waitForReconnect],
  );

  const onUpdateGuard = useCallback(async () => {
    if (!updateStatus?.update_available || !updateStatus.auto_updatable) {
      return;
    }
    await scheduleAndWait({
      expectedPreviousVersion: updateStatus.current_version,
      expectedLatestVersion: updateStatus.latest_version,
    });
  }, [scheduleAndWait, updateStatus]);

  const onReinstallGuard = useCallback(async () => {
    if (!updateStatus?.recovery_reinstall_available) {
      return;
    }
    // A PyPI reinstall may land the same version; skip the version-change gate
    // during reconnect by not pinning an expected previous/target version.
    await scheduleAndWait({
      forcePypiReinstall: true,
      expectedPreviousVersion: "",
      expectedLatestVersion: null,
    });
  }, [scheduleAndWait, updateStatus]);

  const onSetUpdateChannel = useCallback(async (channel: "stable" | "alpha", proof?: GuardUpdateChannelProof) => {
    const mutationId = ++channelMutationId.current;
    updateStatusEpoch.current += 1;
    channelMutationPending.current = true;
    try {
      const status = await setGuardUpdateChannel(channel, proof);
      if (mutationId === channelMutationId.current) {
        updateStatusEpoch.current += 1;
        setUpdateStatus(status);
        if (updatePhaseRef.current === "checking" || updatePhaseRef.current === "idle") {
          setUpdatePhase("idle");
        }
      }
    } finally {
      if (mutationId === channelMutationId.current) {
        channelMutationPending.current = false;
      }
    }
  }, []);

  return {
    guardVersion: updateStatus?.current_version ?? null,
    updateStatus,
    updatePhase,
    updateError,
    onUpdateGuard,
    onReinstallGuard,
    onSetUpdateChannel,
    refreshUpdateStatus,
  };
}
