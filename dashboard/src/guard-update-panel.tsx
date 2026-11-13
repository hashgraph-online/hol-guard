import { useCallback, useState, type ChangeEvent, type ReactNode } from "react";
import { HiMiniArrowPath } from "react-icons/hi2";

import { readRememberedGuardUpdateChannel, type GuardUpdateChannelProof, type GuardUpdateMode } from "./guard-api";
import { AlphaChannelDialog } from "./alpha-update-channel-dialog";
import { UpdateModeDialog } from "./update-mode-dialog";
import { dashboardEmbedsInDesktop } from "./desktop-embed";
import { shouldPromptRecoveryReinstall, updateHelpCopy, updateStatusLabel } from "./guard-update-copy";
import { buildApprovalProofCredentials } from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig, GuardUpdatePhase, GuardUpdateStatus } from "./guard-types";
import { GuardModalLayer } from "./guard-modal-layer";
import {
  GuardUpdateChannelSummary,
  GUARD_UPDATE_ACTION_BUTTON_CLASS,
  GUARD_UPDATE_CONTROL_TEXT_CLASS,
} from "./guard-update-channel-summary";

export type GuardUpdatePanelProps = {
  guardVersion?: string | null;
  updateStatus?: GuardUpdateStatus | null;
  updatePhase?: GuardUpdatePhase;
  updateError?: string | null;
  onUpdateGuard?: () => void;
  onReinstallGuard?: () => void;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onSetUpdateChannel?: (channel: "stable" | "alpha", proof?: GuardUpdateChannelProof) => void | Promise<void>;
  onSetUpdateMode?: (mode: GuardUpdateMode, proof?: GuardUpdateChannelProof) => void | Promise<void>;
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
  const [updateModeModalOpen, setUpdateModeModalOpen] = useState(false);
  const [updateModeDraft, setUpdateModeDraft] = useState<GuardUpdateMode>(props.updateStatus?.update_mode ?? "automatic");
  const [updateModeSavePending, setUpdateModeSavePending] = useState(false);
  const [updateModeSaveError, setUpdateModeSaveError] = useState<string | null>(null);
  const [updateModeApprovalPassword, setUpdateModeApprovalPassword] = useState("");
  const [updateModeApprovalTotpCode, setUpdateModeApprovalTotpCode] = useState("");
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
  const handleOpenUpdateModeModal = useCallback(() => {
    setUpdateModeDraft(props.updateStatus?.update_mode ?? "automatic");
    setUpdateModeSaveError(null);
    setUpdateModeApprovalPassword("");
    setUpdateModeApprovalTotpCode("");
    setUpdateModeModalOpen(true);
  }, [props.updateStatus?.update_mode]);
  const handleCloseUpdateModeModal = useCallback(() => {
    if (updateModeSavePending) return;
    setUpdateModeModalOpen(false);
    setUpdateModeSaveError(null);
  }, [updateModeSavePending]);
  const handleConfirmUpdateMode = useCallback(async () => {
    if (!props.onSetUpdateMode) return;
    setUpdateModeSavePending(true);
    setUpdateModeSaveError(null);
    try {
      const proof = props.approvalGate?.enabled
        ? buildApprovalProofCredentials(props.approvalGate, {
            approvalPassword: updateModeApprovalPassword,
            approvalTotpCode: updateModeApprovalTotpCode,
          })
        : undefined;
      await props.onSetUpdateMode(updateModeDraft, proof);
      setUpdateModeModalOpen(false);
    } catch (error) {
      setUpdateModeSaveError(error instanceof Error ? error.message : "Guard could not save the update preference. Try again.");
    } finally {
      setUpdateModeSavePending(false);
    }
  }, [props.approvalGate, props.onSetUpdateMode, updateModeApprovalPassword, updateModeApprovalTotpCode, updateModeDraft]);

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
  let updateModeLabel = "Automatic Core updates on";
  if (props.updateStatus?.update_mode === "ask") {
    updateModeLabel = "Ask before installing";
  } else if (props.updateStatus?.update_mode === "off") {
    updateModeLabel = "Automatic Core updates off";
  }

  return (
    <div
      className={
        props.compact
          ? "space-y-1 border-t border-brand-blue/10 pt-1.5"
          : "space-y-1.5 border-t border-brand-blue/10 pt-2"
      }
    >
      {updateChannelSummary}
      {props.onSetUpdateMode ? (
        <button type="button" onClick={handleOpenUpdateModeModal} disabled={busy} className="text-[11px] font-medium text-brand-blue hover:underline" aria-label="Manage Core update preferences">
          {updateModeLabel}
        </button>
      ) : null}
      {props.updateStatus?.update_available ? (
        <div className="flex items-center justify-between gap-2">
          <p className="min-w-0 text-[11px] leading-4 text-brand-dark/75 [overflow-wrap:anywhere]">
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
              <span className={GUARD_UPDATE_CONTROL_TEXT_CLASS}>Update</span>
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
          <span className={GUARD_UPDATE_CONTROL_TEXT_CLASS}>Reinstall from PyPI</span>
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
      {updateModeModalOpen ? (
        <GuardModalLayer ariaLabel="Core update preferences" onClose={handleCloseUpdateModeModal} panelClassName="w-full max-w-md">
          <UpdateModeDialog
            mode={props.updateStatus?.update_mode ?? "automatic"}
            draft={updateModeDraft}
            pending={updateModeSavePending}
            error={updateModeSaveError}
            approvalGate={props.approvalGate ?? null}
            approvalPassword={updateModeApprovalPassword}
            approvalTotpCode={updateModeApprovalTotpCode}
            onDraftChange={(event) => setUpdateModeDraft(event.target.value as GuardUpdateMode)}
            onClose={handleCloseUpdateModeModal}
            onConfirm={handleConfirmUpdateMode}
            onApprovalPasswordChange={(event) => setUpdateModeApprovalPassword(event.target.value)}
            onApprovalTotpCodeChange={(event) => setUpdateModeApprovalTotpCode(event.target.value)}
          />
        </GuardModalLayer>
      ) : null}
    </div>
  );
}

export { useGuardUpdate } from "./use-guard-update";
