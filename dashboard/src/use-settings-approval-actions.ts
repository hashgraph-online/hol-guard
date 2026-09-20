import { useCallback } from "react";
import { clearReviewQueue, enrollApprovalGateTotp, clearPolicy, verifyApprovalGateTotp } from "./guard-api";
import { resolveSettingsSaveProofKind, requiresSettingsSaveProof, type SettingsSaveProofCredentials } from "./settings-save-proof-modal";
import { normalizeSettingsPayload, buildClearReviewQueuePayload } from "./settings-workspace-model";
import type { SettingsWorkspaceStateContext } from "./use-settings-workspace-state";
import type { SettingsPersistenceActionsContext } from "./use-settings-persistence-actions";
import type { SettingsEditingActionsContext } from "./use-settings-editing-actions";

export function useSettingsApprovalActions(context: SettingsWorkspaceStateContext & SettingsPersistenceActionsContext & SettingsEditingActionsContext) {
  const {
      onApprovalGateChange, pendingProofAction, setProofModalPending, setProofModalError, executeSave,
      executeImportSettings, executeResetSettings, executeMaintenanceWithProof, setProofModalOpen, setPendingProofAction,
      draft, savedSettingsRef, approvalGateEnabled, openProofModal, totpActionPassword,
      setTotpActionError, setTotpActionPending, approvalGateTotpDeviceLabel, setState, setDraft,
      setApprovalGateEnabled, setApprovalGateCooldown, setApprovalGateStrictAllDecisions, setTotpEnrollment, setTotpSetupStep,
      setTotpSetupOpen, setActionMessage, setActionMessageKind, approvalGateTotpCode, setApprovalGateTotpCode,
      setTotpActionPassword, setClearingApprovals, setClearingReviewQueue,
    } = context;

  const handleProofModalConfirm = useCallback(async (proof: SettingsSaveProofCredentials) => {
    if (pendingProofAction === null) {
      return;
    }
    setProofModalPending(true);
    setProofModalError(null);
    try {
      if (pendingProofAction.kind === "save") {
        await executeSave(proof, pendingProofAction.scope);
      } else if (pendingProofAction.action === "import-settings") {
        if (pendingProofAction.importExport === undefined) {
          throw new Error("Missing settings import payload.");
        }
        await executeImportSettings(pendingProofAction.importExport, proof);
      } else if (pendingProofAction.action === "reset-settings") {
        await executeResetSettings(proof);
      } else {
        await executeMaintenanceWithProof(pendingProofAction.action, proof);
      }
      setProofModalOpen(false);
      setPendingProofAction(null);
    } catch (error) {
      setProofModalError(error instanceof Error ? error.message : "Unable to continue.");
    } finally {
      setProofModalPending(false);
    }
  }, [pendingProofAction, executeSave, executeImportSettings, executeResetSettings, executeMaintenanceWithProof]);

  const handleSave = useCallback(() => {
    if (draft === null) {
      return;
    }
    const savedGateConfig = savedSettingsRef.current?.approval_gate ?? null;
    const proofKind = resolveSettingsSaveProofKind({
      savedGateEnabled: savedGateConfig?.enabled === true,
      wasConfigured: savedGateConfig?.configured === true,
      draftGateEnabled: approvalGateEnabled,
      changingPassword: false,
    });
    if (requiresSettingsSaveProof(proofKind)) {
      openProofModal(proofKind!, { kind: "save" });
      return;
    }
    void executeSave();
  }, [approvalGateEnabled, draft, executeSave, openProofModal]);

  const handleOpenPasswordChangeModal = useCallback((mode: "change-password" | "setup-gate" = "change-password") => {
    openProofModal(mode, { kind: "save", scope: mode === "setup-gate" ? "approval-gate" : "all" });
  }, [openProofModal]);

  const handleRequestRevokeCooldown = useCallback(() => {
    openProofModal("maintenance", { kind: "maintenance", action: "revoke-cooldown" });
  }, [openProofModal]);

  const handleRequestDisableTotp = useCallback(() => {
    openProofModal("maintenance", { kind: "maintenance", action: "disable-totp" });
  }, [openProofModal]);

  const handleStartTotpEnrollment = useCallback(async () => {
    if (!totpActionPassword.trim()) {
      setTotpActionError("Enter your approval password to continue.");
      return;
    }
    setTotpActionPending("enroll");
    setTotpActionError(null);
    try {
      const payload = await enrollApprovalGateTotp(
        totpActionPassword,
        approvalGateTotpDeviceLabel.trim() || "local-device"
      );
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== undefined) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setTotpEnrollment(payload.enrollment ?? null);
      setTotpSetupStep("scan");
      setTotpSetupOpen(payload.enrollment !== undefined && payload.enrollment !== null);
      setActionMessage("Scan the QR code, then enter a live code from your app.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to start TOTP enrollment.");
    } finally {
      setTotpActionPending(null);
    }
  }, [totpActionPassword, approvalGateTotpDeviceLabel, onApprovalGateChange]);

  const handleVerifyTotpEnrollment = useCallback(async () => {
    if (!totpActionPassword.trim()) {
      setTotpActionError("Enter your approval password to continue.");
      return;
    }
    if (!approvalGateTotpCode.trim()) {
      setTotpActionError("Enter the six-digit code from your authenticator app.");
      return;
    }
    setTotpActionPending("verify");
    setTotpActionError(null);
    try {
      const payload = await verifyApprovalGateTotp(totpActionPassword, approvalGateTotpCode);
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== undefined) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setApprovalGateTotpCode("");
      setTotpActionPassword("");
      setTotpEnrollment(null);
      setTotpSetupOpen(false);
      setTotpSetupStep("confirm");
      setActionMessage("Authenticator app connected.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to verify TOTP.");
    } finally {
      setTotpActionPending(null);
    }
  }, [totpActionPassword, approvalGateTotpCode, onApprovalGateChange]);

  const handleDisableTotp = useCallback(async () => {
    handleRequestDisableTotp();
  }, [handleRequestDisableTotp]);

  const handleClearApprovals = useCallback(() => {
    if (!window.confirm("Clear all saved approvals? Guard will ask again for previously approved actions.")) {
      return;
    }
    const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
    if (savedGateEnabled) {
      openProofModal("maintenance", { kind: "maintenance", action: "clear-approvals" });
      return;
    }
    setClearingApprovals(true);
    setActionMessage(null);
    void clearPolicy({ all: true })
      .then(() => {
        setActionMessage("Saved approvals cleared. Guard will ask again for future matching actions.");
        setActionMessageKind("success");
      })
      .catch((error: unknown) => {
        setActionMessage(error instanceof Error ? error.message : "Unable to clear approvals.");
        setActionMessageKind("error");
      })
      .finally(() => {
        setClearingApprovals(false);
      });
  }, [openProofModal]);

  const handleClearReviewQueue = useCallback(() => {
    if (!window.confirm("Clear the pending review queue? Guard will remove waiting items without creating allow or block decisions.")) {
      return;
    }
    const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
    if (savedGateEnabled) {
      openProofModal("maintenance", { kind: "maintenance", action: "clear-queue" });
      return;
    }
    setClearingReviewQueue(true);
    setActionMessage(null);
    void clearReviewQueue(buildClearReviewQueuePayload({}))
      .then((result) => {
        setActionMessage(`Review queue cleared. Removed ${result.cleared} pending ${result.cleared === 1 ? "item" : "items"}.`);
        setActionMessageKind("success");
      })
      .catch((error: unknown) => {
        setActionMessage(error instanceof Error ? error.message : "Unable to clear review queue.");
        setActionMessageKind("error");
      })
      .finally(() => {
        setClearingReviewQueue(false);
      });
  }, [openProofModal]);

  return {
      handleProofModalConfirm, handleSave, handleOpenPasswordChangeModal, handleRequestRevokeCooldown, handleRequestDisableTotp,
      handleStartTotpEnrollment, handleVerifyTotpEnrollment, handleDisableTotp, handleClearApprovals, handleClearReviewQueue,
  };
}

export type SettingsApprovalActionsContext = ReturnType<typeof useSettingsApprovalActions>;
