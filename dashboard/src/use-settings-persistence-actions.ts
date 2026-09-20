import { useCallback } from "react";
import { clearReviewQueue, disableApprovalGateTotp, importSettings, resetSettings, updateSettings, clearPolicy, revokeApprovalGateCooldown } from "./guard-api";
import { type SettingsSaveProofCredentials } from "./settings-save-proof-modal";
import type { GuardApprovalGatePublicConfig, GuardSettings, GuardSettingsExport } from "./guard-types";
import { withoutPresentationSettings } from "./presentation-mode-state";
import { SettingsSaveScope, normalizeSettingsPayload, buildClearReviewQueuePayload, buildApprovalGateWriteProof } from "./settings-workspace-model";
import type { SettingsWorkspaceStateContext } from "./use-settings-workspace-state";
import type { SettingsEditingActionsContext } from "./use-settings-editing-actions";

export function useSettingsPersistenceActions(context: SettingsWorkspaceStateContext & SettingsEditingActionsContext) {
  const {
      onApprovalGateChange, draft, setSaving, setSaveError, setSaveSuccess,
      approvalGateEnabled, approvalGateCooldown, approvalGateStrictAllDecisions, setState, setDraft,
      savedSettingsRef, setApprovalGateEnabled, setApprovalGateCooldown, setApprovalGateStrictAllDecisions, saveSuccessTimerRef,
      setClearingApprovals, setActionMessage, setActionMessageKind, setClearingReviewQueue, setTotpActionPending,
      setTotpActionError, setApprovalGateTotpCode, setTotpActionPassword, setTotpEnrollment, setTotpSetupOpen,
      setTotpSetupStep, setImportingSettings, applyLoadedSettingsPayload, setResettingSettings,
    } = context;

  const executeSave = useCallback(async (proof?: SettingsSaveProofCredentials, scope: SettingsSaveScope = "all") => {
    if (draft === null) {
      return;
    }
    const fromModal = proof !== undefined;
    if (!fromModal) {
      setSaving(true);
      setSaveError(null);
      setSaveSuccess(false);
    }
    try {
      const approvalGateUpdate: GuardApprovalGatePublicConfig & {
        current_password?: string;
        new_password?: string;
        confirm_password?: string;
        totp_code?: string;
      } = {
        enabled: approvalGateEnabled,
        configured: draft.approval_gate?.configured ?? false,
        cooldown_seconds: approvalGateCooldown,
        cooldown_active: draft.approval_gate?.cooldown_active ?? false,
        cooldown_expires_at: draft.approval_gate?.cooldown_expires_at ?? null,
        locked_until: draft.approval_gate?.locked_until ?? null,
        fail_closed: draft.approval_gate?.fail_closed ?? false,
        strict_all_decisions: approvalGateStrictAllDecisions,
        totp_enabled: draft.approval_gate?.totp_enabled ?? false,
        totp_pending: draft.approval_gate?.totp_pending ?? false,
        ...(proof?.currentPassword ? { current_password: proof.currentPassword } : {}),
        ...(proof?.newPassword ? { new_password: proof.newPassword } : {}),
        ...(proof?.confirmPassword ? { confirm_password: proof.confirmPassword } : {}),
        ...(proof?.totpCode ? { totp_code: proof.totpCode } : {}),
      };
      let settingsToSave: Partial<GuardSettings>;
      if (scope === "approval-gate") {
        settingsToSave = { approval_gate: approvalGateUpdate };
      } else {
        settingsToSave = {
          ...withoutPresentationSettings(draft),
          risk_actions: draft.security_level === "custom" ? draft.risk_actions : draft.risk_action_overrides,
          approval_gate: approvalGateUpdate,
        };
      }
      const payload = await updateSettings(settingsToSave);
      const normalizedPayload = normalizeSettingsPayload(payload);
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (normalizedPayload.settings.approval_gate !== undefined) {
        const gate = normalizedPayload.settings.approval_gate;
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      if (!fromModal) {
        setSaveSuccess(true);
        if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
        saveSuccessTimerRef.current = setTimeout(() => setSaveSuccess(false), 2000);
      } else {
        setSaveSuccess(true);
        setSaveError(null);
        if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
        saveSuccessTimerRef.current = setTimeout(() => setSaveSuccess(false), 2000);
      }
    } catch (error) {
      if (fromModal) {
        throw error;
      }
      setSaveError(error instanceof Error ? error.message : "Unable to save settings.");
    } finally {
      if (!fromModal) {
        setSaving(false);
      }
    }
  }, [
    draft,
    approvalGateEnabled,
    approvalGateCooldown,
    approvalGateStrictAllDecisions,
    onApprovalGateChange,
  ]);

  const executeMaintenanceWithProof = useCallback(async (
    action: "clear-approvals" | "clear-queue" | "revoke-cooldown" | "disable-totp",
    proof: SettingsSaveProofCredentials,
  ) => {
    const password = proof.currentPassword?.trim() ?? "";
    const totpCode = proof.totpCode?.trim() ?? "";
    if (action === "clear-approvals") {
      setClearingApprovals(true);
      setActionMessage(null);
      try {
        await clearPolicy({
          all: true,
          approval_password: password || undefined,
          approval_totp_code: totpCode || undefined,
        });
        setActionMessage("Saved approvals cleared. Guard will ask again for future matching actions.");
        setActionMessageKind("success");
      } finally {
        setClearingApprovals(false);
      }
      return;
    }
    if (action === "clear-queue") {
      setClearingReviewQueue(true);
      setActionMessage(null);
      try {
        const result = await clearReviewQueue(buildClearReviewQueuePayload({
          approvalPassword: password,
          approvalTotpCode: totpCode,
        }));
        setActionMessage(`Review queue cleared. Removed ${result.cleared} pending ${result.cleared === 1 ? "item" : "items"}.`);
        setActionMessageKind("success");
      } finally {
        setClearingReviewQueue(false);
      }
      return;
    }
    if (action === "revoke-cooldown") {
      try {
        const payload = await revokeApprovalGateCooldown(
          password,
          totpCode.length > 0 ? totpCode : undefined,
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
        setActionMessage("Cooldown revoked successfully.");
        setActionMessageKind("success");
      } catch (error) {
        throw error;
      }
      return;
    }
    setTotpActionPending("disable");
    setTotpActionError(null);
    try {
      const payload = await disableApprovalGateTotp(password, totpCode);
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
      setActionMessage("Authenticator app disconnected.");
      setActionMessageKind("success");
    } finally {
      setTotpActionPending(null);
    }
  }, [onApprovalGateChange]);

  const executeImportSettings = useCallback(async (
    settingsExport: GuardSettingsExport,
    proof?: SettingsSaveProofCredentials,
  ) => {
    setImportingSettings(true);
    setActionMessage(null);
    try {
      const payload = await importSettings(settingsExport, buildApprovalGateWriteProof(proof));
      const normalizedPayload = normalizeSettingsPayload(payload);
      applyLoadedSettingsPayload(normalizedPayload);
      setActionMessage("Settings imported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to import settings.");
      setActionMessageKind("error");
      throw error;
    } finally {
      setImportingSettings(false);
    }
  }, [applyLoadedSettingsPayload]);

  const executeResetSettings = useCallback(async (proof?: SettingsSaveProofCredentials) => {
    setResettingSettings(true);
    setActionMessage(null);
    try {
      const payload = await resetSettings(buildApprovalGateWriteProof(proof));
      const normalizedPayload = normalizeSettingsPayload(payload);
      applyLoadedSettingsPayload(normalizedPayload);
      setActionMessage("Settings reset to defaults.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to reset settings.");
      setActionMessageKind("error");
      throw error;
    } finally {
      setResettingSettings(false);
    }
  }, [applyLoadedSettingsPayload]);

  return {
      executeSave, executeMaintenanceWithProof, executeImportSettings, executeResetSettings,
  };
}

export type SettingsPersistenceActionsContext = ReturnType<typeof useSettingsPersistenceActions>;
