import { useCallback, type ChangeEvent } from "react";
import { type ProtectionPosture } from "./protection-posture-copy";
import { type SettingsSaveProofMode } from "./settings-save-proof-modal";
import type { GuardSettings, GuardSettingsPayload } from "./guard-types";
import { type LocalSettingsTabKey } from "./settings/settings-ia";
import { riskProfileActions, applyProtectionPosture, applyApprovalGateDraft, resolveTotpSetupStep } from "./settings-workspace-model";
import type { SettingsWorkspaceStateContext } from "./use-settings-workspace-state";

export function useSettingsEditingActions(context: SettingsWorkspaceStateContext) {
  const {
      onApprovalGateChange, setActiveTab, setActionMessage, setSearchQuery, setDraft,
      setSaveError, setPendingMode, setPendingPosture, pendingPosture, pendingMode,
      setApprovalGateEnabled, approvalGateCooldown, approvalGateStrictAllDecisions, setApprovalGateTotpCode, setTotpActionError,
      setApprovalGateTotpDeviceLabel, setTotpActionPassword, setTotpSetupStep, totpEnrollment, setTotpSetupOpen,
      setApprovalGateCooldown, approvalGateEnabled, setApprovalGateStrictAllDecisions, setState, savedSettingsRef,
      pendingProofAction, setProofModalMode, setPendingProofAction, setProofModalError, setProofModalOpen,
      proofModalPending,
    } = context;

  const handleTabChange = useCallback((tab: LocalSettingsTabKey) => {
    setActiveTab(tab);
    setActionMessage(null);
    const url = new URL(window.location.href);
    url.searchParams.set("section", tab);
    window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
  }, []);

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
  }, []);

  const handleStringChange = useCallback(
    (key: keyof GuardSettings) => (event: ChangeEvent<HTMLSelectElement>) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.value });
      setSaveError(null);
    },
    []
  );

  const handleSecurityLevelChange = useCallback((securityLevel: GuardSettings["security_level"]) => {
    setDraft((value) => {
      if (value === null) return value;
      if (securityLevel === "custom") return { ...value, security_level: securityLevel };
      const normalizedLevel = securityLevel === "gentle" ? "relaxed" : securityLevel;
      return {
        ...value,
        security_level: normalizedLevel,
        risk_actions: riskProfileActions[normalizedLevel],
        risk_action_overrides: {},
        harness_risk_actions: {},
      };
    });
    setSaveError(null);
  }, []);

  const handleSwitchToCustomFineTuning = useCallback(() => {
    handleSecurityLevelChange("custom");
  }, [handleSecurityLevelChange]);

  const handleRiskActionChange = useCallback(
    (riskKey: string) => (event: ChangeEvent<HTMLSelectElement>) => {
      setDraft((value) => {
        if (value === null) return value;
        return { ...value, security_level: "custom", risk_actions: { ...value.risk_actions, [riskKey]: event.target.value }, risk_action_overrides: { ...value.risk_action_overrides, [riskKey]: event.target.value } };
      });
      setSaveError(null);
    },
    []
  );

  const handleCodexSecretReadChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setDraft((value) => {
      if (value === null) return value;
      return { ...value, security_level: "custom", harness_risk_actions: { ...value.harness_risk_actions, codex: { ...(value.harness_risk_actions.codex ?? {}), local_secret_read: event.target.value } } };
    });
    setSaveError(null);
  }, []);

  const handleTimeoutChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const nextValue = Number.parseInt(event.target.value, 10);
    const nextTimeout = Number.isNaN(nextValue) ? 0 : nextValue;
    setDraft((value) => value === null ? value : { ...value, approval_wait_timeout_seconds: nextTimeout });
    setSaveError(null);
  }, []);

  const handleNumberChange = useCallback(
    (key: keyof GuardSettings) => (event: ChangeEvent<HTMLInputElement>) => {
      const parsed = Number.parseInt(event.target.value, 10);
      const value = Number.isNaN(parsed) ? 0 : parsed;
      setDraft((settings) => settings === null ? settings : { ...settings, [key]: value });
      setSaveError(null);
    },
    [],
  );

  const handleModeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const nextMode = event.target.value as GuardSettings["mode"];
    if (nextMode === "observe") { setPendingMode(nextMode); return; }
    setDraft((value) => value === null ? value : { ...value, mode: nextMode });
    setSaveError(null);
  }, []);

  const applyDraftPosture = useCallback((posture: ProtectionPosture) => {
    setDraft((value) => value === null ? value : applyProtectionPosture(value, posture));
    setSaveError(null);
  }, []);

  const handleProtectionPostureChange = useCallback((posture: ProtectionPosture) => {
    if (posture === "watch") {
      setPendingPosture(posture);
      return;
    }
    applyDraftPosture(posture);
  }, [applyDraftPosture]);

  const handleTurnProtectionOn = useCallback(() => {
    applyDraftPosture("protected");
  }, [applyDraftPosture]);

  const handleWatchAutoRevertToggle = useCallback((checked: boolean) => {
    setDraft((value) => value === null ? value : { ...value, watch_auto_revert_hours: checked ? 24 : 0 });
    setSaveError(null);
  }, []);

  const confirmModeChange = useCallback(() => {
    if (pendingPosture === "watch") {
      applyDraftPosture("watch");
      setPendingPosture(null);
      setPendingMode(null);
      return;
    }
    if (pendingMode === null) return;
    setDraft((value) => value === null ? value : { ...value, mode: pendingMode });
    setPendingMode(null);
    setSaveError(null);
  }, [applyDraftPosture, pendingMode, pendingPosture]);

  const cancelModeChange = useCallback(() => {
    setPendingMode(null);
    setPendingPosture(null);
  }, []);

  const handleBooleanChange = useCallback(
    (key: keyof GuardSettings) => (event: ChangeEvent<HTMLInputElement>) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.checked });
      setSaveError(null);
    },
    []
  );

  const handleTelemetryToggle = useCallback((checked: boolean) => {
    setDraft((value) => value === null ? value : { ...value, telemetry: checked });
    setSaveError(null);
  }, []);

  const handleSyncToggle = useCallback((checked: boolean) => {
    setDraft((value) => value === null ? value : { ...value, sync: checked });
    setSaveError(null);
  }, []);

  const handleBillingToggle = useCallback((checked: boolean) => {
    setDraft((value) => value === null ? value : { ...value, billing: checked });
    setSaveError(null);
  }, []);

  const handleApprovalGateToggle = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const checked = event.target.checked;
    setApprovalGateEnabled(checked);
    setDraft((value) =>
      value === null
        ? value
        : applyApprovalGateDraft(value, {
          enabled: checked,
          cooldown_seconds: approvalGateCooldown,
          strict_all_decisions: approvalGateStrictAllDecisions,
        })
    );
    setSaveError(null);
  }, [approvalGateCooldown, approvalGateStrictAllDecisions]);

  const handleApprovalGateTotpCode = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalGateTotpCode(event.target.value);
    setTotpActionError(null);
  }, []);

  const handleApprovalGateTotpDeviceLabel = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalGateTotpDeviceLabel(event.target.value);
    setTotpActionError(null);
  }, []);

  const handleTotpActionPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotpActionPassword(event.target.value);
    setTotpActionError(null);
  }, []);

  const handleOpenTotpSetup = useCallback(() => {
    setTotpSetupStep(resolveTotpSetupStep(totpEnrollment));
    setTotpActionError(null);
    setTotpSetupOpen(true);
  }, [totpEnrollment]);

  const handleCloseTotpSetup = useCallback(() => {
    setTotpSetupOpen(false);
    setTotpSetupStep("confirm");
    if (totpEnrollment === null) {
      setTotpActionPassword("");
    }
    setTotpActionError(null);
  }, [totpEnrollment]);

  const handleApprovalGateCooldownChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    const next = Number(event.target.value);
    setApprovalGateCooldown(next);
    setDraft((value) =>
      value === null
        ? value
        : applyApprovalGateDraft(value, {
          enabled: approvalGateEnabled,
          cooldown_seconds: next,
          strict_all_decisions: approvalGateStrictAllDecisions,
        })
    );
    setSaveError(null);
  }, [approvalGateEnabled, approvalGateStrictAllDecisions]);

  const handleApprovalGateStrictAllDecisions = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const strict = event.target.checked;
    setApprovalGateStrictAllDecisions(strict);
    setDraft((value) =>
      value === null
        ? value
        : applyApprovalGateDraft(value, {
          enabled: approvalGateEnabled,
          cooldown_seconds: approvalGateCooldown,
          strict_all_decisions: strict,
        })
    );
    setSaveError(null);
  }, [approvalGateEnabled, approvalGateCooldown]);

  const applyLoadedSettingsPayload = useCallback((normalizedPayload: GuardSettingsPayload) => {
    setState({ kind: "ready", payload: normalizedPayload });
    setDraft(normalizedPayload.settings);
    savedSettingsRef.current = normalizedPayload.settings;
    const gate = normalizedPayload.settings.approval_gate;
    if (gate !== undefined) {
      setApprovalGateEnabled(gate.enabled);
      setApprovalGateCooldown(gate.cooldown_seconds);
      setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
      onApprovalGateChange?.(gate);
    }
  }, [onApprovalGateChange]);

  const openProofModal = useCallback((
    mode: SettingsSaveProofMode,
    action: NonNullable<typeof pendingProofAction>,
  ) => {
    setProofModalMode(mode);
    setPendingProofAction(action);
    setProofModalError(null);
    setProofModalOpen(true);
  }, []);

  const closeProofModal = useCallback(() => {
    if (proofModalPending) {
      return;
    }
    setProofModalOpen(false);
    setPendingProofAction(null);
    setProofModalError(null);
  }, [proofModalPending]);

  return {
      handleTabChange, handleSearchChange, handleStringChange, handleSecurityLevelChange, handleSwitchToCustomFineTuning,
      handleRiskActionChange, handleCodexSecretReadChange, handleTimeoutChange, handleNumberChange, handleModeChange,
      applyDraftPosture, handleProtectionPostureChange, handleTurnProtectionOn, handleWatchAutoRevertToggle, confirmModeChange,
      cancelModeChange, handleBooleanChange, handleTelemetryToggle, handleSyncToggle, handleBillingToggle,
      handleApprovalGateToggle, handleApprovalGateTotpCode, handleApprovalGateTotpDeviceLabel, handleTotpActionPasswordChange, handleOpenTotpSetup,
      handleCloseTotpSetup, handleApprovalGateCooldownChange, handleApprovalGateStrictAllDecisions, applyLoadedSettingsPayload, openProofModal,
      closeProofModal,
  };
}

export type SettingsEditingActionsContext = ReturnType<typeof useSettingsEditingActions>;
