import { useEffect, useRef, useState } from "react";
import { fetchRuntimeSnapshot, fetchSettings, type GuardApprovalGateTotpEnrollment } from "./guard-api";
import { type ProtectionPosture } from "./protection-posture-copy";
import { type SettingsSaveProofMode } from "./settings-save-proof-modal";
import type { GuardNotificationSetupResult, GuardRuntimeSnapshot, GuardSettings, GuardSettingsExport } from "./guard-types";
import { resolveInitialSettingsTab, type LocalSettingsTabKey } from "./settings/settings-ia";
import { SettingsState, TotpSetupStep, SettingsSaveScope, normalizeSettingsPayload, hasUnsavedChanges } from "./settings-workspace-model";
import type { SettingsWorkspaceProps } from "./settings-workspace-model";

export function useSettingsWorkspaceState({ onApprovalGateChange }: SettingsWorkspaceProps) {
  const [state, setState] = useState<SettingsState>({ kind: "loading" });

  const [draft, setDraft] = useState<GuardSettings | null>(null);

  const [saving, setSaving] = useState(false);

  const [saveSuccess, setSaveSuccess] = useState(false);

  const [saveError, setSaveError] = useState<string | null>(null);

  const [clearingApprovals, setClearingApprovals] = useState(false);

  const [clearingEvidence, setClearingEvidence] = useState(false);

  const [clearingReviewQueue, setClearingReviewQueue] = useState(false);

  const [exporting, setExporting] = useState(false);

  const [repairing, setRepairing] = useState(false);

  const [settingUpNotifications, setSettingUpNotifications] = useState(false);

  const [notificationSetup, setNotificationSetup] = useState<GuardNotificationSetupResult | null>(null);

  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const [actionMessageKind, setActionMessageKind] = useState<"success" | "error">("success");

  const [perfSnapshot, setPerfSnapshot] = useState<GuardRuntimeSnapshot | null>(null);

  const [pendingMode, setPendingMode] = useState<GuardSettings["mode"] | null>(null);

  const [pendingPosture, setPendingPosture] = useState<ProtectionPosture | null>(null);

  const [activeTab, setActiveTab] = useState<LocalSettingsTabKey>(() => resolveInitialSettingsTab(window.location.search));

  const [searchQuery, setSearchQuery] = useState("");

  const [importingSettings, setImportingSettings] = useState(false);

  const [resettingSettings, setResettingSettings] = useState(false);

  const [exportingSettings, setExportingSettings] = useState(false);

  const settingsImportInputRef = useRef<HTMLInputElement>(null);

  const saveSuccessTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const savedSettingsRef = useRef<GuardSettings | null>(null);

  const [approvalGateEnabled, setApprovalGateEnabled] = useState(false);

  const [approvalGateTotpCode, setApprovalGateTotpCode] = useState("");

  const [approvalGateTotpDeviceLabel, setApprovalGateTotpDeviceLabel] = useState("local-device");

  const [approvalGateStrictAllDecisions, setApprovalGateStrictAllDecisions] = useState(false);

  const [approvalGateCooldown, setApprovalGateCooldown] = useState(0);

  const [totpEnrollment, setTotpEnrollment] = useState<GuardApprovalGateTotpEnrollment | null>(null);

  const [totpSetupOpen, setTotpSetupOpen] = useState(false);

  const [totpSetupStep, setTotpSetupStep] = useState<TotpSetupStep>("confirm");

  const [totpActionPassword, setTotpActionPassword] = useState("");

  const [totpActionPending, setTotpActionPending] = useState<"enroll" | "verify" | "disable" | null>(null);

  const [totpActionError, setTotpActionError] = useState<string | null>(null);

  const [proofModalOpen, setProofModalOpen] = useState(false);

  const [proofModalMode, setProofModalMode] = useState<SettingsSaveProofMode>("verify-save");

  const [proofModalError, setProofModalError] = useState<string | null>(null);

  const [proofModalPending, setProofModalPending] = useState(false);

  const [pendingProofAction, setPendingProofAction] = useState<
    | { kind: "save"; scope?: SettingsSaveScope }
    | {
        kind: "maintenance";
        action:
          | "clear-approvals"
          | "clear-queue"
          | "revoke-cooldown"
          | "disable-totp"
          | "import-settings"
          | "reset-settings";
        importExport?: GuardSettingsExport;
      }
    | null
  >(null);

  useEffect(() => {
    let cancelled = false;
    fetchSettings()
      .then((payload) => {
        if (!cancelled) {
          const normalizedPayload = normalizeSettingsPayload(payload);
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
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({ kind: "error", message: error instanceof Error ? error.message : "Unable to load Guard settings." });
        }
      });
    return () => { cancelled = true; };
  }, [onApprovalGateChange]);

  useEffect(() => {
    let cancelled = false;
    fetchRuntimeSnapshot()
      .then((snapshot) => { if (!cancelled) setPerfSnapshot(snapshot); })
      .catch((_err: unknown) => {});
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    return () => { if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current); };
  }, []);

  useEffect(() => {
    const handlePopState = () => {
      setActiveTab(resolveInitialSettingsTab(window.location.search));
      setActionMessage(null);
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    function handleBeforeUnload(event: BeforeUnloadEvent) {
      if (hasUnsavedChanges(savedSettingsRef.current, draft)) {
        event.preventDefault();
        event.returnValue = "";
      }
    }
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [draft]);

  return {
      onApprovalGateChange, state, setState, draft, setDraft,
      saving, setSaving, saveSuccess, setSaveSuccess, saveError,
      setSaveError, clearingApprovals, setClearingApprovals, clearingEvidence, setClearingEvidence,
      clearingReviewQueue, setClearingReviewQueue, exporting, setExporting, repairing,
      setRepairing, settingUpNotifications, setSettingUpNotifications, notificationSetup, setNotificationSetup,
      actionMessage, setActionMessage, actionMessageKind, setActionMessageKind, perfSnapshot,
      setPerfSnapshot, pendingMode, setPendingMode, pendingPosture, setPendingPosture,
      activeTab, setActiveTab, searchQuery, setSearchQuery, importingSettings,
      setImportingSettings, resettingSettings, setResettingSettings, exportingSettings, setExportingSettings,
      settingsImportInputRef, saveSuccessTimerRef, savedSettingsRef, approvalGateEnabled, setApprovalGateEnabled,
      approvalGateTotpCode, setApprovalGateTotpCode, approvalGateTotpDeviceLabel, setApprovalGateTotpDeviceLabel, approvalGateStrictAllDecisions,
      setApprovalGateStrictAllDecisions, approvalGateCooldown, setApprovalGateCooldown, totpEnrollment, setTotpEnrollment,
      totpSetupOpen, setTotpSetupOpen, totpSetupStep, setTotpSetupStep, totpActionPassword,
      setTotpActionPassword, totpActionPending, setTotpActionPending, totpActionError, setTotpActionError,
      proofModalOpen, setProofModalOpen, proofModalMode, setProofModalMode, proofModalError,
      setProofModalError, proofModalPending, setProofModalPending, pendingProofAction, setPendingProofAction,
  };
}

export type SettingsWorkspaceStateContext = ReturnType<typeof useSettingsWorkspaceState>;
