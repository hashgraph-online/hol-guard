import { useCallback, type ChangeEvent } from "react";
import { clearEvidence, exportDiagnostics, exportSettings, repairApprovalCenter, setupDesktopNotifications } from "./guard-api";
import type { GuardSettingsExport } from "./guard-types";
import type { SettingsWorkspaceStateContext } from "./use-settings-workspace-state";
import type { SettingsEditingActionsContext } from "./use-settings-editing-actions";
import type { SettingsPersistenceActionsContext } from "./use-settings-persistence-actions";

export function useSettingsMaintenanceActions(context: SettingsWorkspaceStateContext & SettingsEditingActionsContext & SettingsPersistenceActionsContext) {
  const {
      setClearingEvidence, setActionMessage, setActionMessageKind, setExporting, setRepairing,
      setExportingSettings, settingsImportInputRef, savedSettingsRef, openProofModal, executeImportSettings,
      executeResetSettings, setSettingUpNotifications, setNotificationSetup,
    } = context;

  const handleClearEvidence = useCallback(async () => {
    if (!window.confirm("Clear the evidence log permanently? This cannot be undone.")) return;
    setClearingEvidence(true);
    setActionMessage(null);
    try {
      await clearEvidence();
      setActionMessage("Evidence log cleared.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear evidence.");
      setActionMessageKind("error");
    } finally {
      setClearingEvidence(false);
    }
  }, []);

  const handleExportDiagnostics = useCallback(async () => {
    setExporting(true);
    setActionMessage(null);
    try {
      const blob = await exportDiagnostics();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `guard-diagnostics-${Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      setActionMessage("Diagnostics exported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to export diagnostics.");
      setActionMessageKind("error");
    } finally {
      setExporting(false);
    }
  }, []);

  const handleRepairApprovalCenter = useCallback(async () => {
    if (!window.confirm("Reset the approval center locator? The daemon will be reachable again after Guard restarts. Pending approvals are preserved.")) return;
    setRepairing(true);
    setActionMessage(null);
    try {
      await repairApprovalCenter();
      setActionMessage("Approval center repaired. Restart Guard to reconnect.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to repair approval center.");
      setActionMessageKind("error");
    } finally {
      setRepairing(false);
    }
  }, []);

  const handleExportSettings = useCallback(async () => {
    setExportingSettings(true);
    setActionMessage(null);
    try {
      const exported = await exportSettings();
      const blob = new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `guard-settings-${Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      setActionMessage("Settings exported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to export settings.");
      setActionMessageKind("error");
    } finally {
      setExportingSettings(false);
    }
  }, []);

  const handleImportSettingsClick = useCallback(() => {
    settingsImportInputRef.current?.click();
  }, []);

  const handleImportSettingsFile = useCallback(async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setActionMessage(null);
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as GuardSettingsExport;
      const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
      if (savedGateEnabled) {
        openProofModal("maintenance", {
          kind: "maintenance",
          action: "import-settings",
          importExport: parsed,
        });
        return;
      }
      await executeImportSettings(parsed);
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to import settings.");
      setActionMessageKind("error");
    }
  }, [executeImportSettings, openProofModal]);

  const handleResetSettings = useCallback(async () => {
    if (!window.confirm("Reset all local Guard settings to defaults? This cannot be undone.")) return;
    const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
    if (savedGateEnabled) {
      openProofModal("maintenance", { kind: "maintenance", action: "reset-settings" });
      return;
    }
    try {
      await executeResetSettings();
    } catch {
      // executeResetSettings already surfaces the error message.
    }
  }, [executeResetSettings, openProofModal]);

  const handleSetupNotifications = useCallback(async () => {
    setSettingUpNotifications(true);
    setActionMessage(null);
    try {
      const result = await setupDesktopNotifications();
      setNotificationSetup(result);
      if (!result.supported) {
        setActionMessage("Desktop notification setup is not available on this OS.");
        setActionMessageKind("error");
      } else if (result.settings_opened) {
        setActionMessage("Notification settings opened. Turn on alerts and sounds for Guard.");
        setActionMessageKind("success");
      } else {
        setActionMessage(
          "We could not open Settings automatically. Open System Settings > Notifications and allow alerts for Guard."
        );
        setActionMessageKind("success");
      }
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to set up notifications.");
      setActionMessageKind("error");
    } finally {
      setSettingUpNotifications(false);
    }
  }, []);

  return {
      handleClearEvidence, handleExportDiagnostics, handleRepairApprovalCenter, handleExportSettings, handleImportSettingsClick,
      handleImportSettingsFile, handleResetSettings, handleSetupNotifications,
  };
}

export type SettingsMaintenanceActionsContext = ReturnType<typeof useSettingsMaintenanceActions>;
