import type { SettingsWorkspaceStateContext } from "./use-settings-workspace-state";
import type { SettingsEditingActionsContext } from "./use-settings-editing-actions";
import type { SettingsPersistenceActionsContext } from "./use-settings-persistence-actions";
import type { SettingsApprovalActionsContext } from "./use-settings-approval-actions";
import type { SettingsMaintenanceActionsContext } from "./use-settings-maintenance-actions";
import type { GuardSettings, GuardProtectionCapability } from "./guard-types";
import type { ProtectionPosture } from "./protection-posture-copy";

export type SettingsWorkspaceContext = SettingsWorkspaceStateContext & SettingsEditingActionsContext & SettingsPersistenceActionsContext & SettingsApprovalActionsContext & SettingsMaintenanceActionsContext;

export type SettingsWorkspaceReadyContext = Omit<SettingsWorkspaceContext, "draft"> & {
  draft: GuardSettings;
  consequenceSummary: string;
  selectedPosture: ProtectionPosture;
  protectionCapabilities: GuardProtectionCapability[];
};
