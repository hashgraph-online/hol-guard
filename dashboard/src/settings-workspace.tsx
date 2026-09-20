import { resolveInitialSettingsTab } from "./settings/settings-ia";
import type { SettingsWorkspaceProps } from "./settings-workspace-model";
import { useSettingsWorkspaceState } from "./use-settings-workspace-state";
import { useSettingsEditingActions } from "./use-settings-editing-actions";
import { useSettingsPersistenceActions } from "./use-settings-persistence-actions";
import { useSettingsApprovalActions } from "./use-settings-approval-actions";
import { useSettingsMaintenanceActions } from "./use-settings-maintenance-actions";
import { renderSettingsWorkspace } from "./settings-workspace-view";

export {
  buildTotpQrImageOptions,
  formatTotpEnrollmentExpiry,
  formatTotpManualKey,
  TotpEnrollmentQrPanel,
} from "./totp-enrollment-qr-panel";
export { resolveApprovalPasswordSectionCopy } from "./settings/approval-password-copy";
export {
  buildSettingsUpdatePayload,
  isPresentationOnlyChange,
  presentationOnlySavePayload,
  resolveSettingsPresentation,
} from "./settings-presentation";
export { resolveInitialSettingsTab };
export { resolveSecurityLevelDescription, resolveSecurityLevelCardDescription, resolveFineTuningSectionDescription, isFineTuningEditable, buildClearPolicyPayload, buildClearReviewQueuePayload, buildApprovalGateWriteProof, type TotpSetupStep, resolveTotpSetupStep, hasApprovalGateSettingsChanged, effectiveApprovalGateCooldownSeconds, resolveTotpSetupModalTitle, resolveTotpSetupModalDescription, hasUnsavedChanges, applyApprovalGateDraft } from "./settings-workspace-model";

export function SettingsWorkspace({ onApprovalGateChange }: SettingsWorkspaceProps) {
  const state = useSettingsWorkspaceState({ onApprovalGateChange });
  const editing = useSettingsEditingActions(state);
  const persistence = useSettingsPersistenceActions({ ...state, ...editing });
  const approval = useSettingsApprovalActions({ ...state, ...editing, ...persistence });
  const maintenance = useSettingsMaintenanceActions({ ...state, ...editing, ...persistence, ...approval });
  return renderSettingsWorkspace({ ...state, ...editing, ...persistence, ...approval, ...maintenance });
}
