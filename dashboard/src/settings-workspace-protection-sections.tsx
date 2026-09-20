import { ProtectionPosturePanel } from "./protection-posture-panel";
import { SettingsFormSection, SettingsSelectRow, SettingsToggleRow } from "./settings/settings-row-primitives";
import { CloudReviewSettings } from "./settings/cloud-review-settings";
import { lockedProtectionPostures, surfacePolicyOptions } from "./settings-workspace-model";
import { ApprovalGateCard } from "./settings-approval-gate-card";
import { NotificationSetupCard, SettingsActionMessage } from "./settings-workspace-cards";
import type { SettingsWorkspaceReadyContext } from "./settings-workspace-context";

export function renderProtectionSettings({
  consequenceSummary, selectedPosture, draft, protectionCapabilities, handleProtectionPostureChange,
  handleTimeoutChange, handleTelemetryToggle, handleSyncToggle, handleStringChange, handleBillingToggle,
  perfSnapshot,
}: Pick<SettingsWorkspaceReadyContext, "consequenceSummary" | "selectedPosture" | "draft" | "protectionCapabilities" | "handleProtectionPostureChange" | "handleTimeoutChange" | "handleTelemetryToggle" | "handleSyncToggle" | "handleStringChange" | "handleBillingToggle" | "perfSnapshot">) {
  return (
          <div className="flex min-h-0 flex-1 flex-col space-y-6">
            <SettingsFormSection
              title="Protection"
              description={consequenceSummary}
            >
              <ProtectionPosturePanel
                posture={selectedPosture}
                customRules={draft.security_level === "custom"}
                capabilities={protectionCapabilities}
                disabledPostures={lockedProtectionPostures(draft)}
                onPostureChange={handleProtectionPostureChange}
              />
            </SettingsFormSection>

            <SettingsFormSection title="Timing and features">
              <div className="space-y-4 py-3">
                <div>
                  <label htmlFor="approval-wait" className="guard-settings-body font-medium text-brand-dark">
                    How long to wait for your answer
                  </label>
                  <p className="guard-settings-caption text-slate-500">
                    Seconds before Guard returns control to your AI app
                  </p>
                  <input
                    id="approval-wait"
                    type="number"
                    min={0}
                    max={600}
                    value={draft.approval_wait_timeout_seconds}
                    onChange={handleTimeoutChange}
                    className="mt-2 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
                  />
                </div>
                <SettingsToggleRow
                  label="Telemetry"
                  description="Share anonymized usage to improve Guard."
                  checked={draft.telemetry}
                  onChange={handleTelemetryToggle}
                />
                <SettingsToggleRow
                  label="Cloud sync"
                  description="Sync receipts and policy with Guard Cloud when connected."
                  checked={draft.sync}
                  onChange={handleSyncToggle}
                />
                <CloudReviewSettings />
                <SettingsSelectRow
                  label="Cloud receipt privacy"
                  description="Choose how much command detail Guard includes when syncing receipts. Secrets are always removed."
                  value={draft.receipt_redaction_level}
                  onChange={handleStringChange("receipt_redaction_level")}
                  options={[
                    { value: "full", label: "Fully redacted - metadata only" },
                    { value: "partial", label: "Partially redacted - hide paths and package names" },
                    { value: "none", label: "Detailed - include commands, paths, hosts, and packages" },
                  ]}
                />
                <SettingsToggleRow
                  label="Billing features"
                  description="Enable paid supply-chain and blocked-install analytics."
                  checked={draft.billing}
                  onChange={handleBillingToggle}
                />
                {perfSnapshot !== null && perfSnapshot.cloud_state === "local_only" && draft.billing ? (
                  <p className="guard-settings-caption -mt-1 text-slate-500">
                    Billing features require a cloud connection. Connect this machine to access paid features.
                  </p>
                ) : null}
              </div>
            </SettingsFormSection>
          </div>
        );
}

export function renderApprovalSettings({
  approvalGateEnabled, draft, handleStringChange, handleNumberChange, savedSettingsRef,
  approvalGateTotpCode, approvalGateTotpDeviceLabel, approvalGateStrictAllDecisions, approvalGateCooldown, totpEnrollment,
  totpSetupOpen, totpSetupStep, totpActionPassword, totpActionPending, totpActionError,
  handleApprovalGateToggle, handleOpenPasswordChangeModal, handleApprovalGateTotpCode, handleApprovalGateTotpDeviceLabel, handleTotpActionPasswordChange,
  handleOpenTotpSetup, handleCloseTotpSetup, handleApprovalGateStrictAllDecisions, handleApprovalGateCooldownChange, handleStartTotpEnrollment,
  handleVerifyTotpEnrollment, handleDisableTotp, handleRequestRevokeCooldown,
}: Pick<SettingsWorkspaceReadyContext, "approvalGateEnabled" | "draft" | "handleStringChange" | "handleNumberChange" | "savedSettingsRef" | "approvalGateTotpCode" | "approvalGateTotpDeviceLabel" | "approvalGateStrictAllDecisions" | "approvalGateCooldown" | "totpEnrollment" | "totpSetupOpen" | "totpSetupStep" | "totpActionPassword" | "totpActionPending" | "totpActionError" | "handleApprovalGateToggle" | "handleOpenPasswordChangeModal" | "handleApprovalGateTotpCode" | "handleApprovalGateTotpDeviceLabel" | "handleTotpActionPasswordChange" | "handleOpenTotpSetup" | "handleCloseTotpSetup" | "handleApprovalGateStrictAllDecisions" | "handleApprovalGateCooldownChange" | "handleStartTotpEnrollment" | "handleVerifyTotpEnrollment" | "handleDisableTotp" | "handleRequestRevokeCooldown">) {
  return (
          <div className="flex min-h-0 flex-1 flex-col space-y-4">
            {!approvalGateEnabled ? (
              <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] px-4 py-3">
                <p className="text-sm text-brand-dark">
                  Add a password or phone app code before allow or trust changes stick.
                </p>
              </div>
            ) : null}
            <SettingsFormSection
              title="Where Guard asks"
              description="This only chooses the surface for Ask once. It does not change what Guard stops."
            >
              <div className="space-y-4 py-3">
                <SettingsSelectRow
                  label="Ask surface"
                  description="In the app when possible, always in Guard, or never open a browser."
                  value={draft.approval_surface_policy}
                  onChange={handleStringChange("approval_surface_policy")}
                  options={surfacePolicyOptions}
                />
                {draft.approval_surface_policy === "attention-aware" ? (
                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="block">
                      <span className="text-sm font-medium text-brand-dark">Browser delay (seconds)</span>
                      <input
                        type="number"
                        min={0}
                        max={120}
                        value={draft.approval_browser_delay_seconds}
                        onChange={handleNumberChange("approval_browser_delay_seconds")}
                        className="mt-2 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm"
                      />
                    </label>
                  </div>
                ) : null}
              </div>
            </SettingsFormSection>
            <ApprovalGateCard
              enabled={approvalGateEnabled}
              gateConfig={draft.approval_gate ?? null}
              savedGateConfig={savedSettingsRef.current?.approval_gate ?? null}
              totpCode={approvalGateTotpCode}
              totpDeviceLabel={approvalGateTotpDeviceLabel}
              strictAllDecisions={approvalGateStrictAllDecisions}
              cooldownSeconds={approvalGateCooldown}
              totpEnrollment={totpEnrollment}
              totpSetupOpen={totpSetupOpen}
              totpSetupStep={totpSetupStep}
              totpActionPassword={totpActionPassword}
              totpActionPending={totpActionPending}
              totpActionError={totpActionError}
              onToggle={handleApprovalGateToggle}
              onOpenPasswordChangeModal={handleOpenPasswordChangeModal}
              onTotpCodeChange={handleApprovalGateTotpCode}
              onTotpDeviceLabelChange={handleApprovalGateTotpDeviceLabel}
              onTotpActionPasswordChange={handleTotpActionPasswordChange}
              onOpenTotpSetup={handleOpenTotpSetup}
              onCloseTotpSetup={handleCloseTotpSetup}
              onStrictAllDecisionsChange={handleApprovalGateStrictAllDecisions}
              onCooldownChange={handleApprovalGateCooldownChange}
              onStartTotpEnrollment={handleStartTotpEnrollment}
              onVerifyTotpEnrollment={handleVerifyTotpEnrollment}
              onDisableTotp={handleDisableTotp}
              onRevokeCooldown={handleRequestRevokeCooldown}
            />
          </div>
        );
}

export function renderNotificationsSettings({
  notificationSetup, settingUpNotifications, handleSetupNotifications, actionMessage, actionMessageKind,
}: Pick<SettingsWorkspaceReadyContext, "notificationSetup" | "settingUpNotifications" | "handleSetupNotifications" | "actionMessage" | "actionMessageKind">) {
  return (
          <div className="flex min-h-0 flex-1 flex-col space-y-4">
            <NotificationSetupCard
              result={notificationSetup}
              settingUp={settingUpNotifications}
              onSetup={handleSetupNotifications}
            />
            <SettingsActionMessage message={actionMessage} kind={actionMessageKind} />
          </div>
        );
}
