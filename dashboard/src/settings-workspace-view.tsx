import { HiMiniShieldCheck, HiMiniCheckCircle, HiMiniExclamationTriangle, HiMiniMagnifyingGlass } from "react-icons/hi2";
import { ActionButton, EmptyState, SectionLabel } from "./approval-center-primitives";
import { filterSettingsBySearch } from "./apps/app-catalog";
import { WorkspacePageHeader } from "./workspace-page-header";
import { WatchProtectionBanner } from "./watch-protection-banner";
import { SettingsSaveProofModal, resolveSettingsSaveProofModalCopy } from "./settings-save-proof-modal";
import type { GuardProtectionCapability } from "./guard-types";
import { SettingsSectionShell } from "./settings/settings-section-shell";
import { buildConsequenceSummary, currentProtectionPosture, riskControls, isFineTuningEditable, hasUnsavedChanges, saveStatusText, hasApprovalGateSettingsChanged } from "./settings-workspace-model";
import { FineTuningPresetBanner, RiskControlRow } from "./settings-workspace-cards";
import type { SettingsWorkspaceContext } from "./settings-workspace-context";
import { renderProtectionSettings, renderApprovalSettings, renderNotificationsSettings } from "./settings-workspace-protection-sections";
import { renderRulesSettings, renderMaintenanceSettings } from "./settings-workspace-maintenance-sections";

export function renderSettingsWorkspace(context: SettingsWorkspaceContext) {
  const {
    state, draft, searchQuery, activeTab, handleTurnProtectionOn,
    handleSearchChange, handleSwitchToCustomFineTuning, handleRiskActionChange, handleTabChange, handleProtectionPostureChange,
    handleTimeoutChange, handleTelemetryToggle, handleSyncToggle, handleStringChange, handleBillingToggle,
    perfSnapshot, approvalGateEnabled, handleNumberChange, savedSettingsRef, approvalGateTotpCode,
    approvalGateTotpDeviceLabel, approvalGateStrictAllDecisions, approvalGateCooldown, totpEnrollment, totpSetupOpen,
    totpSetupStep, totpActionPassword, totpActionPending, totpActionError, handleApprovalGateToggle,
    handleOpenPasswordChangeModal, handleApprovalGateTotpCode, handleApprovalGateTotpDeviceLabel, handleTotpActionPasswordChange, handleOpenTotpSetup,
    handleCloseTotpSetup, handleApprovalGateStrictAllDecisions, handleApprovalGateCooldownChange, handleStartTotpEnrollment, handleVerifyTotpEnrollment,
    handleDisableTotp, handleRequestRevokeCooldown, notificationSetup, settingUpNotifications, handleSetupNotifications,
    actionMessage, actionMessageKind, handleCodexSecretReadChange, handleWatchAutoRevertToggle, settingsImportInputRef,
    handleImportSettingsFile, handleClearApprovals, clearingApprovals, handleClearReviewQueue, clearingReviewQueue,
    handleClearEvidence, clearingEvidence, handleExportSettings, exportingSettings, handleImportSettingsClick,
    importingSettings, handleExportDiagnostics, exporting, handleResetSettings, resettingSettings,
    handleRepairApprovalCenter, repairing, handleSave, saving, saveSuccess,
    saveError, proofModalOpen, pendingProofAction, proofModalMode, proofModalError,
    proofModalPending, closeProofModal, handleProofModalConfirm, pendingMode, pendingPosture,
    confirmModeChange, cancelModeChange,
  } = context;

  if (state.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-10 w-64" />
        <div className="guard-skeleton h-72 w-full" />
      </div>
    );
  }
  if (state.kind === "error" || draft === null) {
    return <EmptyState title="Settings are unavailable" body={state.kind === "error" ? state.message : "Guard did not return editable settings."} tone="teach" />;
  }

  const consequenceSummary = buildConsequenceSummary(draft);
  const selectedPosture = currentProtectionPosture(draft);
  const protectionCapabilities: GuardProtectionCapability[] = state.kind === "ready"
    ? (state.payload.protection_capabilities ?? [])
    : [];
  const searchMatches = filterSettingsBySearch(searchQuery);
  const hasSearch = searchQuery.trim().length > 0;
  const riskSearchMatches = searchMatches.filter((m) => m.section === "risk");
  const visibleRiskControls = hasSearch
    ? riskControls.filter((rc) => riskSearchMatches.some((m) => m.key === rc.key))
    : riskControls;

  return (
    <div className="flex min-h-[calc(100dvh-11rem)] flex-col gap-6">
      <WorkspacePageHeader
        eyebrow="This machine"
        title={activeTab === "experience" ? "Experience" : "Protection"}
        description="Guard stops dangerous actions automatically and asks once about new or unknown work."
      />
      {selectedPosture === "watch" ? (
        <WatchProtectionBanner onTurnProtectionOn={handleTurnProtectionOn} />
      ) : null}

      <div className="relative">
        <HiMiniMagnifyingGlass className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
        <input
          id="settings-search"
          name="settings-search"
          type="search"
          value={searchQuery}
          onChange={handleSearchChange}
          placeholder="Search settings..."
          aria-label="Search settings"
          className="w-full rounded-xl border border-slate-200 bg-white py-2.5 pl-9 pr-4 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </div>

      {hasSearch && searchMatches.length === 0 && (
        <p className="text-sm text-slate-500">No settings match your search.</p>
      )}

      {hasSearch && riskSearchMatches.length > 0 && (
        <div className="rounded-xl border border-slate-100 p-4">
          <SectionLabel>Matching fine-tuning rules</SectionLabel>
          {!isFineTuningEditable(draft.security_level) ? (
            <div className="mt-3">
              <FineTuningPresetBanner
                securityLevel={draft.security_level}
                posture={selectedPosture}
                onSwitchToCustom={handleSwitchToCustomFineTuning}
              />
            </div>
          ) : null}
          <div className="mt-3 divide-y divide-slate-100 border-t border-slate-100">
            {visibleRiskControls.map((risk) => (
              <RiskControlRow
                key={risk.key}
                risk={risk}
                value={draft.risk_actions[risk.key] ?? "require-reapproval"}
                disabled={!isFineTuningEditable(draft.security_level)}
                onChange={handleRiskActionChange(risk.key)}
                showConsequence
              />
            ))}
          </div>
        </div>
      )}

      <div className="flex min-h-0 flex-1 flex-col">
      <SettingsSectionShell
        activeTab={activeTab}
        onTabChange={handleTabChange}
        intro={
          !hasSearch && activeTab === "protection" && consequenceSummary ? (
            <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4">
              <div className="flex items-start gap-3">
                <HiMiniShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" aria-hidden="true" />
                <div>
                  <SectionLabel>What to expect</SectionLabel>
                  <p className="mt-1 text-sm text-slate-500">{consequenceSummary}</p>
                </div>
              </div>
            </div>
          ) : null
        }
      >
        {activeTab === "protection" && renderProtectionSettings({ consequenceSummary, selectedPosture, draft, protectionCapabilities, handleProtectionPostureChange, handleTimeoutChange, handleTelemetryToggle, handleSyncToggle, handleStringChange, handleBillingToggle, perfSnapshot })}

        {activeTab === "approval" && renderApprovalSettings({ approvalGateEnabled, draft, handleStringChange, handleNumberChange, savedSettingsRef, approvalGateTotpCode, approvalGateTotpDeviceLabel, approvalGateStrictAllDecisions, approvalGateCooldown, totpEnrollment, totpSetupOpen, totpSetupStep, totpActionPassword, totpActionPending, totpActionError, handleApprovalGateToggle, handleOpenPasswordChangeModal, handleApprovalGateTotpCode, handleApprovalGateTotpDeviceLabel, handleTotpActionPasswordChange, handleOpenTotpSetup, handleCloseTotpSetup, handleApprovalGateStrictAllDecisions, handleApprovalGateCooldownChange, handleStartTotpEnrollment, handleVerifyTotpEnrollment, handleDisableTotp, handleRequestRevokeCooldown })}

        {activeTab === "notifications" && renderNotificationsSettings({ notificationSetup, settingUpNotifications, handleSetupNotifications, actionMessage, actionMessageKind })}

        {activeTab === "rules" && renderRulesSettings({ draft, selectedPosture, handleSwitchToCustomFineTuning, handleRiskActionChange, handleCodexSecretReadChange, handleStringChange, handleWatchAutoRevertToggle })}

        {activeTab === "maintenance" && renderMaintenanceSettings({ perfSnapshot, settingsImportInputRef, handleImportSettingsFile, handleClearApprovals, clearingApprovals, handleClearReviewQueue, clearingReviewQueue, handleClearEvidence, clearingEvidence, handleExportSettings, exportingSettings, handleImportSettingsClick, importingSettings, handleExportDiagnostics, exporting, handleResetSettings, resettingSettings, handleRepairApprovalCenter, repairing, actionMessage, actionMessageKind })}
      </SettingsSectionShell>
      </div>

      <div
        className="sticky bottom-2 mt-auto rounded-xl border border-slate-200 bg-white/95 p-3 shadow-lg backdrop-blur sm:bottom-4 sm:p-4"
        role="region"
        aria-label="Save settings"
        hidden={activeTab === "experience"}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <ActionButton onClick={handleSave} disabled={saving || saveSuccess}>
              {saveSuccess ? (
                <span className="flex items-center gap-2">
                  <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
                  Saved
                </span>
              ) : saving ? "Saving…" : "Save settings"}
            </ActionButton>
            {hasUnsavedChanges(savedSettingsRef.current, draft) && (
              <span className="ml-3 inline-flex items-center gap-1.5 text-xs font-medium text-brand-attention">
                <span className="h-1.5 w-1.5 rounded-full bg-brand-attention" />
                Unsaved changes
              </span>
            )}
          </div>
          {saveSuccess ? (
            <p className="text-sm font-semibold text-emerald-600">Settings saved</p>
          ) : saveError ? (
            <p className="text-sm text-brand-purple">{saveError}</p>
          ) : (
            <p className="hidden text-xs text-slate-500 sm:block">Use this for local tuning. Team policy from Guard Cloud may still override some decisions.</p>
          )}
          <div aria-live="polite" aria-atomic="true" className="sr-only">
            {saveStatusText(saveSuccess, saveError)}
          </div>
        </div>
      </div>

      {proofModalOpen && pendingProofAction !== null ? (
        <SettingsSaveProofModal
          open={proofModalOpen}
          mode={proofModalMode}
          gate={savedSettingsRef.current?.approval_gate ?? null}
          {...resolveSettingsSaveProofModalCopy({
            mode: proofModalMode,
            gateSettingsChanged: hasApprovalGateSettingsChanged(
              savedSettingsRef.current?.approval_gate ?? null,
              approvalGateEnabled,
              approvalGateCooldown,
              approvalGateStrictAllDecisions,
            ),
            maintenanceAction: pendingProofAction.kind === "maintenance"
              ? pendingProofAction.action
              : undefined,
          })}
          error={proofModalError}
          pending={proofModalPending || saving || importingSettings || resettingSettings}
          onCancel={closeProofModal}
          onConfirm={handleProofModalConfirm}
        />
      ) : null}

      {(pendingMode === "observe" || pendingPosture === "watch") && (
        <div className="guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-brand-attention/15 bg-white p-6 shadow-xl">
            <div className="flex items-start gap-3">
              <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-attention/10">
                <HiMiniExclamationTriangle className="h-5 w-5 text-brand-attention" aria-hidden="true" />
              </span>
              <div>
                <h3 className="text-base font-semibold text-brand-dark">Switch to Watch?</h3>
                <p className="mt-2 text-sm text-slate-500">Protection is off. Guard is only recording. Use this only while debugging.</p>
              </div>
            </div>
            <div className="mt-6 flex flex-wrap gap-2">
              <button onClick={confirmModeChange} className="inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90">Switch to Watch</button>
              <button onClick={cancelModeChange} className="inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50">Keep protection on</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
