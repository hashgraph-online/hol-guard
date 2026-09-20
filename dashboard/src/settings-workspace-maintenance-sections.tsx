import { HiMiniChevronDown } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { SettingsFormSection, SettingsToggleRow } from "./settings/settings-row-primitives";
import { isFineTuningEditable, resolveFineTuningSectionDescription, riskControls, actionOptions, lockedSetting } from "./settings-workspace-model";
import { FineTuningPresetBanner, RiskControlRow, SettingSelect, DiagnosticsPerfCard, SettingsActionMessage } from "./settings-workspace-cards";
import type { SettingsWorkspaceReadyContext } from "./settings-workspace-context";

export function renderRulesSettings({
  draft, selectedPosture, handleSwitchToCustomFineTuning, handleRiskActionChange, handleCodexSecretReadChange,
  handleStringChange, handleWatchAutoRevertToggle,
}: Pick<SettingsWorkspaceReadyContext, "draft" | "selectedPosture" | "handleSwitchToCustomFineTuning" | "handleRiskActionChange" | "handleCodexSecretReadChange" | "handleStringChange" | "handleWatchAutoRevertToggle">) {
  return (
          <div className="flex min-h-0 flex-1 flex-col space-y-6">
            {!isFineTuningEditable(draft.security_level) ? (
              <FineTuningPresetBanner
                securityLevel={draft.security_level}
                posture={selectedPosture}
                onSwitchToCustom={handleSwitchToCustomFineTuning}
              />
            ) : null}
            <SettingsFormSection
              title="Risky action types"
              description={resolveFineTuningSectionDescription(draft.security_level)}
            >
              <div className={`space-y-1 ${!isFineTuningEditable(draft.security_level) ? "opacity-60" : ""}`}>
                {riskControls.map((risk) => (
                  <RiskControlRow
                    key={risk.key}
                    risk={risk}
                    value={draft.risk_actions[risk.key] ?? "require-reapproval"}
                    disabled={!isFineTuningEditable(draft.security_level)}
                    onChange={handleRiskActionChange(risk.key)}
                    showConsequence={isFineTuningEditable(draft.security_level)}
                  />
                ))}
                <div className="grid gap-2 border-t border-slate-100 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center">
                  <div>
                    <p className="text-sm font-medium text-brand-dark">Codex reading secret files</p>
                    <p className="text-xs text-slate-500">
                      Only for trusted projects where Codex may read .env or .npmrc without an extra prompt.
                    </p>
                  </div>
                  <SettingSelect
                    label="Codex should"
                    value={
                      draft.harness_risk_actions.codex?.local_secret_read
                      ?? draft.risk_actions.local_secret_read
                      ?? "require-reapproval"
                    }
                    options={actionOptions}
                    onChange={handleCodexSecretReadChange}
                    disabled={!isFineTuningEditable(draft.security_level)}
                  />
                </div>
              </div>
            </SettingsFormSection>

            <details className="group rounded-xl border border-slate-200 bg-slate-50/40 open:bg-white">
              <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-4 rounded-xl px-4 py-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/50 [&::-webkit-details-marker]:hidden">
                <span>
                  <span className="block text-sm font-semibold text-brand-dark">Advanced fallback behavior</span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-slate-500">
                    Decide what happens when Guard has no remembered rule or specific risk match.
                  </span>
                </span>
                <HiMiniChevronDown className="h-5 w-5 shrink-0 text-slate-400 transition-transform group-open:rotate-180" aria-hidden="true" />
              </summary>
              <div className="border-t border-slate-100 px-4 pb-4">
                <div className="grid gap-3 py-4 sm:grid-cols-2">
                  <SettingSelect label="First-time action" value={draft.default_action} options={actionOptions} onChange={handleStringChange("default_action")} />
                  <SettingSelect label="Unknown source" value={draft.unknown_publisher_action} options={actionOptions} onChange={handleStringChange("unknown_publisher_action")} />
                  <SettingSelect label="Changed command" value={draft.changed_hash_action} options={actionOptions} onChange={handleStringChange("changed_hash_action")} />
                  <SettingSelect label="New website or host" value={draft.new_network_domain_action} options={actionOptions} onChange={handleStringChange("new_network_domain_action")} />
                  <SettingSelect label="Nested commands" value={draft.subprocess_action} options={actionOptions} onChange={handleStringChange("subprocess_action")} />
                </div>
                <div className="border-t border-slate-100 py-4">
                  <SettingsToggleRow
                    label="Auto-revert Watch"
                    description="Turn protection back on after 24 hours unless you disable this."
                    checked={(draft.watch_auto_revert_hours ?? 24) > 0}
                    disabled={lockedSetting(draft, "watch_auto_revert_hours")}
                    onChange={handleWatchAutoRevertToggle}
                  />
                </div>
              </div>
            </details>
          </div>
        );
}

export function renderMaintenanceSettings({
  perfSnapshot, settingsImportInputRef, handleImportSettingsFile, handleClearApprovals, clearingApprovals,
  handleClearReviewQueue, clearingReviewQueue, handleClearEvidence, clearingEvidence, handleExportSettings,
  exportingSettings, handleImportSettingsClick, importingSettings, handleExportDiagnostics, exporting,
  handleResetSettings, resettingSettings, handleRepairApprovalCenter, repairing, actionMessage,
  actionMessageKind,
}: Pick<SettingsWorkspaceReadyContext, "perfSnapshot" | "settingsImportInputRef" | "handleImportSettingsFile" | "handleClearApprovals" | "clearingApprovals" | "handleClearReviewQueue" | "clearingReviewQueue" | "handleClearEvidence" | "clearingEvidence" | "handleExportSettings" | "exportingSettings" | "handleImportSettingsClick" | "importingSettings" | "handleExportDiagnostics" | "exporting" | "handleResetSettings" | "resettingSettings" | "handleRepairApprovalCenter" | "repairing" | "actionMessage" | "actionMessageKind">) {
  return (
          <div className="flex min-h-0 flex-1 flex-col space-y-6">
            <SettingsFormSection title="Keep this machine tidy" description="Export, reset, clear history, or fix a broken approval link.">
              <div className="space-y-4 py-3">
                {perfSnapshot !== null ? <DiagnosticsPerfCard snapshot={perfSnapshot} /> : null}
                <input
                  ref={settingsImportInputRef}
                  type="file"
                  accept="application/json,.json"
                  className="sr-only"
                  onChange={handleImportSettingsFile}
                  aria-hidden="true"
                  tabIndex={-1}
                />
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-3">
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Clear saved approvals</p>
                      <p className="text-xs text-slate-500">Guard will ask again for every action that was previously approved.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleClearApprovals} disabled={clearingApprovals} variant="outline">
                          {clearingApprovals ? "Clearing…" : "Clear approvals"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Clear review queue</p>
                      <p className="text-xs text-slate-500">Removes pending review items only.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleClearReviewQueue} disabled={clearingReviewQueue} variant="outline">
                          {clearingReviewQueue ? "Clearing…" : "Clear review queue"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Clear evidence log</p>
                      <p className="text-xs text-slate-500">Permanently removes local audit history.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleClearEvidence} disabled={clearingEvidence} variant="outline">
                          {clearingEvidence ? "Clearing…" : "Clear evidence"}
                        </ActionButton>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Export settings</p>
                      <p className="text-xs text-slate-500">Download local Guard preferences as JSON.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleExportSettings} disabled={exportingSettings} variant="secondary">
                          {exportingSettings ? "Exporting…" : "Export settings"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Import settings</p>
                      <p className="text-xs text-slate-500">Restore preferences from a Guard settings export file.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleImportSettingsClick} disabled={importingSettings} variant="secondary">
                          {importingSettings ? "Importing…" : "Import settings"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Export diagnostics</p>
                      <p className="text-xs text-slate-500">Download evidence and runtime details for support.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleExportDiagnostics} disabled={exporting} variant="secondary">
                          {exporting ? "Exporting…" : "Export diagnostics"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Reset to defaults</p>
                      <p className="text-xs text-slate-500">Restore factory local settings on this machine.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleResetSettings} disabled={resettingSettings} variant="outline">
                          {resettingSettings ? "Resetting…" : "Reset settings"}
                        </ActionButton>
                      </div>
                    </div>
                    <div id="approval-center-repair">
                      <p className="text-sm font-semibold text-brand-dark">Repair approval center</p>
                      <p className="text-xs text-slate-500">Use when the approval link fails after Guard restarts.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleRepairApprovalCenter} disabled={repairing} variant="secondary">
                          {repairing ? "Repairing…" : "Repair"}
                        </ActionButton>
                      </div>
                    </div>
                  </div>
                </div>
                <SettingsActionMessage message={actionMessage} kind={actionMessageKind} />
              </div>
            </SettingsFormSection>
          </div>
        );
}
