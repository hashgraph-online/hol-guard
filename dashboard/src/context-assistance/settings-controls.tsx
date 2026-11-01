import { useId } from "react";
import type { GuardContextAssistanceConfig } from "../guard-types";
import { SettingsFormSection, SettingsSelectRow, SettingsToggleRow } from "../settings/settings-row-primitives";
import { contextStatusCopy } from "./status";
import { withContextProfile } from "./settings-model";
import type { ContextAssistanceStatus, ContextControlAction, ContextInstallation } from "./types";
import { ContextExecutionPanel } from "./execution-panel";
import { CigarRuntimeSelection } from "./runtime-selection";

export type ContextSettingsControlsProps = {
  value: GuardContextAssistanceConfig | null;
  status: ContextAssistanceStatus | null;
  installations: ContextInstallation[] | null;
  loading: boolean;
  busy: boolean;
  disabled: boolean;
  locked: boolean;
  dirty: boolean;
  error: string | null;
  onChange: (value: GuardContextAssistanceConfig) => void;
  onRefresh: () => void;
  onChooseRuntime: () => void;
  onManageVersions?: () => void;
  onControl: (action: ContextControlAction) => void;
};

const buttonClass = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50";

export function ContextSettingsControls(props: ContextSettingsControlsProps) {
  const { value, status, installations } = props;
  const titleId = useId();
  const statusCopy = status ? contextStatusCopy(status) : null;
  const selected = installations?.some((item) => item.runtime_id === value?.runtime_id) === true;
  const disabled = props.disabled || props.busy;
  const editingDisabled = disabled || props.locked || value === null || status === null;
  const checkDisabled = disabled || props.dirty || !status?.verification_permitted || Boolean(status?.job) || !value?.runtime_id;
  const stopped = !value?.enabled && !status?.requested_enabled && !status?.job && !status?.effective_enabled;
  const runtime = status?.runtime ?? status?.last_check;
  return (
    <SettingsFormSection title="Context assistance" description="Optional local context from CIGAR helps explain work using the sources you authorize.">
      <div className="space-y-4 py-4" aria-labelledby={titleId}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h4 id={titleId} className="text-sm font-semibold text-brand-dark">{runtime ? "CIGAR " + runtime.package_version : "CIGAR runtime"}</h4>
            <p className="mt-1 text-sm text-slate-600" role="status" aria-live="polite">
              {props.loading ? "Checking availability…" : statusCopy ? `${statusCopy.label}. ${statusCopy.detail}` : "Availability has not been verified."}
            </p>
          </div>
          <button type="button" className={buttonClass} disabled={disabled || props.loading} onClick={props.onRefresh}>
            Refresh status
          </button>
        </div>
        {props.error ? <p role="alert" className="text-sm text-red-700">{props.error}</p> : null}
        {props.dirty ? <p role="status" className="text-sm text-slate-600">Save settings before checking or starting this runtime.</p> : null}
        <div className="flex flex-wrap gap-2">
          {status?.requested_enabled && !status.effective_enabled ? (
            <button type="button" className={buttonClass + " border-brand-blue bg-brand-blue/10"}
              disabled={checkDisabled || !status.effective_preferences.enabled}
              onClick={() => props.onControl("activate")}>Start context assistance</button>
          ) : null}
          <button type="button" className={buttonClass} disabled={checkDisabled} onClick={() => props.onControl("recheck")}>Check selected runtime</button>
          {!stopped ? <button type="button" className={buttonClass} disabled={disabled} onClick={() => props.onControl("stop")}>Turn off now</button> : null}
        </div>
        <p className="text-sm text-slate-600">
          Requires a verified final CPython 3.14 runtime on this machine. A separate Python 3.14 environment works even when Guard uses an older supported Python.
        </p>
        {props.locked ? <p className="text-sm text-slate-600">Your organization manages these preferences. You can still turn context assistance off.</p> : null}
        {status?.restriction ? <p className="text-sm text-slate-600">Policy restrictions apply. Your saved choices are retained; effective limits are shown below.</p> : null}
        {value ? (
          <>
            <SettingsToggleRow label="Use CIGAR on this machine" checked={value.enabled}
              description="Save your preferences, then click Start CIGAR at the top of this page to verify and run the runtime."
              disabled={editingDisabled || (!value.enabled && !selected)}
              onChange={(enabled) => props.onChange({ ...value, enabled })} />
            <CigarRuntimeSelection value={value} status={status} installations={installations} disabled={disabled}
              onManage={props.onManageVersions} onRefresh={props.onChooseRuntime}
              onRestore={() => { if (status) props.onChange({ ...value, runtime_id: status.preferences.runtime_id,
                enabled: value.enabled && Boolean(status.preferences.runtime_id) }); }} />
            <SettingsSelectRow label="Context size" value={value.resource_profile} disabled={editingDisabled}
              description="Smaller context uses one workspace and stops after two idle minutes. Balanced allows two workspaces and ten idle minutes."
              options={[{ value: "low_memory", label: "Smaller context" }, { value: "balanced", label: "Balanced" }, { value: "custom", label: "Custom limits" }]}
              onChange={(event) => props.onChange(withContextProfile(value, event.target.value as GuardContextAssistanceConfig["resource_profile"]))} />
            <SettingsToggleRow label="Review briefs" description="Prepare cited context to help you understand a request. Guard's approval choices stay available."
              checked={value.features.review_briefs} disabled={editingDisabled}
              onChange={(review_briefs) => props.onChange({ ...value, features: { ...value.features, review_briefs } })} />
            <SettingsToggleRow label="Context for AI apps" description="Allow scoped context tools for apps you authorize. Sharing between agents requires a separate choice."
              checked={value.features.agent_context} disabled={editingDisabled}
              onChange={(agent_context) => props.onChange({ ...value, features: { ...value.features, agent_context, shared_agents: agent_context && value.features.shared_agents } })} />
            <SettingsToggleRow label="Share context between paired AI connections"
              description="Separate connections for the same app and workspace can use shared context. Notes require explicit access and your review before sharing. Saving this change ends existing context grants; pair connections again after starting the runtime."
              checked={value.features.shared_agents}
              disabled={editingDisabled || !value.features.agent_context || status?.capabilities?.shared_agents !== true}
              onChange={(shared_agents) => props.onChange({ ...value, features: { ...value.features, shared_agents } })} />
            {!value.features.agent_context ? <p className="text-sm text-slate-600">Enable Context for AI apps before choosing sharing.</p> : null}
            <details className="rounded-lg border border-slate-100 p-3 text-sm">
              <summary className="cursor-pointer font-medium text-brand-dark">Sources, limits and runtime details</summary>
              <SettingsToggleRow label="Associate native context with execution"
                description="Add a short context check to supported native captured-Bash commands. Requires native facts and fresh app/workspace access. Guard proceeds under its existing authorization when the association is unavailable."
                checked={value.features.execution_context === true}
                disabled={editingDisabled || (value.features.execution_context !== true
                  && (status?.capabilities?.execution_context !== true || !value.sources.native_policy_facts))}
                onChange={(execution_context) => props.onChange({ ...value, features: { ...value.features, execution_context } })} />
              {status?.capabilities?.execution_context !== true ? <p className="text-xs text-slate-500">This native execution route is unavailable in the current build. Review briefs and scoped context tools have their own controls.</p> : null}
              {!value.sources.native_policy_facts ? <p className="text-xs text-slate-500">Enable native policy and decision facts to choose execution associations.</p> : null}
              {value.resource_profile === "custom" ? (
                <fieldset className="mt-3 grid gap-3 sm:grid-cols-2" disabled={editingDisabled}>
                  <legend className="mb-2 font-medium text-brand-dark">Custom limits</legend>
                  {([
                    ["context_tokens", "Context token budget", 64, 16384],
                    ["reserve_tokens", "Reserved tokens", 0, value.limits.context_tokens - 1],
                    ["max_active_workspaces", "Active workspaces", 1, 8],
                    ["idle_shutdown_seconds", "Idle shutdown in seconds", 30, 3600],
                  ] as const).map(([key, label, min, max]) => (
                    <label key={key} className="text-sm text-slate-600">{label}
                      <input type="number" min={min} max={max} step={1} value={value.limits[key]}
                        className="mt-1 min-h-11 w-full rounded-lg border border-slate-200 px-3 py-2 text-brand-dark"
                        onChange={(event) => {
                          const next = event.target.valueAsNumber;
                          if (Number.isSafeInteger(next)) props.onChange({ ...value, limits: { ...value.limits, [key]: next } });
                        }} />
                    </label>
                  ))}
                </fieldset>
              ) : null}
              <SettingsToggleRow label="Native policy and decision facts" description="Use admitted policy facts and native evaluation metadata. Up to 64 recent native decisions stay in local memory for five minutes."
                checked={value.sources.native_policy_facts} disabled={editingDisabled}
                onChange={(native_policy_facts) => props.onChange({ ...value,
                  features: { ...value.features, execution_context: native_policy_facts && value.features.execution_context === true },
                  sources: { ...value.sources, native_policy_facts } })} />
              <SettingsToggleRow label="Sanitized receipt facts" description="Use sanitized facts from Guard's local history."
                checked={value.sources.sanitized_receipt_facts} disabled={editingDisabled}
                onChange={(sanitized_receipt_facts) => props.onChange({ ...value, sources: { ...value.sources, sanitized_receipt_facts } })} />
              <p className="text-slate-600">Workspace documents require explicit source access. Runtime activation grants no document access.</p>
              <SettingsToggleRow label="Allow selected workspace documents" description="After saving, choose each folder and file in Workspace context access. Files are read only with an explicit grant."
                checked={value.sources.workspace_documents} disabled={editingDisabled}
                onChange={(workspace_documents) => props.onChange({ ...value, sources: { ...value.sources, workspace_documents,
                  source_set_id: workspace_documents ? value.sources.source_set_id || "selected-workspaces" : value.sources.source_set_id } })} />
              <label className="block text-sm text-slate-600">Evidence storage
                <select value={value.storage.mode} disabled={editingDisabled}
                  className="mt-1 min-h-11 w-full rounded-lg border border-slate-200 px-3 py-2 text-brand-dark"
                  onChange={(event) => props.onChange({ ...value, storage: { ...value.storage, mode: event.target.value === "sqlite" ? "sqlite" : "memory" } })}>
                  <option value="memory">Memory only (recommended)</option>
                  <option value="sqlite" disabled={status?.capabilities?.private_persistence !== true}>Save evidence locally</option>
                </select>
              </label>
              <p className="text-xs text-slate-500">Memory data ends when the runtime stops. Saved evidence uses private local files, with no Guard encryption; it can outlive the runtime until retention or removal. Restoring it never restores app access or approvals. Saving a storage change ends current context access.</p>
              {status?.capabilities?.private_persistence !== true ? <p className="text-xs text-slate-500">Saved evidence activation is unavailable in this build. Existing saved data can be removed in Data & repair.</p> : null}
              <label className="block text-sm text-slate-600">Context history, saved evidence and shared-note retention in hours
                <input type="number" min={1} max={720} step={1} value={value.storage.retention_hours} disabled={editingDisabled}
                  className="mt-1 min-h-11 w-full rounded-lg border border-slate-200 px-3 py-2 text-brand-dark"
                  onChange={(event) => {
                    const retention_hours = event.target.valueAsNumber;
                    if (Number.isSafeInteger(retention_hours)) props.onChange({ ...value, storage: { ...value.storage, retention_hours } });
                  }} />
              </label>
              <p className="text-xs text-slate-500">Memory data also ends when access is revoked, the runtime stops, or Guard restarts. Changing preferences requires fresh grants.</p>
              <dl className="mt-3 grid gap-2 sm:grid-cols-2">
                <div><dt>Effective context budget</dt><dd>{(status?.effective_preferences ?? value).limits.context_tokens} tokens, including {(status?.effective_preferences ?? value).limits.reserve_tokens} reserved</dd></div>
                <div><dt>Effective workspace limit</dt><dd>{(status?.effective_preferences ?? value).limits.max_active_workspaces}</dd></div>
                <div><dt>Effective idle shutdown</dt><dd>{(status?.effective_preferences ?? value).limits.idle_shutdown_seconds} seconds</dd></div>
                <div><dt>Storage</dt><dd>{value.storage.mode === "memory" ? "Memory only" : "Private persistence requested"}</dd></div>
                {runtime ? <>
                  <div><dt>Last verified Python</dt><dd>{runtime.interpreter.version.join(".")} · {runtime.interpreter.platform}</dd></div>
                  <div><dt>Qualification</dt><dd>Local development candidate</dd></div>
                  {value.features.shared_agents ? <div><dt>Shared context check</dt><dd>{runtime.shared_compile_verified ? "Verified with an independent local client" : "Check and start the selected runtime"}</dd></div> : null}
                  {value.storage.mode === "sqlite" ? <div><dt>Saved evidence check</dt><dd>{runtime.persistence_compile_verified ? "Verified write, restart and fresh-grant recovery" : "Check and start the selected runtime"}</dd></div> : null}
                  {value.features.execution_context ? <div><dt>Execution SDK check</dt><dd>{runtime.execution_handoff_verified ? "Verified submission, host review, binding and one-time context take" : "Check and start the selected runtime"}</dd></div> : null}
                </> : null}
              </dl>
              {status?.diagnostic ? <p className="mt-3 break-words text-xs text-slate-500">Diagnostic: {status.diagnostic}</p> : null}
            </details>
            <ContextExecutionPanel status={status} />
          </>
        ) : <p className="text-sm text-slate-600">Update Guard to a native core with context assistance support before choosing these settings.</p>}
        <p className="text-xs text-slate-500">Context is supporting information. Guard keeps command protection and approval decisions in its native execution flow.</p>
      </div>
    </SettingsFormSection>
  );
}
