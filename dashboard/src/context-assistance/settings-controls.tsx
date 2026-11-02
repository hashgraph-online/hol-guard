import { useId, type ReactNode } from "react";
import { HiMiniArrowPath, HiMiniCheckCircle, HiMiniChevronRight, HiMiniExclamationTriangle, HiMiniPauseCircle } from "react-icons/hi2";
import type { GuardContextAssistanceConfig } from "../guard-types";
import { SelectMenu } from "../select-menu";
import { SettingsFormSection, SettingsMenuRow, SettingsToggleRow } from "../settings/settings-row-primitives";
import { contextStatusCopy } from "./status";
import { withContextProfile } from "./settings-model";
import type { ContextAssistanceStatus, ContextControlAction, ContextInstallation } from "./types";
import { ContextExecutionPanel } from "./execution-panel";
import { CigarRuntimeSelection } from "./runtime-selection";
import { versionButton, versionField, versionPrimary } from "./versions-view";

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

const note = "rounded-xl border border-brand-dark/10 bg-surface-1 px-4 py-3 text-sm leading-6 text-brand-dark/75";
const caption = "text-xs leading-5 text-slate-500";
const PROFILES = [
  { value: "low_memory" as const, label: "Smaller context", description: "One project at a time. Stops after two idle minutes." },
  { value: "balanced" as const, label: "Balanced", description: "Two projects at a time. Stops after ten idle minutes." },
  { value: "custom" as const, label: "Custom limits", description: "Set your own limits under Advanced." },
];

function Group({ title, children }: { title: string; children: ReactNode }) {
  return <section className="space-y-3"><h4 className="text-sm font-semibold text-brand-dark">{title}</h4>{children}</section>;
}

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return <div className="rounded-xl bg-surface-1 px-3 py-2.5"><dt className="text-xs text-slate-500">{term}</dt><dd className="mt-0.5 text-sm font-medium text-brand-dark">{children}</dd></div>;
}

export function ContextSettingsControls(props: ContextSettingsControlsProps) {
  const { value, status, installations } = props;
  const titleId = useId();
  const storageId = useId();
  const statusCopy = status ? contextStatusCopy(status) : null;
  const selected = installations?.some((item) => item.runtime_id === value?.runtime_id) === true;
  const disabled = props.disabled || props.busy;
  const editingDisabled = disabled || props.locked || value === null || status === null;
  const checkDisabled = disabled || props.dirty || !status?.verification_permitted || Boolean(status?.job) || !value?.runtime_id;
  const stopped = !value?.enabled && !status?.requested_enabled && !status?.job && !status?.effective_enabled;
  const runtime = status?.runtime ?? status?.last_check;
  const running = status?.effective_enabled === true;
  const attention = !running && Boolean(status?.requested_enabled && !status.job);
  const [Icon, tone] = running ? [HiMiniCheckCircle, "bg-brand-green-bg text-brand-green-text"]
    : attention ? [HiMiniExclamationTriangle, "bg-amber-100 text-amber-700"] : [HiMiniPauseCircle, "bg-brand-dark/[0.06] text-brand-dark/55"];
  const effective = status?.effective_preferences ?? value;
  return (
    <div className="space-y-8">
      <section aria-labelledby={titleId} className="guard-surface-in rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-5">
        <div className="flex flex-wrap items-start gap-x-6 gap-y-4">
          <div className="flex min-w-0 flex-[1_1_20rem] items-start gap-3.5">
            <span aria-hidden="true" className={"flex size-10 shrink-0 items-center justify-center rounded-full " + tone}>
              {props.loading || status?.job ? <HiMiniArrowPath className="size-5 motion-safe:animate-spin" /> : <Icon className="size-5" />}
            </span>
            <div className="min-w-0 space-y-1.5">
              <h3 id={titleId} className="text-lg font-semibold tracking-[-0.01em] text-brand-dark">{runtime ? "CIGAR " + runtime.package_version : "CIGAR runtime"}</h3>
              <p className="max-w-[62ch] text-sm leading-6 text-brand-dark/75" role="status" aria-live="polite">
                {props.loading ? "Checking availability…" : statusCopy ? `${statusCopy.label}. ${statusCopy.detail}` : "Availability has not been verified."}
              </p>
              <p className={caption}>CIGAR uses its own copy of Python 3.14. Guard sets it up for you when you click Turn on CIGAR.</p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {status?.requested_enabled && !status.effective_enabled ? (
              <button type="button" className={versionPrimary} disabled={checkDisabled || !status.effective_preferences.enabled}
                onClick={() => props.onControl("activate")}>Start context assistance</button>
            ) : null}
            <button type="button" className={versionButton} disabled={checkDisabled} onClick={() => props.onControl("recheck")}>Check selected runtime</button>
            {!stopped ? <button type="button" className={versionButton} disabled={disabled} onClick={() => props.onControl("stop")}>Turn off now</button> : null}
            <button type="button" aria-label="Refresh runtime status" title="Refresh runtime status" disabled={disabled || props.loading} onClick={props.onRefresh}
              className="inline-flex size-11 items-center justify-center rounded-lg text-brand-dark/70 hover:bg-brand-dark/[0.05] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-50">
              <HiMiniArrowPath aria-hidden="true" className="size-4" /></button>
          </div>
        </div>
      </section>
      {props.error ? <div role="alert" className="cigar-note"><strong>CIGAR needs attention</strong><p>{props.error}</p></div> : null}
      {props.dirty ? <p role="status" className={note}>Save settings before checking or starting this runtime.</p> : null}
      {props.locked ? <p className={note}>Your organization manages these preferences. You can still turn context assistance off.</p> : null}
      {status?.restriction ? <p className={note}>Policy restrictions apply. Your saved choices are retained; effective limits are shown below.</p> : null}
      {value ? (
        <>
          <SettingsFormSection title="Runtime">
            <SettingsToggleRow label="Use CIGAR on this machine" checked={value.enabled}
              description="Lets CIGAR run on this computer. The Turn on CIGAR button sets this for you."
              disabled={editingDisabled || (!value.enabled && !selected)}
              onChange={(enabled) => props.onChange({ ...value, enabled })} />
            <CigarRuntimeSelection value={value} status={status} installations={installations} disabled={disabled}
              onManage={props.onManageVersions} onRefresh={props.onChooseRuntime}
              onRestore={() => { if (status) props.onChange({ ...value, runtime_id: status.preferences.runtime_id,
                enabled: value.enabled && Boolean(status.preferences.runtime_id) }); }} />
          </SettingsFormSection>
          <SettingsFormSection title="What CIGAR helps with">
            <SettingsMenuRow label="Context size" value={value.resource_profile} disabled={editingDisabled} options={PROFILES}
              description="How much CIGAR keeps ready at once. Smaller suits most laptops."
              onChange={(profile) => props.onChange(withContextProfile(value, profile))} />
            <SettingsToggleRow label="Review briefs" description="Prepare cited context to help you understand a request. Guard's approval choices stay available."
              checked={value.features.review_briefs} disabled={editingDisabled}
              onChange={(review_briefs) => props.onChange({ ...value, features: { ...value.features, review_briefs } })} />
            <SettingsToggleRow label="Context for AI apps" description="Allow scoped context tools for apps you authorize. Sharing between agents requires a separate choice."
              checked={value.features.agent_context} disabled={editingDisabled}
              onChange={(agent_context) => props.onChange({ ...value, features: { ...value.features, agent_context, shared_agents: agent_context && value.features.shared_agents } })} />
            <div>
              <SettingsToggleRow label="Share context between paired AI connections"
                description="Separate connections for the same app and workspace can use shared context. Notes require explicit access and your review before sharing. Saving this change ends existing context grants; pair connections again after starting the runtime."
                checked={value.features.shared_agents}
                disabled={editingDisabled || !value.features.agent_context || status?.capabilities?.shared_agents !== true}
                onChange={(shared_agents) => props.onChange({ ...value, features: { ...value.features, shared_agents } })} />
              {!value.features.agent_context ? <p className={caption + " pb-3"}>Enable Context for AI apps before choosing sharing.</p> : null}
            </div>
          </SettingsFormSection>
          <details className="group rounded-2xl border border-brand-dark/10 bg-white">
            <summary className="flex min-h-14 cursor-pointer list-none items-center gap-3 rounded-2xl px-4 py-3 hover:bg-surface-1 sm:px-5 [&::-webkit-details-marker]:hidden">
              <HiMiniChevronRight aria-hidden="true" className="size-4 shrink-0 text-brand-dark/50 transition-transform group-open:rotate-90 motion-reduce:transition-none" />
              <span className="min-w-0"><span className="block text-sm font-semibold text-brand-dark">Advanced</span>
                <span className="block text-xs text-brand-dark/60">Sources, limits, storage and runtime details</span></span>
            </summary>
            <div className="space-y-8 border-t border-brand-dark/[0.07] px-4 py-5 sm:px-5">
              <Group title="Sources">
                <div className="divide-y divide-slate-100">
                  <SettingsToggleRow label="Native policy and decision facts" description="Use admitted policy facts and native evaluation metadata. Up to 64 recent native decisions stay in local memory for five minutes."
                    checked={value.sources.native_policy_facts} disabled={editingDisabled}
                    onChange={(native_policy_facts) => props.onChange({ ...value,
                      features: { ...value.features, execution_context: native_policy_facts && value.features.execution_context === true },
                      sources: { ...value.sources, native_policy_facts } })} />
                  <SettingsToggleRow label="Sanitized receipt facts" description="Use sanitized facts from Guard's local history."
                    checked={value.sources.sanitized_receipt_facts} disabled={editingDisabled}
                    onChange={(sanitized_receipt_facts) => props.onChange({ ...value, sources: { ...value.sources, sanitized_receipt_facts } })} />
                  <SettingsToggleRow label="Allow selected workspace documents" description="After saving, choose each folder and file in Workspace context access. Files are read only with an explicit grant."
                    checked={value.sources.workspace_documents} disabled={editingDisabled}
                    onChange={(workspace_documents) => props.onChange({ ...value, sources: { ...value.sources, workspace_documents,
                      source_set_id: workspace_documents ? value.sources.source_set_id || "selected-workspaces" : value.sources.source_set_id } })} />
                  <div>
                    <SettingsToggleRow label="Associate native context with execution"
                      description="Add a short context check to supported native captured-Bash commands. Requires native facts and fresh app/workspace access. Guard proceeds under its existing authorization when the association is unavailable."
                      checked={value.features.execution_context === true}
                      disabled={editingDisabled || (value.features.execution_context !== true
                        && (status?.capabilities?.execution_context !== true || !value.sources.native_policy_facts))}
                      onChange={(execution_context) => props.onChange({ ...value, features: { ...value.features, execution_context } })} />
                    {status?.capabilities?.execution_context !== true ? <p className={caption + " pb-2"}>This native execution route is unavailable in the current build. Review briefs and scoped context tools have their own controls.</p> : null}
                    {!value.sources.native_policy_facts ? <p className={caption + " pb-2"}>Enable native policy and decision facts to choose execution associations.</p> : null}
                  </div>
                </div>
                <p className={caption}>Workspace documents require explicit source access. Runtime activation grants no document access.</p>
              </Group>
              {value.resource_profile === "custom" ? (
                <fieldset className="grid gap-4 sm:grid-cols-2" disabled={editingDisabled}>
                  <legend className="mb-3 text-sm font-semibold text-brand-dark">Custom limits</legend>
                  {([
                    ["context_tokens", "Context token budget", 64, 16384],
                    ["reserve_tokens", "Reserved tokens", 0, value.limits.context_tokens - 1],
                    ["max_active_workspaces", "Active workspaces", 1, 8],
                    ["idle_shutdown_seconds", "Idle shutdown in seconds", 30, 3600],
                  ] as const).map(([key, label, min, max]) => (
                    <label key={key} className="text-sm font-medium text-brand-dark">{label}
                      <input type="number" min={min} max={max} step={1} value={value.limits[key]} className={versionField + " tabular-nums"}
                        onChange={(event) => {
                          const next = event.target.valueAsNumber;
                          if (Number.isSafeInteger(next)) props.onChange({ ...value, limits: { ...value.limits, [key]: next } });
                        }} />
                    </label>
                  ))}
                </fieldset>
              ) : null}
              <Group title="Storage">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div><span id={storageId} className="text-sm font-medium text-brand-dark">Evidence storage</span>
                    <SelectMenu labelledBy={storageId} className="mt-1.5 w-full" value={value.storage.mode} disabled={editingDisabled}
                      options={[{ value: "memory" as const, label: "Memory only (recommended)", description: "Notes disappear when CIGAR stops." },
                        { value: "sqlite" as const, label: "Save evidence locally", description: status?.capabilities?.private_persistence === true
                          ? "Private local files that can outlive the runtime." : "Not available in this build.", disabled: status?.capabilities?.private_persistence !== true }]}
                      onChange={(mode) => props.onChange({ ...value, storage: { ...value.storage, mode } })} /></div>
                  <label className="block text-sm font-medium text-brand-dark">Retention in hours
                    <input type="number" min={1} max={720} step={1} value={value.storage.retention_hours} disabled={editingDisabled} className={versionField + " tabular-nums"}
                      aria-describedby={storageId + "-retention"}
                      onChange={(event) => {
                        const retention_hours = event.target.valueAsNumber;
                        if (Number.isSafeInteger(retention_hours)) props.onChange({ ...value, storage: { ...value.storage, retention_hours } });
                      }} />
                    <span id={storageId + "-retention"} className={caption + " mt-1 block font-normal"}>Applies to context history, saved evidence and shared notes.</span>
                  </label>
                </div>
                <p className={caption}>Memory data ends when the runtime stops. Saved evidence uses private local files, with no Guard encryption; it can outlive the runtime until retention or removal. Restoring it never restores app access or approvals. Saving a storage change ends current context access.</p>
                {status?.capabilities?.private_persistence !== true ? <p className={caption}>Saved evidence activation is unavailable in this build. Existing saved data can be removed in Data & repair.</p> : null}
                <p className={caption}>Memory data also ends when access is revoked, the runtime stops, or Guard restarts. Changing preferences requires fresh grants.</p>
              </Group>
              {effective ? <Group title="In effect now">
                <dl className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  <Fact term="Effective context budget">{effective.limits.context_tokens} tokens, including {effective.limits.reserve_tokens} reserved</Fact>
                  <Fact term="Effective workspace limit">{effective.limits.max_active_workspaces}</Fact>
                  <Fact term="Effective idle shutdown">{effective.limits.idle_shutdown_seconds} seconds</Fact>
                  <Fact term="Storage">{value.storage.mode === "memory" ? "Memory only" : "Private persistence requested"}</Fact>
                  {runtime ? <>
                    <Fact term="Last verified Python">{runtime.interpreter.version.join(".")} · {runtime.interpreter.platform}</Fact>
                    <Fact term="Qualification">Local development candidate</Fact>
                    {value.features.shared_agents ? <Fact term="Shared context check">{runtime.shared_compile_verified ? "Verified with an independent local client" : "Check and start the selected runtime"}</Fact> : null}
                    {value.storage.mode === "sqlite" ? <Fact term="Saved evidence check">{runtime.persistence_compile_verified ? "Verified write, restart and fresh-grant recovery" : "Check and start the selected runtime"}</Fact> : null}
                    {value.features.execution_context ? <Fact term="Execution SDK check">{runtime.execution_handoff_verified ? "Verified submission, host review, binding and one-time context take" : "Check and start the selected runtime"}</Fact> : null}
                  </> : null}
                </dl>
                {status?.diagnostic ? <p className={caption + " break-words"}>Diagnostic: {status.diagnostic}</p> : null}
              </Group> : null}
            </div>
          </details>
          <ContextExecutionPanel status={status} />
        </>
      ) : <p className={note}>Update Guard to a native core with context assistance support before choosing these settings.</p>}
      <p className={caption}>Context is supporting information. Guard keeps command protection and approval decisions in its native execution flow.</p>
    </div>
  );
}
