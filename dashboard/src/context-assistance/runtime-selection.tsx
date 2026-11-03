import type { GuardContextAssistanceConfig } from "../guard-types";
import { shellHref } from "../shell-navigation-link";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import { installationLabel, platformLabel, versionButton, versionQuiet } from "./versions-view";
type Props = {
  value: GuardContextAssistanceConfig; status: ContextAssistanceStatus | null;
  installations: ContextInstallation[] | null; disabled: boolean;
  onManage?: () => void; onRefresh: () => void; onRestore: () => void;
};
/** Runtime identity is committed by the native versions owner, never drafted here. */
export function CigarRuntimeSelection(props: Props) {
  const id = props.status?.preferences.runtime_id ?? props.value.runtime_id;
  const selected = props.installations?.find((item) => item.runtime_id === id);
  const pending = props.status !== null && props.value.runtime_id !== id;
  return <div className="space-y-3 py-4">
    <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="min-w-0 flex-[1_1_16rem]">
        <p className="guard-settings-body font-medium text-brand-dark">Selected runtime</p>
        <p className="mt-0.5 break-all font-mono text-sm text-brand-dark/80">{id || "No runtime selected"}</p>
        {selected ? <p className="guard-settings-caption mt-0.5 text-slate-500">{selected.sdk_version ? "CIGAR " + selected.sdk_version + " · " : ""}Python {selected.python_version.join(".")} · {platformLabel(selected.platform)} · {installationLabel(selected.qualification)}</p> : null}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {props.onManage ? <button type="button" className={versionButton} disabled={props.disabled} onClick={props.onManage}>Choose or switch runtime</button>
          : <a className={versionButton} href={shellHref("/cigar?section=versions")}>Choose or switch runtime</a>}
        {props.installations !== null ? <button type="button" className={versionQuiet} disabled={props.disabled} onClick={props.onRefresh}>Refresh runtime list</button> : null}
      </div>
    </div>
    {props.installations?.length === 0 ? <p className="text-sm text-slate-600">No registered CIGAR runtime is available in this profile. Python 3.14 may already be installed; use Updates to inspect approved builds and registration options.</p> : null}
    <p className="guard-settings-caption text-slate-500">Choose, prepare and switch runtimes in Updates. A separate selection job protects your current runtime and data.</p>
    {pending ? <div role="status" className="space-y-2 rounded-xl border border-amber-200 bg-amber-50/60 px-4 py-3 text-sm text-amber-900"><p>A pending runtime choice is in this form. Use the current selection before preparing a different runtime in Updates.</p>
      <button type="button" className={versionButton} disabled={props.disabled} onClick={props.onRestore}>Use current selection</button></div> : null}
  </div>;
}
