import type { GuardContextAssistanceConfig } from "../guard-types";
import { shellHref } from "../shell-navigation-link";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import { versionButton } from "./versions-view";
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
  return <div className="space-y-2">
    <p className="text-sm font-semibold text-brand-dark">Selected runtime</p>
    <p className="break-all text-sm text-slate-600">{id || "No runtime selected"}</p>
    {selected ? <p className="text-sm text-slate-600">{selected.sdk_version ? "CIGAR " + selected.sdk_version + " · " : ""}Python {selected.python_version.join(".")} · {selected.platform} · {selected.qualification.replaceAll("_", " ")}</p> : null}
    {props.installations?.length === 0 ? <p className="text-sm text-slate-600">No registered CIGAR runtime is available in this profile. Python 3.14 may already be installed; use Versions & updates to inspect approved builds and registration options.</p> : null}
    <p className="text-sm text-slate-600">Choose, prepare and switch runtimes in Versions & updates. A separate selection job protects your current runtime and data.</p>
    {props.onManage ? <button type="button" className={versionButton} disabled={props.disabled} onClick={props.onManage}>Choose or switch runtime</button>
      : <a className={versionButton + " inline-flex items-center"} href={shellHref("/cigar?section=versions")}>Choose or switch runtime</a>}
    {props.installations !== null ? <button type="button" className={versionButton} disabled={props.disabled} onClick={props.onRefresh}>Refresh runtime list</button> : null}
    {pending ? <div role="status" className="text-sm text-amber-800"><p>A pending runtime choice is in this form. Use the current selection before preparing a different runtime in Versions & updates.</p>
      <button type="button" className={versionButton} disabled={props.disabled} onClick={props.onRestore}>Use current selection</button></div> : null}
  </div>;
}
