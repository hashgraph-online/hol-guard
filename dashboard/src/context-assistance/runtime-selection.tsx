import type { GuardContextAssistanceConfig } from "../guard-types";
import { shellHref } from "../shell-navigation-link";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import { installationLabel, platformLabel, versionButton, versionQuiet } from "./versions-view";
type Props = {
  value: GuardContextAssistanceConfig; status: ContextAssistanceStatus | null;
  installations: ContextInstallation[] | null; disabled: boolean;
  onManage?: () => void; onRefresh: () => void; onRestore: () => void;
};
const sentence = (text: string) => text.charAt(0).toUpperCase() + text.slice(1);
function describe(id: string, installations: ContextInstallation[] | null, selected: ContextInstallation | undefined): string {
  if (!id) return "Not set up yet";
  if (installations === null) return "Looking up version details";
  if (!selected) return "Picked, but not found on this computer";
  const sdk = selected.sdk_version ? "CIGAR " + selected.sdk_version + " · " : "";
  return sdk + "Python " + selected.python_version.join(".") + " · " + platformLabel(selected.platform);
}
/** Runtime identity is committed by the native versions owner, never drafted here. The raw ID lives under More settings. */
export function CigarRuntimeSelection(props: Props) {
  const id = props.status?.preferences.runtime_id ?? props.value.runtime_id;
  const selected = props.installations?.find((item) => item.runtime_id === id);
  const pending = props.status !== null && props.value.runtime_id !== id;
  return <div className="space-y-3 py-4">
    <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="min-w-0 flex-[1_1_16rem]">
        <p className="guard-settings-body font-medium text-brand-dark">CIGAR version</p>
        <p className="mt-0.5 text-sm text-brand-dark/80">{describe(id, props.installations ?? null, selected)}</p>
        {selected ? <p className="guard-settings-caption mt-0.5 text-slate-500">{sentence(installationLabel(selected.qualification))}</p> : null}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {props.onManage ? <button type="button" className={versionButton} disabled={props.disabled} onClick={props.onManage}>Change version</button>
          : <a className={versionButton} href={shellHref("/cigar?section=versions")}>Change version</a>}
        {props.installations !== null ? <button type="button" className={versionQuiet} disabled={props.disabled} onClick={props.onRefresh}>Refresh versions</button> : null}
      </div>
    </div>
    {props.installations?.length === 0 ? <p className="text-sm text-slate-600">CIGAR is not set up on this computer yet. Turn on CIGAR at the top of this page and Guard sets it up for you.</p> : null}
    {pending ? <div role="status" className="space-y-2 rounded-xl border border-amber-200 bg-amber-50/60 px-4 py-3 text-sm text-amber-900"><p>This form has a different version picked than the one in use. Keep the current version here, then switch versions in Updates.</p>
      <button type="button" className={versionButton} disabled={props.disabled} onClick={props.onRestore}>Keep current version</button></div> : null}
  </div>;
}
