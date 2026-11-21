import { useState } from "react";
import { HiMiniArrowPath } from "react-icons/hi2";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal } from "../settings-save-proof-modal";
import type { ContextAssistanceStatus } from "./types";
import { cigarJobActive } from "./versions-actions";
import { CigarVersionJobsPanel } from "./versions-jobs-panel";
import { useCigarVersions, type CaptureCigarStatus } from "./use-versions";
import { versionQuiet, type CigarVersionAction } from "./versions-view";
type Props = { status: ContextAssistanceStatus | null; disabled: boolean; locked: boolean; dirty: boolean;
  gate: GuardApprovalGatePublicConfig | null; captureStatus: CaptureCigarStatus };
const notice = "rounded-xl border border-brand-dark/10 bg-surface-1 px-4 py-3 text-sm leading-6 text-brand-dark/75";
export function CigarVersionsPanel(props: Props) {
  const versions = useCigarVersions(props.captureStatus);
  const [approval, setApproval] = useState<CigarVersionAction | null>(null);
  const { data } = versions;
  const disabled = props.disabled || versions.busy || versions.loading;
  const changesDisabled = disabled || versions.uncertain;
  const selectionDisabled = changesDisabled || props.locked || props.dirty || !props.status || Boolean(props.status.job);
  const activeJobs = data?.jobs.filter(cigarJobActive) ?? [];
  function choose(action: CigarVersionAction) {
    if (disabled || action.input.action !== "cancel" && versions.uncertain) return;
    if (action.input.action !== "cancel" && props.gate?.enabled) setApproval(action);
    else void versions.perform(action.input);
  }
  return <div className="space-y-6" data-testid="cigar-versions">
    <div className="cigar-section-intro"><h2>Updates</h2>
      <p>CIGAR is built into Guard and updates when Guard does. There is nothing to download here. This page only shows CIGAR work that is still running or that stopped partway.</p></div>
    <div className="flex flex-wrap gap-2">
      <button type="button" className={versionQuiet} disabled={props.disabled || versions.busy || versions.loading} onClick={() => void versions.refresh()}>
        <HiMiniArrowPath aria-hidden="true" className={"size-4" + (versions.loading ? " motion-safe:animate-spin" : "")} />Refresh list</button>
    </div>
    {versions.loading && !data ? <div role="status" className="space-y-3" aria-label="Loading CIGAR versions…">
      {[0, 1, 2].map((row) => <div key={row} className="h-16 rounded-2xl bg-brand-dark/[0.04] motion-safe:animate-pulse" />)}
      <span className="sr-only">Loading CIGAR versions…</span></div> : null}
    {versions.busy ? <p role="status" className={notice}>Starting. Keep this page open until Guard confirms the change has started.</p> : null}
    {versions.error ? <div role="alert" className="cigar-note"><strong>CIGAR updates need attention</strong><p>{versions.error}</p><p>Refresh the list before trying another change.</p></div> : null}
    {versions.tracking ? <p className="break-all text-xs text-brand-dark/60">Guard is working on job {versions.tracking} and keeps going if you leave this page. Refresh the list to see how it went.</p> : null}
    {props.dirty ? <p role="status" className={notice}>Save your CIGAR setting changes before finishing a step here.</p> : null}
    {data ? <CigarVersionJobsPanel jobs={activeJobs} status={props.status} disabled={disabled} selectionDisabled={selectionDisabled} onAction={choose} /> : null}
    <SettingsSaveProofModal open={approval !== null} mode="verify-save" gate={props.gate}
      title={approval?.title ?? "Confirm CIGAR change"} detail={approval?.detail ?? ""} confirmLabel="Confirm change"
      error={null} pending={versions.busy} onCancel={() => setApproval(null)}
      onConfirm={(proof) => { if (approval) { const action = approval; setApproval(null); void versions.perform(action.input, proof); } }} />
  </div>;
}
