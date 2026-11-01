import { useState } from "react";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal } from "../settings-save-proof-modal";
import type { ContextAssistanceStatus } from "./types";
import { cigarVersionJobId } from "./versions-actions";
import { CigarVersionBuildsPanel } from "./versions-builds-panel";
import { CigarVersionJobsPanel } from "./versions-jobs-panel";
import { CigarUpdatePreferencesPanel } from "./versions-preferences-panel";
import { useCigarVersions, type CaptureCigarStatus } from "./use-versions";
import { versionButton, versionCard, versionField, type CigarVersionAction } from "./versions-view";
type Props = { status: ContextAssistanceStatus | null; disabled: boolean; locked: boolean; dirty: boolean;
  gate: GuardApprovalGatePublicConfig | null; captureStatus: CaptureCigarStatus };
export function CigarVersionsPanel(props: Props) {
  const versions = useCigarVersions(props.captureStatus);
  const [approval, setApproval] = useState<CigarVersionAction | null>(null);
  const [signedCatalog, setSignedCatalog] = useState("");
  const { data } = versions;
  const disabled = props.disabled || versions.busy || versions.loading;
  const changesDisabled = disabled || versions.uncertain;
  const selectionDisabled = changesDisabled || props.locked || props.dirty || !props.status || Boolean(props.status.job);
  function choose(action: CigarVersionAction) {
    if (disabled || action.input.action !== "cancel" && versions.uncertain) return;
    if (action.input.action !== "cancel" && props.gate?.enabled) setApproval(action);
    else void versions.perform(action.input);
  }
  return <div className="space-y-6" data-testid="cigar-versions">
    <div className="cigar-section-intro"><h2>Updates</h2>
      <p>Guard handles this for you when you turn CIGAR on. Come here only to pick a specific version, check for new ones, or go back to an earlier one. Opening this page changes nothing.</p></div>
    <div className="flex flex-wrap gap-2">
      <button type="button" className={versionButton} disabled={props.disabled || versions.busy || versions.loading} onClick={() => void versions.refresh()}>Refresh versions & jobs</button>
      <button type="button" className={versionButton} disabled={changesDisabled || !data?.catalog.catalog.remote_feed_configured || !data.catalog.catalog.trust_configured || Boolean(data.catalog.catalog.feed_diagnostic)}
        onClick={() => choose({ input: { action: "refresh_catalog", job_id: cigarVersionJobId() }, title: "Check for CIGAR catalog updates",
          detail: "Fetch the configured signed release catalog. This does not prepare or switch an SDK." })}>Check for catalog updates</button>
    </div>
    {versions.loading ? <p role="status" className="text-sm text-slate-600">Reading CIGAR versions and job metadata…</p> : null}
    {versions.busy ? <p role="status" className="text-sm text-slate-600">Submitting the selected action. Preparation continues as a native job.</p> : null}
    {versions.error ? <div role="alert" className="cigar-note"><strong>CIGAR updates need attention</strong><p>{versions.error}</p><p>Refresh versions and jobs before submitting another change.</p></div> : null}
    {versions.tracking ? <p className="break-all text-xs text-slate-600">Last submitted job: {versions.tracking}. Refresh jobs to confirm its outcome.</p> : null}
    {props.dirty ? <p role="status" className="text-sm text-slate-600">You can prepare builds now. Save your CIGAR preference edits before preparing or committing a selection.</p> : null}
    {data ? <>
      <section className={versionCard} aria-label="CIGAR release catalog">
        <p className="text-sm text-slate-600">Catalog: {data.catalog.catalog.source} · {data.catalog.catalog.fresh_for_preparation ? "current for preparation" : "refresh required"} · Guard host: {data.catalog.host_platform ?? "not reported by this Guard build"}</p>
        {!data.catalog.catalog.remote_feed_configured ? <p className="text-sm text-slate-600">A remote release feed is not configured. Guard can still use eligible bundled entries.</p> : null}
        {data.catalog.catalog.diagnostic ? <p className="break-all text-sm text-amber-800">Catalog diagnostic: {data.catalog.catalog.diagnostic}</p> : null}
        {data.catalog.catalog.trust_diagnostic || data.catalog.catalog.feed_diagnostic ? <p className="break-all text-sm text-amber-800">Catalog update configuration: {data.catalog.catalog.trust_diagnostic ?? data.catalog.catalog.feed_diagnostic}</p> : null}
        <details className="text-sm text-slate-600"><summary className="cursor-pointer">Import a signed catalog</summary>
          <p className="mt-2">Use a catalog signed by an already trusted release key. Importing metadata never selects or starts a runtime.</p>
          <label className="mt-2 block">Signed catalog JSON<textarea className={versionField} rows={4} maxLength={2_000_000} value={signedCatalog} disabled={changesDisabled}
            onChange={(event) => setSignedCatalog(event.target.value)} spellCheck={false} /></label>
          <button type="button" className={versionButton} disabled={changesDisabled || !signedCatalog.trim() || !data.catalog.catalog.trust_configured}
            onClick={() => choose({ input: { action: "import_catalog", signed_catalog: signedCatalog }, title: "Import signed CIGAR catalog",
              detail: "Verify and publish this release metadata using Guard's existing trusted keys. Leave the selected runtime unchanged." })}>Verify & import catalog</button>
        </details>
      </section>
      <CigarVersionJobsPanel jobs={data.jobs} status={props.status} disabled={disabled} selectionDisabled={selectionDisabled} onAction={choose} />
      <CigarVersionBuildsPanel data={data} status={props.status} disabled={changesDisabled} selectionDisabled={selectionDisabled} onAction={choose} />
      <CigarUpdatePreferencesPanel value={data.updates} builds={data.catalog.builds} disabled={changesDisabled} onAction={choose} />
    </> : null}
    <SettingsSaveProofModal open={approval !== null} mode="verify-save" gate={props.gate}
      title={approval?.title ?? "Confirm CIGAR change"} detail={approval?.detail ?? ""} confirmLabel="Confirm change"
      error={null} pending={versions.busy} onCancel={() => setApproval(null)}
      onConfirm={(proof) => { if (approval) { const action = approval; setApproval(null); void versions.perform(action.input, proof); } }} />
  </div>;
}
