import { useState } from "react";
import { HiMiniArrowPath, HiMiniChevronRight, HiMiniCloudArrowDown } from "react-icons/hi2";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal } from "../settings-save-proof-modal";
import type { ContextAssistanceStatus } from "./types";
import { cigarVersionJobId } from "./versions-actions";
import { CigarVersionBuildsPanel } from "./versions-builds-panel";
import { CigarVersionJobsPanel } from "./versions-jobs-panel";
import { CigarUpdatePreferencesPanel } from "./versions-preferences-panel";
import { CigarVersionStatusBand } from "./versions-status-band";
import { useCigarVersions, type CaptureCigarStatus } from "./use-versions";
import { versionButton, versionField, versionQuiet, type CigarVersionAction } from "./versions-view";
type Props = { status: ContextAssistanceStatus | null; disabled: boolean; locked: boolean; dirty: boolean;
  gate: GuardApprovalGatePublicConfig | null; captureStatus: CaptureCigarStatus };
const notice = "rounded-xl border border-brand-dark/10 bg-surface-1 px-4 py-3 text-sm leading-6 text-brand-dark/75";
export function CigarVersionsPanel(props: Props) {
  const versions = useCigarVersions(props.captureStatus);
  const [approval, setApproval] = useState<CigarVersionAction | null>(null);
  const [signedCatalog, setSignedCatalog] = useState("");
  const { data } = versions;
  const disabled = props.disabled || versions.busy || versions.loading;
  const changesDisabled = disabled || versions.uncertain;
  const selectionDisabled = changesDisabled || props.locked || props.dirty || !props.status || Boolean(props.status.job);
  const catalog = data?.catalog.catalog;
  function choose(action: CigarVersionAction) {
    if (disabled || action.input.action !== "cancel" && versions.uncertain) return;
    if (action.input.action !== "cancel" && props.gate?.enabled) setApproval(action);
    else void versions.perform(action.input);
  }
  return <div className="space-y-6" data-testid="cigar-versions">
    <div className="cigar-section-intro"><h2>Updates</h2>
      <p>Guard handles this for you when you turn CIGAR on. Come here only to pick a specific version, check for new ones, or go back to an earlier one. Opening this page changes nothing.</p></div>
    <CigarVersionStatusBand status={props.status} data={data} loading={versions.loading} actions={<>
      <button type="button" className={versionButton} disabled={changesDisabled || !catalog?.remote_feed_configured || !catalog.trust_configured || Boolean(catalog.feed_diagnostic)}
        onClick={() => choose({ input: { action: "refresh_catalog", job_id: cigarVersionJobId() }, title: "Check for CIGAR catalog updates",
          detail: "Fetch the configured signed release catalog. This does not prepare or switch an SDK." })}><HiMiniCloudArrowDown aria-hidden="true" className="size-4" />Check for catalog updates</button>
      <button type="button" className={versionQuiet} disabled={props.disabled || versions.busy || versions.loading} onClick={() => void versions.refresh()}>
        <HiMiniArrowPath aria-hidden="true" className={"size-4" + (versions.loading ? " motion-safe:animate-spin" : "")} />Refresh versions & jobs</button>
    </>} />
    {versions.loading && !data ? <div role="status" className="space-y-3" aria-label="Reading CIGAR versions and job metadata…">
      {[0, 1, 2].map((row) => <div key={row} className="h-16 rounded-2xl bg-brand-dark/[0.04] motion-safe:animate-pulse" />)}
      <span className="sr-only">Reading CIGAR versions and job metadata…</span></div> : null}
    {versions.busy ? <p role="status" className={notice}>Submitting the selected action. Preparation continues as a native job.</p> : null}
    {versions.error ? <div role="alert" className="cigar-note"><strong>CIGAR updates need attention</strong><p>{versions.error}</p><p>Refresh versions and jobs before submitting another change.</p></div> : null}
    {versions.tracking ? <p className="break-all text-xs text-brand-dark/60">Last submitted job: {versions.tracking}. Refresh jobs to confirm its outcome.</p> : null}
    {props.dirty ? <p role="status" className={notice}>You can prepare builds now. Save your CIGAR preference edits before preparing or committing a selection.</p> : null}
    {data ? <>
      {data.jobs.length ? <CigarVersionJobsPanel jobs={data.jobs} status={props.status} disabled={disabled} selectionDisabled={selectionDisabled} onAction={choose} /> : null}
      <CigarVersionBuildsPanel data={data} status={props.status} disabled={changesDisabled} selectionDisabled={selectionDisabled} onAction={choose} />
      <details className="group rounded-2xl border border-brand-dark/10 bg-white">
        <summary className="flex min-h-14 cursor-pointer list-none items-center gap-3 rounded-2xl px-4 py-3 hover:bg-surface-1 sm:px-5 [&::-webkit-details-marker]:hidden">
          <HiMiniChevronRight aria-hidden="true" className="size-4 shrink-0 text-brand-dark/50 transition-transform group-open:rotate-90 motion-reduce:transition-none" />
          <span className="min-w-0"><span className="block text-sm font-semibold text-brand-dark">Advanced</span>
            <span className="block text-xs text-brand-dark/60">Update preferences, pinning and the release catalog</span></span>
        </summary>
        <div className="space-y-8 border-t border-brand-dark/[0.07] px-4 py-5 sm:px-5">
          <CigarUpdatePreferencesPanel value={data.updates} builds={data.catalog.builds} disabled={changesDisabled} onAction={choose} />
          <section className="space-y-3 border-t border-brand-dark/[0.07] pt-6" aria-label="CIGAR release catalog">
            <h4 className="font-semibold text-brand-dark">Release catalog</h4>
            <dl className="grid gap-3 text-sm sm:grid-cols-3">
              <div><dt className="text-xs text-brand-dark/55">Source</dt><dd className="font-medium capitalize text-brand-dark">{data.catalog.catalog.source}</dd></div>
              <div><dt className="text-xs text-brand-dark/55">Freshness</dt><dd className="font-medium text-brand-dark">{data.catalog.catalog.fresh_for_preparation ? "current for preparation" : "refresh required"}</dd></div>
              <div><dt className="text-xs text-brand-dark/55">Guard host</dt><dd className="font-mono text-xs leading-5 text-brand-dark">{data.catalog.host_platform ?? "not reported by this Guard build"}</dd></div>
            </dl>
            {!data.catalog.catalog.remote_feed_configured ? <p className="text-sm text-brand-dark/70">A remote release feed is not configured. Guard can still use eligible bundled entries.</p> : null}
            {data.catalog.catalog.diagnostic ? <p className="break-all text-sm text-amber-800">Catalog diagnostic: {data.catalog.catalog.diagnostic}</p> : null}
            {data.catalog.catalog.trust_diagnostic || data.catalog.catalog.feed_diagnostic ? <p className="break-all text-sm text-amber-800">Catalog update configuration: {data.catalog.catalog.trust_diagnostic ?? data.catalog.catalog.feed_diagnostic}</p> : null}
            <details className="group/import text-sm text-brand-dark/75"><summary className="inline-flex min-h-11 cursor-pointer list-none items-center gap-1.5 font-semibold text-brand-dark/80 hover:text-brand-dark [&::-webkit-details-marker]:hidden">
              <HiMiniChevronRight aria-hidden="true" className="size-4 transition-transform group-open/import:rotate-90 motion-reduce:transition-none" />Import a signed catalog</summary>
              <div className="space-y-3 pl-5">
                <p>Use a catalog signed by an already trusted release key. Importing metadata never selects or starts a runtime.</p>
                <label className="block text-xs font-medium text-brand-dark/65">Signed catalog JSON<textarea className={versionField + " font-mono text-xs"} rows={4} maxLength={2_000_000} value={signedCatalog} disabled={changesDisabled}
                  onChange={(event) => setSignedCatalog(event.target.value)} spellCheck={false} /></label>
                <button type="button" className={versionButton} disabled={changesDisabled || !signedCatalog.trim() || !data.catalog.catalog.trust_configured}
                  onClick={() => choose({ input: { action: "import_catalog", signed_catalog: signedCatalog }, title: "Import signed CIGAR catalog",
                    detail: "Verify and publish this release metadata using Guard's existing trusted keys. Leave the selected runtime unchanged." })}>Verify & import catalog</button>
              </div>
            </details>
          </section>
        </div>
      </details>
    </> : null}
    <SettingsSaveProofModal open={approval !== null} mode="verify-save" gate={props.gate}
      title={approval?.title ?? "Confirm CIGAR change"} detail={approval?.detail ?? ""} confirmLabel="Confirm change"
      error={null} pending={versions.busy} onCancel={() => setApproval(null)}
      onConfirm={(proof) => { if (approval) { const action = approval; setApproval(null); void versions.perform(action.input, proof); } }} />
  </div>;
}
