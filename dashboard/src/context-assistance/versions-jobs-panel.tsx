import { useId, useState } from "react";
import type { ContextAssistanceStatus } from "./types";
import { canCommitCigarJob, cigarJobPending } from "./versions-actions";
import type { CigarVersionJob } from "./versions-jobs";
import { versionButton, versionCard, type CigarVersionActionHandler } from "./versions-view";
type Props = { jobs: CigarVersionJob[]; status: ContextAssistanceStatus | null; disabled: boolean; selectionDisabled: boolean; onAction: CigarVersionActionHandler };
const operation = { install: "Prepare SDK", verify: "Verify installation", setup_interpreter: "Prepare Python", refresh_catalog: "Refresh catalog",
  switch: "Switch runtime", rollback: "Roll back runtime", select: "Select first runtime", recover: "Recover selection" };
export function CigarVersionJobsPanel(props: Props) {
  const [acknowledged, setAcknowledged] = useState<string | null>(null);
  const id = useId();
  return <section className="space-y-3" aria-labelledby={id + "-heading"}>
    <h3 id={id + "-heading"} className="font-semibold text-brand-dark">Preparation & selection jobs</h3>
    {!props.jobs.length ? <p className="text-sm text-slate-600">No CIGAR update jobs have been recorded.</p> : null}
    {props.jobs.map((job) => <article className={versionCard} key={job.job_id} aria-label={operation[job.operation] + " " + job.job_id}>
      <h4 className="font-semibold text-brand-dark">{operation[job.operation]}</h4>
      <p className="text-sm text-slate-600" role="status">{job.phase.replaceAll("_", " ")}{job.cancel_requested ? " · cancellation requested" : ""}</p>
      {job.family === "selection" ? <>
        <p className="break-all text-sm text-slate-600">Target: {job.target_runtime_id}</p>
        {job.keeps_disabled ? <p className="text-sm text-slate-600">{job.operation === "recover" ? "Recovery keeps CIGAR off." : "Selecting this runtime keeps CIGAR off."} Start it separately when you are ready.</p>
          : <p className="text-sm text-slate-600">Switching briefly pauses CIGAR. Context access and app connections require fresh grants afterward. Your Guard approvals remain in place.</p>}
        {job.can_commit ? <>
          {job.reconnect_required ? <label className="flex min-h-11 items-center gap-3 text-sm text-slate-600"><input type="checkbox"
            checked={acknowledged === job.job_id + ":" + job.expected_generation} disabled={props.selectionDisabled}
            onChange={(event) => setAcknowledged(event.target.checked ? job.job_id + ":" + job.expected_generation : null)} />I am ready to reconnect context sources and apps.</label> : null}
          <button type="button" className={versionButton}
            disabled={props.selectionDisabled || !canCommitCigarJob(job, props.status)
              || job.reconnect_required && acknowledged !== job.job_id + ":" + job.expected_generation}
            onClick={() => props.onAction({ input: { action: "commit", job_id: job.job_id, expected_generation: job.expected_generation, reconnect: job.reconnect_required },
              title: job.keeps_disabled ? "Select CIGAR runtime" : "Switch CIGAR now",
              detail: job.keeps_disabled ? "Commit the verified selection and keep CIGAR off." : "Switch to the verified runtime now. Reconnect context sources and apps after the switch." })}>
            {job.keeps_disabled ? "Select & keep CIGAR off" : "Switch now"}</button>
          {!canCommitCigarJob(job, props.status) ? <p className="text-sm text-amber-800">The live selection changed. Refresh status and jobs before continuing.</p> : null}
        </> : null}
      </> : null}
      <div className="flex flex-wrap gap-2">
        {cigarJobPending(job) && !job.cancel_requested ? <button type="button" className={versionButton} disabled={props.disabled}
          onClick={() => props.onAction({ input: { action: "cancel", job_id: job.job_id }, title: "Cancel CIGAR job", detail: "Ask Guard to cancel this job and finish its cleanup." })}>Cancel job</button> : null}
        {job.recovery_available ? <button type="button" className={versionButton} disabled={props.disabled || !props.status}
          onClick={() => props.onAction({ input: { action: "recover", job_id: job.job_id,
            ...(job.family === "selection" && props.status ? { expected_generation: props.status.generation } : {}) },
            title: "Recover interrupted CIGAR work", detail: "Ask Guard to reconcile the interrupted operation. Recovery never restores old context grants or approvals." })}>Recover job</button> : null}
      </div>
      <details className="text-xs text-slate-600"><summary className="cursor-pointer">Job details</summary>
        <p className="break-all">Job: {job.job_id}</p><p className="break-all">Diagnostic: {job.code}</p>
        {job.family === "selection" ? <p>Expected generation: {job.expected_generation}</p> : null}
        {job.family === "selection" && job.recovery_attempt ? <>
          <p>Recovery deadline: <time dateTime={new Date(job.recovery_attempt.deadline_at_ms).toISOString()}>{new Date(job.recovery_attempt.deadline_at_ms).toLocaleString()}</time></p>
          <p>Original preparation deadline: <time dateTime={new Date(job.deadline_at_ms).toISOString()}>{new Date(job.deadline_at_ms).toLocaleString()}</time></p>
        </> : <p>Deadline: <time dateTime={new Date(job.deadline_at_ms).toISOString()}>{new Date(job.deadline_at_ms).toLocaleString()}</time></p>}
        {job.family === "selection" && job.cleanup_pending ? <p>Cleanup is still pending. Wait before another switch.</p> : null}
      </details>
    </article>)}
  </section>;
}
