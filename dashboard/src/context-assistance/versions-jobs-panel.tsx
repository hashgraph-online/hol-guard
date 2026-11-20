import { useId, useState } from "react";
import { HiMiniArrowPath, HiMiniChevronRight, HiMiniExclamationTriangle } from "react-icons/hi2";
import { Tag } from "../approval-center-primitives";
import type { ContextAssistanceStatus } from "./types";
import { canCommitCigarJob, cigarJobPending } from "./versions-actions";
import type { CigarVersionJob } from "./versions-jobs";
import { versionButton, versionHeading, versionLead, versionPrimary, type CigarVersionActionHandler } from "./versions-view";
type Props = { jobs: CigarVersionJob[]; status: ContextAssistanceStatus | null; disabled: boolean; selectionDisabled: boolean; onAction: CigarVersionActionHandler };
const operation = { install: "Download CIGAR", verify: "Check CIGAR", setup_interpreter: "Set up Python for CIGAR", refresh_catalog: "Look for new versions",
  switch: "Switch CIGAR version", rollback: "Go back to the earlier version", select: "Choose a CIGAR version", recover: "Clean up a version switch" };
const phaseWords: Record<string, string> = { ready: "Ready", completed: "Done", cancelled: "Cancelled", failed: "Did not finish", recovery_required: "Needs cleanup" };
export function cigarJobPhaseLabel(job: CigarVersionJob): string {
  // Guard keeps a prepared switch's worker alive while it waits for the person to choose Switch now.
  if (job.phase === "ready" && job.can_commit) return "Ready to switch";
  if (cigarJobPending(job)) return "Working";
  return phaseWords[job.phase] ?? "Stopped partway";
}
const time = (ms: number) => <time dateTime={new Date(ms).toISOString()}>{new Date(ms).toLocaleString()}</time>;
export function CigarVersionJobsPanel(props: Props) {
  const [acknowledged, setAcknowledged] = useState<string | null>(null);
  const id = useId();
  return <section className="space-y-3" aria-labelledby={id + "-heading"}>
    <div><h3 id={id + "-heading"} className={versionHeading}>In progress</h3>
      <p className={versionLead}>Work Guard is doing for you. Each change waits for your go-ahead before it touches the version in use.</p></div>
    {!props.jobs.length ? <p className="text-sm text-brand-dark/65">Nothing is running right now.</p> : null}
    {props.jobs.map((job) => {
      const pending = cigarJobPending(job);
      // A prepared switch keeps its worker alive but is waiting on the person, not working.
      const working = pending && !(job.phase === "ready" && job.can_commit);
      const attention = job.recovery_available || job.phase === "failed" || job.phase === "recovery_required";
      let tone: "amber" | "blue" | "slate" = pending ? "blue" : "slate";
      if (attention) tone = "amber";
      return <article key={job.job_id} aria-label={operation[job.operation] + " " + job.job_id}
        className={"guard-surface-in space-y-3 rounded-2xl border p-4 sm:p-5 " + (attention ? "border-amber-300/70 bg-amber-50/50" : "border-brand-blue/20 bg-brand-blue/[0.03]")}>
        <div className="flex flex-wrap items-center gap-2.5">
          <span aria-hidden="true" className={"flex size-8 items-center justify-center rounded-full " + (attention ? "bg-amber-100 text-amber-700" : "bg-brand-blue/10 text-brand-blue")}>
            {attention ? <HiMiniExclamationTriangle className="size-4" /> : <HiMiniArrowPath className={"size-4" + (working ? " motion-safe:animate-spin" : "")} />}
          </span>
          <h4 className="font-semibold text-brand-dark">{operation[job.operation]}</h4>
          <span role="status"><Tag tone={tone}>{cigarJobPhaseLabel(job)}{job.cancel_requested ? " · stopping" : ""}</Tag></span>
        </div>
        {job.family === "selection" ? <div className="space-y-2 text-sm leading-6 text-brand-dark/75">
          <p className="break-all text-xs text-brand-dark/55">Target: {job.target_runtime_id}</p>
          {job.keeps_disabled ? <p>{job.operation === "recover" ? "Recovery keeps CIGAR off." : "Selecting this runtime keeps CIGAR off."} Start it separately when you are ready.</p>
            : <p>Switching briefly pauses CIGAR. Context access and app connections require fresh grants afterward. Your Guard approvals remain in place.</p>}
          {job.can_commit ? <>
            {job.reconnect_required ? <label className="flex min-h-11 cursor-pointer items-center gap-3 rounded-lg border border-brand-dark/10 bg-white px-3"><input type="checkbox" className="size-4 accent-brand-blue"
              checked={acknowledged === job.job_id + ":" + job.expected_generation} disabled={props.selectionDisabled}
              onChange={(event) => setAcknowledged(event.target.checked ? job.job_id + ":" + job.expected_generation : null)} />I am ready to reconnect context sources and apps.</label> : null}
            <button type="button" className={versionPrimary}
              disabled={props.selectionDisabled || !canCommitCigarJob(job, props.status)
                || job.reconnect_required && acknowledged !== job.job_id + ":" + job.expected_generation}
              onClick={() => props.onAction({ input: { action: "commit", job_id: job.job_id, expected_generation: job.expected_generation, reconnect: job.reconnect_required },
                title: job.keeps_disabled ? "Select CIGAR runtime" : "Switch CIGAR now",
                detail: job.keeps_disabled ? "Commit the verified selection and keep CIGAR off." : "Switch to the verified runtime now. Reconnect context sources and apps after the switch." })}>
              {job.keeps_disabled ? "Select & keep CIGAR off" : "Switch now"}</button>
            {!canCommitCigarJob(job, props.status) ? <p className="text-amber-800">The live selection changed. Refresh status and jobs before continuing.</p> : null}
          </> : null}
        </div> : null}
        {job.recovery_available ? <p className="text-sm leading-6 text-amber-900">This step stopped partway. Choose Clean up and Guard finishes or undoes it.</p> : null}
        {(pending && !job.cancel_requested) || job.recovery_available ? <div className="flex flex-wrap gap-2">
          {pending && !job.cancel_requested ? <button type="button" className={versionButton} disabled={props.disabled}
            onClick={() => props.onAction({ input: { action: "cancel", job_id: job.job_id }, title: "Stop this step", detail: "Guard stops this step and tidies up after it. The CIGAR version you use now stays as it is." })}>Stop</button> : null}
          {job.recovery_available ? <button type="button" className={versionButton} disabled={props.disabled || !props.status}
            onClick={() => props.onAction({ input: { action: "recover", job_id: job.job_id,
              ...(job.family === "selection" && props.status ? { expected_generation: props.status.generation } : {}) },
              title: "Clean up this step", detail: "Guard finishes or undoes the step that stopped partway. Context access you gave before is not turned back on, and your Guard approvals stay as they are." })}>Clean up</button> : null}
        </div> : null}
        <details className="group text-xs text-brand-dark/60"><summary className="inline-flex min-h-8 cursor-pointer list-none items-center gap-1 font-medium hover:text-brand-dark [&::-webkit-details-marker]:hidden">
          <HiMiniChevronRight aria-hidden="true" className="size-3.5 transition-transform group-open:rotate-90 motion-reduce:transition-none" />Job details</summary>
          <div className="mt-1 space-y-0.5 pl-5">
            <p className="break-all">Job: {job.job_id}</p><p className="break-all">Diagnostic: {job.code}</p>
            {job.family === "selection" ? <p>Expected generation: {job.expected_generation}</p> : null}
            {job.family === "selection" && job.recovery_attempt ? <>
              <p>Recovery deadline: {time(job.recovery_attempt.deadline_at_ms)}</p>
              <p>Original preparation deadline: {time(job.deadline_at_ms)}</p>
            </> : <p>Deadline: {time(job.deadline_at_ms)}</p>}
            {job.family === "selection" && job.cleanup_pending ? <p>Cleanup is still pending. Wait before another switch.</p> : null}
          </div>
        </details>
      </article>;
    })}
  </section>;
}
