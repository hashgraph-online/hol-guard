import { useCallback, useEffect, useRef, useState } from "react";
import { HiMiniCheckCircle, HiMiniExclamationTriangle, HiMiniWrenchScrewdriver } from "react-icons/hi2";
import { ActionButton, Tag, type TagTone } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { WorkspaceFinding, WorktreeKeys } from "./workspace-findings-api";
import {
  applyFix,
  fetchFixProposals,
  FixRequestError,
  prepareFix,
  skippedManifestMessage,
  type FixProposal,
  type AppliedFix,
  type FixProposalState,
  type PreparedFix,
} from "./workspace-fix-api";

/** Only a direct npm dependency with a published fix can get a reviewed one-line edit. */
export function canPrepareFix(finding: WorkspaceFinding): boolean {
  return finding.ecosystem === "npm" && finding.fixVersion !== null && finding.packageName !== null;
}

const STATE_TAGS: Record<Exclude<FixProposalState, "prepared">, { label: string; tone: TagTone }> = {
  applied: { label: "Waiting for re-check", tone: "attention" },
  still_present: { label: "Still found", tone: "red" },
  verified_fixed: { label: "Fixed", tone: "green" },
  stale: { label: "File changed", tone: "slate" },
};

export type WorktreeFixes = {
  proposals: FixProposal[];
  /** The finding whose fix is open for review. */
  reviewing: string | null;
  prepared: PreparedFix | null;
  busy: string | null;
  error: string | null;
  /** The proposal list could not be read, so stored fixes are unknown. */
  loaded: boolean;
  loadError: string | null;
  /** The daemon cannot write fixes on this system; the diff stays for a manual edit. */
  applyUnsupported: boolean;
  notice: string | null;
  prepare: (finding: WorkspaceFinding) => void;
  review: (findingId: string) => void;
  close: () => void;
  apply: (proposal: FixProposal) => void;
  retry: () => void;
};

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Proposals of one worktree, reloaded whenever a newer assessment can settle them. */
export function useWorktreeFixes(worktree: WorktreeKeys, assessmentRunId: string | null): WorktreeFixes {
  const [proposals, setProposals] = useState<FixProposal[]>([]);
  const [reviewing, setReviewing] = useState<string | null>(null);
  const [prepared, setPrepared] = useState<PreparedFix | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [applyUnsupported, setApplyUnsupported] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const mounted = useRef(true);
  const latestReload = useRef(0);
  const { codebaseKey, worktreeKey } = worktree;

  /** Resolves to the list it applied, or null when a newer reload started first. */
  const reload = useCallback(async (signal?: AbortSignal): Promise<FixProposal[] | null> => {
    latestReload.current += 1;
    const request = latestReload.current;
    try {
      const next = await fetchFixProposals({ codebaseKey, worktreeKey }, signal);
      if (!mounted.current || request !== latestReload.current) return null;
      setProposals(next);
      setLoaded(true);
      setLoadError(null);
      return next;
    } catch (reason) {
      if (mounted.current && request === latestReload.current && !signal?.aborted) setLoadError(message(reason));
      throw reason;
    }
  }, [codebaseKey, worktreeKey]);

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    reload(controller.signal).catch(() => undefined);
    return () => {
      mounted.current = false;
      controller.abort();
    };
  }, [reload, assessmentRunId]);

  const run = useCallback(async (key: string, operation: () => Promise<void>) => {
    setBusy(key);
    setError(null);
    setNotice(null);
    try {
      await operation();
    } catch (reason) {
      if (!mounted.current) return;
      setError(message(reason));
      if (reason instanceof FixRequestError && reason.code === "fix_apply_unsupported") setApplyUnsupported(true);
    } finally {
      if (mounted.current) setBusy(null);
    }
  }, []);

  const prepare = useCallback((finding: WorkspaceFinding) => {
    setReviewing(finding.findingId);
    setPrepared(null);
    void run(`prepare:${finding.findingId}`, async () => {
      let result: PreparedFix;
      try {
        result = await prepareFix({ codebaseKey, worktreeKey }, finding.findingId);
      } catch (reason) {
        // A refusal still names the files it left unchanged.
        if (mounted.current && reason instanceof FixRequestError && (reason.skipped.length > 0 || reason.truncated)) {
          setPrepared({ proposals: [], skipped: reason.skipped, truncated: reason.truncated });
        }
        throw reason;
      }
      if (!mounted.current) return;
      setPrepared(result);
      await reload();
    });
  }, [codebaseKey, worktreeKey, reload, run]);

  const apply = useCallback((proposal: FixProposal) => {
    void run(`apply:${proposal.proposalId}`, async () => {
      let result: AppliedFix | null = null;
      try {
        result = await applyFix(proposal.proposalId);
      } finally {
        // A stale or refused apply changes the proposal's state too.
        const next = await reload().catch(() => null);
        if (result && mounted.current) {
          setNotice(appliedNotice(proposal, result));
          // Keep the review open while another package.json still waits for its own apply,
          // and when the reload failed or was superseded, since then it is unknown.
          const remaining = next === null || next.some(
            (item) => item.findingId === proposal.findingId && item.state === "prepared",
          );
          if (!remaining) {
            setReviewing(null);
            setPrepared(null);
          }
        }
      }
    });
  }, [reload, run]);

  const review = useCallback((findingId: string) => {
    setReviewing(findingId);
    setPrepared(null);
    setError(null);
  }, []);
  const close = useCallback(() => {
    setReviewing(null);
    setPrepared(null);
    setError(null);
  }, []);

  const retry = useCallback(() => {
    void reload().catch(() => undefined);
  }, [reload]);

  return {
    proposals, reviewing, prepared, busy, error, loaded, loadError, applyUnsupported, notice,
    prepare, review, close, apply, retry,
  };
}

export function appliedNotice(proposal: FixProposal, result: AppliedFix): string {
  const lockfiles = result.lockfiles.length > 0 ? result.lockfiles.join(", ") : "your lockfile";
  const changed = `Guard changed ${proposal.manifestPath}. Update ${lockfiles} with your package manager. `;
  if (!result.verificationQueued) {
    return changed + "Guard could not schedule a check, so run Assess now once the lockfile is updated. " +
      "It marks this fixed only when a complete check no longer finds it.";
  }
  return changed + "Guard checks again after each change and marks this fixed only when a complete check no longer finds it.";
}

/**
 * One prepare stores a proposal per package.json with the same timestamp, so a
 * proposal still waiting for review wins over whichever sibling sorts first.
 */
function currentFor(proposals: FixProposal[], findingId: string): FixProposal | undefined {
  const own = proposals.filter((proposal) => proposal.findingId === findingId);
  // The daemon lists proposals newest first.
  return own.find((proposal) => proposal.state === "prepared") ?? own[0];
}

export function FixCell(props: { finding: WorkspaceFinding; fixes: WorktreeFixes }) {
  const { finding, fixes } = props;
  const proposal = currentFor(fixes.proposals, finding.findingId);
  const preparing = fixes.busy === `prepare:${finding.findingId}`;
  // Until the list loads, a stored proposal could be hidden behind a second Prepare.
  const blocked = fixes.busy !== null || fixes.loadError !== null || !fixes.loaded;
  if (proposal?.state === "prepared") {
    return (
      <ActionButton variant="outline" onClick={() => fixes.review(finding.findingId)} disabled={fixes.busy !== null}>
        Review fix
      </ActionButton>
    );
  }
  // A finding listed again after a verified fix (a reverted lockfile) needs a new fix, not "Fixed".
  if (proposal && proposal.state !== "stale" && proposal.state !== "verified_fixed") {
    const tag = STATE_TAGS[proposal.state];
    return (
      <span className="inline-flex flex-col items-start gap-1">
        <Tag tone={tag.tone}>{tag.label}</Tag>
        {proposal.state === "still_present" && (
          <span className="text-xs text-slate-500">Update the lockfile, then Guard checks again.</span>
        )}
      </span>
    );
  }
  if (!canPrepareFix(finding)) return <span className="text-slate-500">Manual update</span>;
  return (
    <ActionButton variant="outline" className="gap-1.5" onClick={() => fixes.prepare(finding)} disabled={blocked}>
      <HiMiniWrenchScrewdriver className="h-4 w-4" aria-hidden="true" />
      {preparing ? "Preparing…" : proposal ? "Prepare again" : "Prepare fix"}
    </ActionButton>
  );
}

export function FixReview(props: { fixes: WorktreeFixes; findings: WorkspaceFinding[] }) {
  const { fixes } = props;
  const heading = useRef<HTMLHeadingElement>(null);
  // The review opens below the table, so move focus there for keyboard and phone users.
  useEffect(() => {
    if (fixes.reviewing === null) return;
    heading.current?.focus({ preventScroll: true });
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    heading.current?.scrollIntoView({ block: "nearest", behavior: reduced ? "auto" : "smooth" });
  }, [fixes.reviewing]);
  if (fixes.reviewing === null) return null;
  const finding = props.findings.find((item) => item.findingId === fixes.reviewing);
  // A newer check that no longer lists the finding leaves nothing to apply.
  const pending = finding
    ? fixes.proposals.filter((proposal) => proposal.findingId === fixes.reviewing && proposal.state === "prepared")
    : [];
  const preparing = fixes.busy === `prepare:${fixes.reviewing}`;
  const headingId = `fix-review-${fixes.reviewing.slice(0, 16)}`;
  const skipped = fixes.prepared?.skipped ?? [];

  return (
    <section aria-labelledby={headingId} className="space-y-4 rounded-xl border border-slate-200 bg-surface-1/60 px-4 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1 basis-64">
          <h4 id={headingId} ref={heading} tabIndex={-1} className="text-sm font-semibold text-brand-dark focus:outline-none">
            Review fix for {finding?.packageName ?? pending[0]?.packageName ?? "this package"}
          </h4>
          <p className="mt-1 max-w-[68ch] text-sm text-slate-600">
            Guard changes only the version range shown below. Nothing is written until you apply it, and an edit
            made to the file after this review cancels the change.
          </p>
        </div>
        <ActionButton variant="ghost" onClick={fixes.close} disabled={fixes.busy !== null && !preparing}>
          Close
        </ActionButton>
      </div>
      {preparing && <div className="guard-skeleton h-24 w-full rounded-xl" aria-label="Preparing fix" />}
      {fixes.error && <FixNotice tone="error" text={fixes.error} />}
      {!finding && !preparing && (
        <FixNotice tone="success" text="The latest check no longer lists this finding, so there is nothing to apply." />
      )}
      {pending.map((proposal) => (
        <ProposalReview key={proposal.proposalId} proposal={proposal} fixes={fixes} />
      ))}
      {skipped.length > 0 && (
        <div className="space-y-1">
          <p className="text-sm font-semibold text-brand-dark">Left unchanged</p>
          <ul className="space-y-1 text-sm text-slate-600">
            {skipped.map((item) => (
              <li key={`${item.manifestPath}:${item.reason}`}>
                <span className="font-mono text-xs text-slate-700">{item.manifestPath}</span>{" "}
                {skippedManifestMessage(item.reason)}
              </li>
            ))}
          </ul>
        </div>
      )}
      {fixes.prepared?.truncated && (
        <FixNotice tone="warning" text="Guard stopped before reading every package.json, so other files may still list this package." />
      )}
    </section>
  );
}

function ProposalReview(props: { proposal: FixProposal; fixes: WorktreeFixes }) {
  const { proposal, fixes } = props;
  const applying = fixes.busy === `apply:${proposal.proposalId}`;
  return (
    <div className="space-y-3">
      <ul className="space-y-1 text-sm text-slate-700">
        {proposal.edits.map((edit) => (
          <li key={`${edit.section}:${edit.fromSpec}`}>
            <span className="font-mono text-xs">{proposal.manifestPath}</span>
            <span className="text-slate-500"> · {edit.section}: </span>
            <span className="font-mono text-xs">{edit.fromSpec}</span>
            <span className="text-slate-500"> to </span>
            <span className="font-mono text-xs font-semibold">{edit.toSpec}</span>
          </li>
        ))}
      </ul>
      {proposal.diff && <DiffBlock diff={proposal.diff} label={`Proposed change to ${proposal.manifestPath}`} />}
      {!fixes.applyUnsupported && (
        <ActionButton variant="primary" onClick={() => fixes.apply(proposal)} disabled={fixes.busy !== null}>
          {applying ? "Applying…" : `Apply to ${proposal.manifestPath}`}
        </ActionButton>
      )}
    </div>
  );
}

function lineClass(line: string): string {
  if (line.startsWith("+") && !line.startsWith("+++")) return "bg-emerald-50 text-emerald-900";
  if (line.startsWith("-") && !line.startsWith("---")) return "bg-red-50 text-red-900";
  if (line.startsWith("@@")) return "text-slate-500";
  return "text-slate-700";
}

export function DiffBlock(props: { diff: string; label: string }) {
  const lines = props.diff.replace(/\n$/, "").split("\n");
  return (
    <pre
      aria-label={props.label}
      tabIndex={0}
      className="max-h-72 overflow-auto rounded-lg border border-slate-200 bg-white py-2 font-mono text-xs leading-5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40"
    >
      {lines.map((line, index) => (
        <span key={index} className={`block whitespace-pre px-3 ${lineClass(line)}`}>
          {line || " "}
        </span>
      ))}
    </pre>
  );
}

const HISTORY_DETAIL: Record<"applied" | "still_present" | "verified_fixed", string> = {
  applied: "Waiting for a complete check.",
  still_present: "A complete check still found it. Update the lockfile, then Guard checks again.",
  verified_fixed: "Confirmed by a complete check",
};

/** Applied fixes whose finding is no longer listed, so their outcome stays visible. */
export function FixHistory(props: { fixes: WorktreeFixes; findings: WorkspaceFinding[] }) {
  const listed = new Set(props.findings.map((finding) => finding.findingId));
  const settled = props.fixes.proposals.filter(
    (proposal): proposal is FixProposal & { state: "applied" | "still_present" | "verified_fixed" } =>
      proposal.state !== "prepared" && proposal.state !== "stale" && !listed.has(proposal.findingId),
  );
  if (settled.length === 0 && !props.fixes.notice) return null;
  return (
    <div className="space-y-2">
      {props.fixes.notice && <FixNotice tone="success" text={props.fixes.notice} />}
      {settled.length > 0 && (
        <ul className="divide-y divide-slate-100 border-y border-slate-100 text-sm">
          {settled.map((proposal) => {
            const tag = STATE_TAGS[proposal.state];
            const when = proposal.state === "verified_fixed" && proposal.verifiedAtMs
              ? ` ${formatRelativeTime(new Date(proposal.verifiedAtMs).toISOString())}.`
              : "";
            return (
              <li key={proposal.proposalId} className="flex flex-wrap items-center justify-between gap-2 py-2.5">
                <span className="min-w-0">
                  <span className="font-semibold text-brand-dark">{proposal.packageName}</span>
                  <span className="text-slate-600"> to </span>
                  <span className="font-mono text-xs text-slate-700">{proposal.fixVersion}</span>
                  <span className="text-slate-600"> in </span>
                  <span className="font-mono text-xs text-slate-700">{proposal.manifestPath}</span>
                  <span className="block text-xs text-slate-500">{HISTORY_DETAIL[proposal.state]}{when}</span>
                </span>
                <Tag tone={tag.tone}>{tag.label}</Tag>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/** Shown above the findings so a failed load never reads as "no fixes yet". */
export function FixLoadError(props: { fixes: WorktreeFixes }) {
  if (props.fixes.loadError === null) return null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-red-200 bg-red-50/60 px-3 py-2">
      <p className="flex gap-2 text-sm text-red-800" role="alert">
        <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        Guard could not load the fixes prepared for this workspace, so Prepare stays off until they load. Check that
        Guard is running, then retry.
      </p>
      <ActionButton variant="outline" onClick={props.fixes.retry}>
        Retry
      </ActionButton>
    </div>
  );
}

function FixNotice(props: { tone: "error" | "warning" | "success"; text: string }) {
  const styles = {
    error: "border-red-200 bg-red-50/60 text-red-800",
    warning: "border-amber-200 bg-amber-50/60 text-amber-900",
    success: "border-emerald-200 bg-emerald-50/60 text-emerald-900",
  }[props.tone];
  const Icon = props.tone === "success" ? HiMiniCheckCircle : HiMiniExclamationTriangle;
  return (
    <p className={`flex gap-2 rounded-lg border px-3 py-2 text-sm ${styles}`} role={props.tone === "error" ? "alert" : "status"}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      {props.text}
    </p>
  );
}
