import { useEffect, useRef, useState } from "react";
import { guardAwareHref } from "../guard-api";
import type { GuardApprovalRequest } from "../guard-types";
import { attachedNativeDecision, prepareNativeDecisionContext, type NativeDecisionContext } from "./action-api";
import { fetchContextAssistance } from "./api";
import { ContextBriefView } from "./brief-view";
import { listContextWorkspaces } from "./workspaces-api";

const button = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";

export function ContextReviewPanel({ item }: { item: GuardApprovalRequest }) {
  const decisionId = attachedNativeDecision(item.action_envelope_json, item.harness);
  const [context, setContext] = useState<NativeDecisionContext | null>(null);
  const [previous, setPrevious] = useState<NativeDecisionContext | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const revision = useRef(0);
  const generation = useRef<string | null>(null);
  const [watching, setWatching] = useState(false);

  useEffect(() => {
    revision.current += 1; request.current?.abort(); generation.current = null;
    setContext(null); setPrevious(null); setError(null); setBusy(false); setWatching(false);
    return () => { revision.current += 1; request.current?.abort(); };
  }, [item.request_id, item.status, item.workspace, item.harness, decisionId]);

  useEffect(() => {
    if (!watching || !context) return;
    const controller = new AbortController();
    let pending = false;
    const timer = window.setInterval(() => {
      if (pending) return;
      pending = true;
      void fetchContextAssistance(controller.signal).then(async (status) => {
        if (controller.signal.aborted) return;
        let authorized = status.effective_enabled && status.generation === generation.current;
        if (authorized) {
          const scopes = await listContextWorkspaces(controller.signal);
          const scope = scopes.find((scope) => scope.scope_id === context.scope.scope_id);
          authorized = Boolean(scope && !scope.revoked && scope.native_policy_facts
            && scope.policy_revision === context.scope.policy_revision && scope.sources.length === context.scope.sources.length
            && context.scope.sources.every((source) => scope.sources.some((current) => current.source_id === source.source_id && current.sha256 === source.sha256)));
        }
        if (controller.signal.aborted) return;
        if (!authorized) {
          revision.current += 1; request.current?.abort();
          setContext(null); setPrevious(null); setBusy(false); setWatching(false);
          setError("Context access changed. Check Projects & AI apps in CIGAR before preparing more context.");
        }
      }).catch(() => {
        if (!controller.signal.aborted) {
          revision.current += 1; request.current?.abort();
          setContext(null); setPrevious(null); setBusy(false); setWatching(false);
          setError("Context status is unavailable. Refresh it before using prepared context.");
        }
      }).finally(() => { pending = false; });
    }, 2500);
    return () => { window.clearInterval(timer); controller.abort(); };
  }, [watching, context]);

  async function prepare(explain = false) {
    if (busy || !decisionId) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError(null);
    try {
      const status = await fetchContextAssistance(controller.signal);
      if (controller.signal.aborted) return;
      if (!status.effective_enabled || !status.effective_preferences.features.review_briefs) {
        throw new Error("Enable review context and start a verified Python 3.14 runtime in CIGAR → Settings.");
      }
      generation.current = status.generation;
      const scopes = await listContextWorkspaces(controller.signal);
      const scope = scopes.find((scope) => scope.app === "dashboard" && scope.workspace === item.workspace
        && !scope.revoked && scope.native_policy_facts);
      if (!scope) throw new Error("Grant this workspace dashboard access with native Guard policy facts in CIGAR → Projects & AI apps.");
      const value = await prepareNativeDecisionContext(scope, decisionId, item.harness, controller.signal,
        explain ? context?.brief.snapshot_id : undefined);
      if (revision.current !== current || controller.signal.aborted) return;
      if (!explain && context) setPrevious(context);
      setContext(value); setWatching(true);
    } catch (cause) {
      if (revision.current === current && !controller.signal.aborted) {
        setContext(null); setPrevious(null); setWatching(false);
        setError(cause instanceof Error ? cause.message : "Decision context is unavailable. Guard approvals remain available.");
      }
    } finally {
      if (revision.current === current) setBusy(false);
    }
  }

  if (!decisionId) return null;
  return <section aria-label="Optional decision context" className="space-y-3 rounded-xl border border-slate-200 p-4 sm:p-5">
    <h3 className="text-sm font-semibold text-brand-dark">Optional decision context</h3>
    <p className="text-sm text-slate-600">Prepare local supporting context for the attached native decision using the sources you authorize.</p>
    <div className="flex flex-wrap gap-2" aria-busy={busy}>
      <button type="button" className={button} disabled={busy} onClick={() => void prepare()}>
        {busy ? "Preparing context…" : context ? "Refresh decision context" : "Prepare decision context"}
      </button>
      {context ? <button type="button" className={button} disabled={busy} onClick={() => void prepare(true)}>Verify context sources</button> : null}
      <a className={`${button} inline-flex items-center`} href={guardAwareHref("/cigar?section=access")}>Manage context access</a>
    </div>
    {error ? <p role="status" className="text-sm text-slate-600">{error} You can still use the approval controls.</p> : null}
    {context ? <section aria-label="Native decision context" className="space-y-3">
      <p className="text-sm text-slate-600">Verified when prepared · {context.brief.rendered_tokens} tokens. Refresh after sources or access change.</p>
      <ContextBriefView brief={context.brief} scope={context.scope} />
      {context.explanation ? <p role="status" className="text-sm text-slate-600">The retained selection and its sources were verified again.</p> : null}
      <details><summary className="min-h-11 cursor-pointer text-sm font-semibold">Native decision association</summary>
        <p className="text-sm text-slate-600">{context.association.action_type} · {context.association.operation} · policy generation {context.association.policy_generation}</p>
        <p className="break-all text-xs text-slate-500">{context.association.decision_id}</p>
        <p className="text-sm text-slate-600">This links context to the native evaluation. Current executable bytes and execution are not verified by this context.</p>
      </details>
      {previous ? <details><summary className="min-h-11 cursor-pointer text-sm font-semibold">Compare with earlier decision context</summary>
        <p className="mb-2 text-sm text-slate-600">Earlier context is historical and may no longer apply.</p>
        <ContextBriefView brief={previous.brief} scope={previous.scope} />
      </details> : null}
    </section> : null}
  </section>;
}
