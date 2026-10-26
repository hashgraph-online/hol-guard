import { useEffect, useRef, useState } from "react";
import {
  fetchLocalSkillPage, fetchLocalSkillRoots, scanLocalSkillMetadata,
  prepareSkillWorkflow, type SkillWorkflowPreflight, type LocalSkillPage, type LocalSkillRoot,
} from "../skill-workflow-api";
import { guardAwareHref } from "../guard-api";
import { localCliHref } from "../local-cli-links";

export function LocalSkillsWorkspace() {
  const [open, setOpen] = useState(false);
  const [roots, setRoots] = useState<LocalSkillRoot[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [page, setPage] = useState<LocalSkillPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [input, setInput] = useState("");
  const [search, setSearch] = useState("");
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preparing, setPreparing] = useState<string | null>(null);
  const [preflights, setPreflights] = useState<Record<string, SkillWorkflowPreflight>>({});
  const revision = useRef<number | undefined>(undefined);
  const scan = useRef<AbortController | null>(null);
  useEffect(() => () => scan.current?.abort(), []);
  useEffect(() => {
    if (input === search) return;
    const timer = window.setTimeout(() => { setSearch(input); setOffset(0); }, 250);
    return () => window.clearTimeout(timer);
  }, [input, search]);
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    void Promise.all([
      fetchLocalSkillRoots(controller.signal),
      fetchLocalSkillPage({ offset, search, revision: offset > 0 ? revision.current : undefined, signal: controller.signal }),
    ]).then(([nextRoots, nextPage]) => {
      if (!controller.signal.aborted) {
        setRoots(nextRoots); setPage(nextPage); revision.current = nextPage.revision;
      }
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not load skill metadata.");
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [open, offset, search, reload]);
  const readMetadata = async () => {
    const controller = new AbortController();
    scan.current = controller;
    setBusy(true); setError(null);
    try {
      await scanLocalSkillMetadata(selected, controller.signal);
      if (!controller.signal.aborted) { setOffset(0); setPreflights({}); setReload((value) => value + 1); }
    } catch (caught) {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Skill discovery did not finish.");
    } finally {
      setBusy(false); if (scan.current === controller) scan.current = null;
    }
  };
  const prepareWorkflow = async (skillId: string) => {
    const controller = new AbortController();
    scan.current = controller; setPreparing(skillId); setError(null);
    try {
      const result = await prepareSkillWorkflow(skillId, controller.signal);
      if (result) setPreflights((current) => ({ ...current, [skillId]: result }));
    } catch (caught) {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not prepare this workflow.");
    } finally {
      setPreparing(null); if (scan.current === controller) scan.current = null;
    }
  };
  return (
    <details className="mt-8 border-b border-slate-200 pb-5" onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary className="min-h-11 cursor-pointer py-3 text-base font-semibold text-brand-dark">Local skills and workflows</summary>
      {open ? <section aria-label="Local skill metadata" aria-busy={busy || loading || preparing !== null}>
        <p className="max-w-2xl text-sm leading-6 text-brand-dark/75">
          Choose the skill folders Guard may inspect. This reads bounded names and descriptions.
          Instructions and scripts stay unloaded; declared tools remain requests for permission.
        </p>
        <fieldset disabled={busy || loading || preparing !== null} className="mt-4">
          <legend className="text-sm font-semibold text-brand-dark">Folders to read</legend>
          {roots.map((root) => <label key={root.root_id} className="mt-2 flex min-h-11 items-center gap-3 text-sm text-brand-dark/75">
            <input type="checkbox" checked={selected.includes(root.root_id)} disabled={!root.available}
              onChange={(event) => setSelected((current) => event.target.checked ? [...current, root.root_id]
                : current.filter((id) => id !== root.root_id))} />
            <span className="break-all">{root.path}{root.available ? "" : " · Not available"}</span>
          </label>)}
        </fieldset>
        <div className="mt-3 flex flex-wrap gap-3">
          <button type="button" disabled={busy || loading || preparing !== null || selected.length === 0} onClick={() => void readMetadata()}
            className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50">
            {busy ? "Reading skill metadata…" : "Read selected skill metadata"}
          </button>
          {busy ? <button type="button" onClick={() => scan.current?.abort()}
            className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark">Cancel skill scan</button> : null}
        </div>
        {error ? <div role="alert" className="mt-3 text-sm leading-6 text-red-700">
          <p>{error}</p><button type="button" onClick={() => { setOffset(0); setReload((value) => value + 1); }}
            className="mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark">Reload skill metadata</button>
        </div> : null}
        {page && page.revision > 0 ? <>
          <p role="status" className="mt-4 text-sm leading-6 text-brand-dark/75">{page.known_count} skills indexed.
            {page.complete ? "" : ` ${page.issue_count} discovery gaps; some metadata could not be indexed.`} No permissions granted.</p>
          <label className="mt-4 block max-w-xl text-sm font-semibold text-brand-dark">Find a local skill
            <input type="search" value={input} onChange={(event) => setInput(event.target.value)}
              className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-3 font-normal" />
          </label>
          <ul className="mt-4 divide-y divide-slate-200">{page.skills.map((skill) => <li key={skill.skill_id} className="py-4">
            <h3 className="text-sm font-semibold text-brand-dark">{skill.name}</h3>
            <p className="mt-1 max-w-2xl text-sm leading-6 text-brand-dark/75">{skill.description}</p>
            {skill.duplicate_name ? <p className="mt-2 text-xs font-semibold text-brand-dark/75">
              Same name found in another origin. Each copy keeps its own identity and review.</p> : null}
            <details className="mt-2 text-xs leading-5 text-brand-dark/75">
              <summary className="min-h-11 cursor-pointer py-3 font-semibold">Origin and requirements</summary>
              <p className="break-all">{skill.uri}</p>
              {skill.compatibility ? <p className="mt-2">Declared compatibility: {skill.compatibility}</p> : null}
              {skill.requested_tools ? <p className="mt-2 break-words">Requested tools: {skill.requested_tools}</p> : null}
              <p className="mt-2">Requirements are incomplete. Loading this skill cannot allow its tools.</p>
            </details>
            <p className="mt-2 max-w-2xl text-xs leading-5 text-brand-dark/75">
              Prepare inspects files in this skill directory to identify its revision and check declared dependencies.
              It does not run scripts or activate the skill.
            </p>
            <button type="button" disabled={busy || preparing !== null} onClick={() => void prepareWorkflow(skill.skill_id)}
              className="mt-2 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50">
              {preparing === skill.skill_id ? "Preparing workflow…" : `Prepare ${skill.name}`}
            </button>
            {preparing === skill.skill_id ? <button type="button" onClick={() => scan.current?.abort()}
              className="ml-3 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark">Cancel preparation</button> : null}
            {preflights[skill.skill_id] ? <SkillPreflightPreview plan={preflights[skill.skill_id]!} /> : null}
          </li>)}</ul>
          {page.matched_count === 0 ? <p className="mt-3 text-sm text-brand-dark/75">No skills match this search.</p> : null}
          {page.matched_count > 50 ? <nav aria-label="Local skill pages" className="mt-4 flex flex-wrap items-center gap-3">
            <button type="button" disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - 50))}
              className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50">Previous</button>
            <span className="text-sm text-brand-dark/75">Page {offset / 50 + 1}</span>
            <button type="button" disabled={page.next_offset === null || loading} onClick={() => {
              if (page.next_offset !== null) setOffset(page.next_offset);
            }} className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50">Next</button>
          </nav> : null}
        </> : null}
      </section> : null}
    </details>
  );
}

function SkillPreflightPreview({ plan }: { plan: SkillWorkflowPreflight }) {
  const [expired, setExpired] = useState(false);
  useEffect(() => {
    const remaining = plan.expires_at - performance.now();
    setExpired(remaining <= 0);
    const timer = window.setTimeout(() => setExpired(true), Math.max(0, remaining));
    return () => window.clearTimeout(timer);
  }, [plan.expires_at]);
  if (expired) return <p role="status" className="mt-4 text-xs leading-5 text-brand-dark/75">
    This workflow preview expired. Prepare it again to check current evidence.
  </p>;
  const stateLabel = { "saved-allow": "Saved Allow · runtime checks required", deny: "Denied", ask: "Needs review", unresolved: "Not resolved" };
  const dependencyLabel = {
    declared: "Guard dependency manifest (nonstandard extension)",
    invalid: "Invalid Guard dependency manifest; review the skill's metadata.",
    absent: "No Guard dependency manifest. Requirements remain unresolved.",
  }[plan.dependency_status];
  return <section aria-label="Workflow preflight" className="mt-4 border-l-2 border-brand-blue pl-4 text-xs leading-5 text-brand-dark/75">
    <p className="font-semibold">{plan.inspection.status === "complete" ? "Skill revision inspected" : "Skill revision could not be fully inspected"}</p>
    <p className="mt-2">Dependencies: {dependencyLabel}</p>
    <p className="mt-2">Permissions checked at revision {plan.authority_revision}. Native publication: {plan.native_state}.</p>
    <ul className="mt-3 divide-y divide-slate-200">{plan.requirements.map((requirement) => (
      <li key={`${requirement.connection_id}:${requirement.tool_name}`} className="py-3">
        <p className="break-all font-mono">{requirement.tool_name}</p><p className="mt-1 font-semibold">{stateLabel[requirement.state]}</p>
        <a href={guardAwareHref(localCliHref(requirement.connection_id))} className="mt-2 inline-flex min-h-11 items-center font-semibold text-brand-blue">
          Review connection permissions
        </a>
      </li>
    ))}</ul>
    <p className="mt-2">This is a preview of current evidence. Preparing grants nothing; every runtime call still checks its permissions.</p>
  </section>;
}
