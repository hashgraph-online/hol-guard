import type { ContextBrief, ContextWorkspaceScope } from "./workspaces-api";

export function ContextBriefView({ brief, scope }: { brief: ContextBrief; scope: ContextWorkspaceScope }) {
  return <div className="space-y-3">
    <div className="max-h-96 space-y-3 overflow-auto text-sm text-slate-700">
      {brief.excerpts.map((excerpt, index) => <p key={index} className="whitespace-pre-wrap break-words">{excerpt.text}</p>)}
    </div>
    <details><summary className="min-h-11 cursor-pointer text-sm font-semibold">Sources and revisions</summary>
      <ul className="mt-2 space-y-2 text-sm">{brief.citations.map((citation, index) => <li key={`${citation.node_id}-${index}`}>
        {scope.sources.find((source) => source.source_id === citation.source)?.path ??
          (citation.source === "guard:notes" ? "Reviewed shared notes" : citation.source === "guard:action" ? "Authenticated native decision facts" : citation.source === "guard:receipts" ? "Native Guard receipt facts" : "Native Guard policy facts")}, lines {citation.start_line}–{citation.end_line}
        <span className="block break-all text-xs text-slate-500">{citation.document_digest}</span>
      </li>)}</ul>
    </details>
  </div>;
}
