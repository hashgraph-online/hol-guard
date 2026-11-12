import { useEffect, useRef } from "react";
import { commitDashboardLocation } from "../dashboard-location";
import { CigarAllowFilesButton, type CigarAllowFiles } from "./allow-files";
import { setSwarmContextTarget, usesPromptContext, type SwarmContextTarget } from "./swarm-handoff";
import type { ContextWorkspaceScope } from "./workspaces-api";
import { versionButton, versionHeading, versionLead, versionQuiet } from "./versions-view";

export function SwarmContextPanel({ target, ready, loaded, scope, filesAllowed, allowFiles }: {
  target: SwarmContextTarget; ready: boolean; loaded: boolean; scope?: ContextWorkspaceScope; filesAllowed: boolean; allowFiles?: CigarAllowFiles;
}) {
  const automatic = usesPromptContext(target.harness);
  const panel = useRef<HTMLElement>(null);
  let lead = "Choose the files below, then add the project. These choices also apply to other agents working in this folder.";
  if (!ready) lead = "Turn on or restart CIGAR above to continue. Your selected agent stays here.";
  else if (!filesAllowed) lead = "Allow project context so connected agents can receive the files you pick. Your approval is required before this setting changes.";
  else if (!loaded) lead = "Checking this project's context…";
  else if (scope) {
    const files = scope.sources.length === 1 ? "file" : "files";
    lead = `This project already has ${scope.sources.length} approved ${files}. Use “Show what your AI would get” below to preview its context.`;
  }
  useEffect(() => { panel.current?.focus({ preventScroll: true }); panel.current?.scrollIntoView({ block: "start" }); }, [target.id]);
  return <section ref={panel} tabIndex={-1} aria-label="Context for Swarm agent" className="space-y-3 rounded-2xl border border-brand-blue/25 bg-brand-blue/[0.04] p-5">
    <p className="text-xs font-semibold uppercase tracking-wider text-brand-blue">From Swarm</p>
    <h3 className={versionHeading}>Context for {target.label}</h3>
    <p className="break-all font-mono text-sm text-brand-dark/75">{target.workspace ?? "This agent did not report its project. Choose its folder below."}</p>
    <p className={versionLead}>{lead}</p>
    <p className="text-sm leading-6 text-brand-dark/70">{automatic
      ? "With Guard connected in App setup, new prompts in this app receive project context. A running turn keeps its existing context; send your next instruction after setup."
      : "This app needs a CIGAR MCP connection. After adding the project, open App setup and pair its request under “Connect another app” below. Finding its process does not connect it."}</p>
    <div className="flex flex-wrap gap-2">
      {ready && !filesAllowed && allowFiles ? <CigarAllowFilesButton allow={allowFiles} className={versionButton} /> : null}
      <button type="button" className={versionButton} onClick={() => {
        setSwarmContextTarget(null);
        commitDashboardLocation(`/swarm?agent=${encodeURIComponent(target.id)}&panel=context`);
      }}>Back to agent</button>
      <button type="button" className={versionQuiet} onClick={() => commitDashboardLocation(`/apps/${encodeURIComponent(target.harness)}`)}>App setup</button>
      <button type="button" className={versionQuiet} onClick={() => setSwarmContextTarget(null)}>Dismiss</button>
    </div>
  </section>;
}
