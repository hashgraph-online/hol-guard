import { useId, useState } from "react";
import { HiMiniClock, HiMiniCodeBracketSquare, HiMiniFolderPlus, HiMiniXMark } from "react-icons/hi2";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { commitDashboardLocation } from "../dashboard-location";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { FolderPickerDialog } from "./folder-picker";
import { MAX_PROJECT_FILES, ProjectFilesPicker } from "./project-files-picker";
import { forgetProject, readRecentProjects, rememberProject, type RecentProject } from "./recent-projects";
import { versionButton, versionHeading, versionLead, versionPrimary } from "./versions-view";

export type AddProjectInput = { workspace: string; files: string[]; app: string; notes?: { read: boolean; propose: boolean } };
type Props = {
  busy: boolean; dirty: boolean; documentsAllowed: boolean; agentsAllowed: boolean; sharingAllowed: boolean; executionAllowed: boolean;
  gate: GuardApprovalGatePublicConfig | null; error: string | null; first: boolean;
  /** Folders that already have access, so Recent only offers ones that need adding back. */
  active?: string[];
  onGrant: (input: AddProjectInput, credentials?: SettingsSaveProofCredentials) => Promise<boolean>;
};
type AppOption = { value: string; label: string; description: string };

const question = "text-sm font-semibold text-brand-dark";
const folderName = (path: string) => path.split(/[\\/]/).filter(Boolean).pop() ?? path;
const openSettings = () => {
  const url = new URL(window.location.href); url.searchParams.set("section", "runtime");
  commitDashboardLocation(url.pathname + url.search + url.hash);
};
const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;

/** Which apps may ask CIGAR for this project. Only the dashboard exists unless agent features are on. */
export function projectAppOptions(agentsAllowed: boolean, executionAllowed: boolean): AppOption[] {
  return [
    { value: "dashboard", label: "Only this page", description: "You look things up here, in Guard." },
    ...(agentsAllowed ? ["codex", "claude-code", "cursor"].map((name) => ({ value: name, label: harnessDisplayName(name), description: "This app can ask CIGAR about the project after you connect it." })) : []),
    ...(executionAllowed ? ["pi", "omp"].map((name) => ({ value: name, label: harnessDisplayName(name), description: "Commands it runs through Guard come back with project notes." })) : []),
  ];
}

export function proofDetail(input: AddProjectInput, executionAllowed: boolean, sharingAllowed: boolean): string {
  const who = input.app === "dashboard" ? "" : ` for ${harnessDisplayName(input.app)}`;
  const files = input.files.length ? plural(input.files.length, "file") : "no files";
  const notes = sharingAllowed && input.app !== "dashboard"
    ? ` Shared notes: ${input.notes?.read ? "allowed" : "off"}${input.notes?.propose ? ", and it may suggest new ones for you to review" : ""}.` : "";
  const execution = executionAllowed && (input.app === "pi" || input.app === "omp") ? " This does not approve any command." : "";
  return `CIGAR can read ${files} in ${folderName(input.workspace)}${who}, plus Guard's own safety facts for that folder. Nothing else in it is opened.${execution}${notes}`;
}

export function AddProjectPanel({ busy, dirty, documentsAllowed, agentsAllowed, sharingAllowed, executionAllowed, gate, error, first, active = [], onGrant }: Props) {
  const id = useId();
  const [workspace, setWorkspace] = useState<string | null>(null);
  const [files, setFiles] = useState<string[]>([]);
  const [app, setApp] = useState("dashboard");
  const [notesRead, setNotesRead] = useState(false);
  const [notesPropose, setNotesPropose] = useState(false);
  const [picking, setPicking] = useState(false);
  const [proofOpen, setProofOpen] = useState(false);
  const [recent, setRecent] = useState<RecentProject[]>(() => readRecentProjects());
  const [preset, setPreset] = useState<string[] | null>(null);
  const shortcuts = recent.filter((project) => !active.includes(project.workspace));
  const apps = projectAppOptions(agentsAllowed, executionAllowed);
  const chosenApp = apps.some((option) => option.value === app) ? app : "dashboard";
  const input: AddProjectInput | null = workspace ? {
    workspace, files: documentsAllowed ? files : [], app: chosenApp,
    notes: sharingAllowed && chosenApp !== "dashboard" ? { read: notesRead, propose: notesPropose } : undefined,
  } : null;

  async function grant(credentials?: SettingsSaveProofCredentials) {
    if (!input) return;
    if (await onGrant(input, credentials)) {
      setRecent(rememberProject(input)); setProofOpen(false); setWorkspace(null); setFiles([]); setPreset(null);
    }
  }

  function reuse(project: RecentProject) {
    setPreset(project.files); setFiles(project.files); setApp(project.app); setWorkspace(project.workspace);
  }

  return <section className="space-y-5 rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-6" aria-labelledby={`${id}-add`}>
    <div><h3 id={`${id}-add`} className={versionHeading}>{first && !shortcuts.length ? "Add your first project" : "Add a project"}</h3>
      <p className={versionLead}>Choose a folder and the notes CIGAR may read. Secret files, like passwords and keys, are always skipped.</p></div>

    <fieldset disabled={busy || dirty} className="space-y-6">
      <legend className="sr-only">Add a project</legend>
      {workspace ? <div className="flex flex-wrap items-center gap-3 rounded-xl bg-surface-1/70 p-3 pr-4">
        <span aria-hidden="true" className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue"><HiMiniCodeBracketSquare className="size-5" /></span>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-brand-dark">{folderName(workspace)}</p>
          <p className="truncate font-mono text-xs text-brand-dark/55" title={workspace}>{workspace}</p>
        </div>
        <button type="button" className={versionButton} onClick={() => setPicking(true)}>Change folder</button>
      </div> : <button type="button" onClick={() => setPicking(true)}
        className="group flex w-full items-center gap-4 rounded-2xl border border-dashed border-brand-blue/35 bg-brand-blue/[0.025] p-5 text-left transition-colors duration-200 hover:border-brand-blue/60 hover:bg-brand-blue/[0.05] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60 motion-reduce:transition-none">
        <span aria-hidden="true" className="flex size-12 shrink-0 items-center justify-center rounded-2xl bg-brand-blue text-white shadow-sm shadow-brand-blue/30 transition-transform duration-300 ease-out group-hover:scale-105 motion-reduce:transition-none"><HiMiniFolderPlus className="size-6" /></span>
        <span className="min-w-0"><span className="block text-base font-semibold text-brand-dark">Choose a project folder</span>
          <span className="mt-0.5 block text-sm text-brand-dark/65">Browse to the folder you work in. Nothing is read until you say so.</span></span>
      </button>}

      {!workspace && shortcuts.length ? <RecentProjects projects={shortcuts} onReuse={reuse} onForget={(path) => setRecent(forgetProject(path))} /> : null}

      {workspace ? <div className="guard-surface-in space-y-2.5">
        <h4 className={question}>What should CIGAR read?</h4>
        {documentsAllowed ? <ProjectFilesPicker workspace={workspace} selected={files} onChange={setFiles} disabled={busy || dirty} preset={preset} />
          : <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl bg-surface-1/70 px-4 py-3">
            <p className="min-w-0 flex-1 text-sm leading-6 text-brand-dark/70">Reading project files is off, so CIGAR uses only Guard's own safety facts here. Turn on “Allow selected workspace documents” in Settings to pick notes.</p>
            <button type="button" className={versionButton} onClick={openSettings}>Open Settings</button>
          </div>}
      </div> : null}

      {workspace && apps.length > 1 ? <fieldset className="guard-surface-in space-y-2.5">
        <legend className={question}>Which app can use it?</legend>
        <div className="grid gap-2 sm:grid-cols-2">{apps.map((option) => <label key={option.value}
          className="flex cursor-pointer gap-3 rounded-xl border border-brand-dark/10 p-3 transition-colors hover:border-brand-dark/25 has-[:checked]:border-brand-blue/50 has-[:checked]:bg-brand-blue/[0.04] has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-brand-blue/40">
          <input type="radio" name={`${id}-app`} value={option.value} className="mt-0.5 size-4 shrink-0 accent-brand-blue" checked={chosenApp === option.value} onChange={() => setApp(option.value)} />
          <span className="min-w-0"><span className="block text-sm font-semibold text-brand-dark">{option.label}</span>
            <span className="mt-0.5 block text-xs leading-5 text-brand-dark/60">{option.description}</span></span>
        </label>)}</div>
        {sharingAllowed && chosenApp !== "dashboard" ? <div className="space-y-0.5 rounded-xl bg-surface-1/70 px-3 py-1.5 text-sm text-brand-dark/80">
          <label className="flex min-h-11 cursor-pointer items-center gap-3"><input type="checkbox" className="size-4 accent-brand-blue" checked={notesRead}
            onChange={(event) => { setNotesRead(event.target.checked); if (!event.target.checked) setNotesPropose(false); }} />Let it read shared notes you approved</label>
          <label className="flex min-h-11 cursor-pointer items-center gap-3"><input type="checkbox" className="size-4 accent-brand-blue" checked={notesPropose} disabled={!notesRead}
            onChange={(event) => setNotesPropose(event.target.checked)} />Let it suggest new notes for you to review</label>
        </div> : null}
      </fieldset> : null}

      {dirty ? <p role="status" className="cigar-note">Save your preferences first, then add the project.</p> : null}
      {workspace ? <div className="flex flex-wrap items-center gap-3 border-t border-brand-dark/[0.07] pt-4">
        <button className={versionPrimary} type="button" disabled={files.length > MAX_PROJECT_FILES}
          onClick={() => { if (gate?.enabled) setProofOpen(true); else void grant(); }}>Give CIGAR access</button>
        <p className="text-xs leading-5 text-brand-dark/60">{documentsAllowed && files.length ? `CIGAR will read ${plural(files.length, "file")} from ${folderName(workspace)}.` : `CIGAR will use Guard's safety facts for ${folderName(workspace)}.`}</p>
      </div> : null}
    </fieldset>

    <FolderPickerDialog open={picking} initialPath={workspace} onCancel={() => setPicking(false)}
      onChoose={(path) => { setPicking(false); if (path !== workspace) { setPreset(null); setFiles([]); setWorkspace(path); } }} />
    <SettingsSaveProofModal open={proofOpen && !!input} mode="verify-save" gate={gate} title="Confirm CIGAR access"
      detail={input ? proofDetail(input, executionAllowed, sharingAllowed) : ""} confirmLabel="Give access"
      error={error} pending={busy} onCancel={() => { if (!busy) setProofOpen(false); }} onConfirm={(credentials) => void grant(credentials)} />
  </section>;
}

/** Projects this browser added before, offered back after Guard restarts. */
export function RecentProjects({ projects, onReuse, onForget }: { projects: RecentProject[]; onReuse: (project: RecentProject) => void; onForget: (workspace: string) => void }) {
  return <div className="guard-surface-in space-y-2.5">
    <h4 className={question}>Recent projects</h4>
    <ul className="grid gap-2 sm:grid-cols-2">{projects.map((project) => {
      const name = folderName(project.workspace);
      const who = project.app === "dashboard" ? "this page" : harnessDisplayName(project.app);
      return <li key={project.workspace} className="flex items-center rounded-xl border border-brand-dark/10 bg-white transition-colors hover:border-brand-dark/25 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-brand-blue/40">
        <button type="button" className="flex min-h-12 min-w-0 flex-1 items-center gap-3 rounded-l-xl p-2.5 text-left focus-visible:outline-none" title={project.workspace} onClick={() => onReuse(project)}>
          <span aria-hidden="true" className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-brand-dark/[0.05] text-brand-dark/55"><HiMiniClock className="size-4" /></span>
          <span className="min-w-0"><span className="block truncate text-sm font-semibold text-brand-dark">{name}</span>
            <span className="block truncate text-xs text-brand-dark/60">{plural(project.files.length, "file")} · for {who}</span></span>
        </button>
        <button type="button" aria-label={`Remove ${name} from this list`} className="mr-1.5 flex size-9 shrink-0 items-center justify-center rounded-lg text-brand-dark/40 hover:bg-brand-dark/[0.05] hover:text-brand-dark focus-visible:outline-none" onClick={() => onForget(project.workspace)}>
          <HiMiniXMark className="size-4" /></button>
      </li>;
    })}</ul>
  </div>;
}
