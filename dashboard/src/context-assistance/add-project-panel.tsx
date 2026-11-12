import { useId, useState } from "react";
import { HiMiniClock, HiMiniCodeBracketSquare, HiMiniFolderPlus, HiMiniXMark } from "react-icons/hi2";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { CigarAllowFilesButton, type CigarAllowFiles } from "./allow-files";
import { FolderPickerDialog } from "./folder-picker";
import { MAX_PROJECT_FILES, ProjectFilesPicker } from "./project-files-picker";
import { forgetProject, readRecentProjects, rememberProject, type RecentProject } from "./recent-projects";
import { versionButton, versionHeading, versionLead, versionPrimary } from "./versions-view";

/** A project picked here counts for every AI app, so there is no app to choose. */
export type AddProjectInput = { workspace: string; files: string[] };
type Props = {
  busy: boolean; dirty: boolean; documentsAllowed: boolean; executionAllowed: boolean;
  gate: GuardApprovalGatePublicConfig | null; error: string | null; first: boolean;
  /** Turns on reading project files in place when it is off. */
  allowFiles?: CigarAllowFiles;
  /** Folders that already have access, so Recent only offers ones that need adding back. */
  active?: string[];
  initialWorkspace?: string | null;
  onGrant: (input: AddProjectInput, credentials?: SettingsSaveProofCredentials) => Promise<boolean>;
};

const question = "text-sm font-semibold text-brand-dark";
const folderName = (path: string) => path.split(/[\\/]/).filter(Boolean).pop() ?? path;
const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;

export function proofDetail(input: AddProjectInput, executionAllowed: boolean): string {
  const files = input.files.length ? plural(input.files.length, "file") : "no files";
  const execution = executionAllowed ? " This does not approve any command." : "";
  return `CIGAR can read ${files} in ${folderName(input.workspace)}, plus Guard's own safety facts for that folder, for prompts in every AI app. Nothing else in it is opened.${execution}`;
}

function summary(workspace: string, files: number, documentsAllowed: boolean): string {
  if (documentsAllowed && files) return `Prompts about ${folderName(workspace)} will use these ${plural(files, "file")}, in every AI app.`;
  return `No files picked, so your AI apps keep finding matching files in ${folderName(workspace)} on their own.`;
}

export function AddProjectPanel({ busy, dirty, documentsAllowed, executionAllowed, gate, error, first, allowFiles, active = [], initialWorkspace = null, onGrant }: Props) {
  const id = useId();
  const [workspace, setWorkspace] = useState<string | null>(initialWorkspace);
  const [files, setFiles] = useState<string[]>([]);
  const [picking, setPicking] = useState(false);
  const [proofOpen, setProofOpen] = useState(false);
  const [recent, setRecent] = useState<RecentProject[]>(() => readRecentProjects());
  const [preset, setPreset] = useState<string[] | null>(null);
  const shortcuts = recent.filter((project) => !active.includes(project.workspace));
  const input: AddProjectInput | null = workspace ? { workspace, files: documentsAllowed ? files : [] } : null;

  async function grant(credentials?: SettingsSaveProofCredentials) {
    if (!input) return;
    if (await onGrant(input, credentials)) {
      setRecent(rememberProject({ ...input, app: "dashboard" })); setProofOpen(false); setWorkspace(null); setFiles([]); setPreset(null);
    }
  }

  function reuse(project: RecentProject) {
    setPreset(project.files); setFiles(project.files); setWorkspace(project.workspace);
  }

  return <section className="space-y-5 rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-6" aria-labelledby={`${id}-add`}>
    <div><h3 id={`${id}-add`} className={versionHeading}>{first && !shortcuts.length ? "Add your first project" : "Add a project"}</h3>
      <p className={versionLead}>Choose a folder and tick the files CIGAR should read. Secret files, like passwords and keys, are always skipped.</p></div>

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
        <h4 className={question}>Which files should CIGAR read?</h4>
        {documentsAllowed ? <ProjectFilesPicker workspace={workspace} selected={files} onChange={setFiles} disabled={busy || dirty} preset={preset} />
          : <div className="space-y-3 rounded-xl bg-surface-1/70 px-4 py-4">
            <p className="text-sm leading-6 text-brand-dark/75">Reading project files is off right now. Turn it on to pick files here and to give your AI apps matching files with each prompt.</p>
            {allowFiles ? <CigarAllowFilesButton allow={allowFiles} className={versionPrimary} /> : null}
          </div>}
      </div> : null}

      {dirty ? <p role="status" className="cigar-note">Save your preferences first, then add the project.</p> : null}
      {workspace ? <div className="flex flex-wrap items-center gap-3 border-t border-brand-dark/[0.07] pt-4">
        <button className={versionPrimary} type="button" disabled={files.length > MAX_PROJECT_FILES}
          onClick={() => { if (gate?.enabled) setProofOpen(true); else void grant(); }}>Add project</button>
        <p className="text-xs leading-5 text-brand-dark/60">{summary(workspace, input?.files.length ?? 0, documentsAllowed)}</p>
      </div> : null}
    </fieldset>

    <FolderPickerDialog open={picking} initialPath={workspace} onCancel={() => setPicking(false)}
      onChoose={(path) => { setPicking(false); if (path !== workspace) { setPreset(null); setFiles([]); setWorkspace(path); } }} />
    <SettingsSaveProofModal open={proofOpen && !!input} mode="verify-save" gate={gate} title="Add this project"
      detail={input ? proofDetail(input, executionAllowed) : ""} confirmLabel="Add project"
      error={error} pending={busy} onCancel={() => { if (!busy) setProofOpen(false); }} onConfirm={(credentials) => void grant(credentials)} />
  </section>;
}

/** Projects this browser added before, offered back after Guard restarts. */
export function RecentProjects({ projects, onReuse, onForget }: { projects: RecentProject[]; onReuse: (project: RecentProject) => void; onForget: (workspace: string) => void }) {
  return <div className="guard-surface-in space-y-2.5">
    <h4 className={question}>Recent projects</h4>
    <ul className="grid gap-2 sm:grid-cols-2">{projects.map((project) => {
      const name = folderName(project.workspace);
      return <li key={project.workspace} className="flex items-center rounded-xl border border-brand-dark/10 bg-white transition-colors hover:border-brand-dark/25 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-brand-blue/40">
        <button type="button" className="flex min-h-12 min-w-0 flex-1 items-center gap-3 rounded-l-xl p-2.5 text-left focus-visible:outline-none" title={project.workspace} onClick={() => onReuse(project)}>
          <span aria-hidden="true" className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-brand-dark/[0.05] text-brand-dark/55"><HiMiniClock className="size-4" /></span>
          <span className="min-w-0"><span className="block truncate text-sm font-semibold text-brand-dark">{name}</span>
            <span className="block truncate text-xs text-brand-dark/60">{project.files.length ? plural(project.files.length, "file") : "Guard's safety facts only"}</span></span>
        </button>
        <button type="button" aria-label={`Remove ${name} from this list`} className="mr-1.5 flex size-9 shrink-0 items-center justify-center rounded-lg text-brand-dark/40 hover:bg-brand-dark/[0.05] hover:text-brand-dark focus-visible:outline-none" onClick={() => onForget(project.workspace)}>
          <HiMiniXMark className="size-4" /></button>
      </li>;
    })}</ul>
  </div>;
}
