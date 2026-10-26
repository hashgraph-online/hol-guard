import { useCallback, useId, useState } from "react";
import { HiMiniCheck, HiMiniChevronDown, HiMiniPlus } from "react-icons/hi2";

import {
  enrollablePackageScriptCommands,
  looksLikeProjectRelocatePaste,
  packageScriptFilterNeedle,
  type LocalCliCommand,
  type LocalCliItem,
} from "../local-cli-api";
import { commandMatchesQuery } from "./custom-extension-command-view";

function scriptCount(item: LocalCliItem): number {
  return enrollablePackageScriptCommands(item.commands).length;
}

/** The script to open the browser on when the pasted command names one in this project. Uses the browser's own matcher, so an accepted query always shows a row. */
export function packageScriptQueryFrom(query: string, commands: readonly LocalCliCommand[]): string {
  const trimmed = query.trim();
  if (!trimmed || looksLikeProjectRelocatePaste(trimmed)) return "";
  const needle = packageScriptFilterNeedle(trimmed);
  return needle && commands.some((command) => commandMatchesQuery(command, needle)) ? needle : "";
}

/** The folder a project was found in, when it adds something the package name does not already say. */
export function projectFolderLabel(item: LocalCliItem): string | null {
  const folder = item.source_label?.trim();
  return folder && folder !== item.name ? folder : null;
}

export function projectMetaLine(item: LocalCliItem): string {
  const count = scriptCount(item);
  const folder = projectFolderLabel(item);
  return [folder, `${count} ${count === 1 ? "script" : "scripts"}`].filter(Boolean).join(" · ");
}

/**
 * The project whose scripts are being set, with an in-place switcher. Projects
 * are named by package and folder together, so two folders called `dashboard`
 * in different repositories stay distinguishable.
 */
export function SelectedProject(props: {
  item: LocalCliItem;
  projects: readonly LocalCliItem[];
  disabled: boolean;
  onSelect: (item: LocalCliItem) => void;
  onFindAnother: () => void;
}) {
  const listId = useId();
  const [open, setOpen] = useState(false);
  const others = props.projects.filter((project) => project.cli_id !== props.item.cli_id);
  const toggle = useCallback(() => setOpen((current) => !current), []);
  const choose = useCallback((project: LocalCliItem) => {
    setOpen(false);
    props.onSelect(project);
  }, [props]);
  return (
    <section aria-labelledby="custom-extension-selected" className="mt-6 max-w-4xl border-b border-slate-200 pb-5">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h2 id="custom-extension-selected" className="break-words text-xl font-semibold tracking-tight text-brand-dark">
            {props.item.name}
          </h2>
          <p className="mt-1.5 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm text-brand-dark/70">
            <code className="rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-xs font-semibold text-brand-dark">
              {props.item.example_label}
            </code>
            <span className="min-w-0 break-words">{projectMetaLine(props.item)}</span>
          </p>
        </div>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={listId}
          disabled={props.disabled}
          onClick={toggle}
          className="inline-flex min-h-11 items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark hover:border-brand-blue/60 disabled:opacity-60"
        >
          Change project
          <HiMiniChevronDown className={`size-4 transition-transform duration-150 motion-reduce:transition-none ${open ? "rotate-180" : ""}`} aria-hidden="true" />
        </button>
      </div>
      <div id={listId} hidden={!open}>
        {open ? (
          <ul className="mt-4 divide-y divide-slate-200 overflow-hidden rounded-2xl border border-slate-200 bg-white" aria-label="Projects on this device">
            <li>
              <ProjectOption project={props.item} current onChoose={toggle} />
            </li>
            {others.map((project) => (
              <li key={project.cli_id}>
                <ProjectOption project={project} current={false} onChoose={choose} />
              </li>
            ))}
            <li>
              <button
                type="button"
                onClick={props.onFindAnother}
                className="flex min-h-12 w-full items-center gap-2 px-4 text-left text-sm font-semibold text-brand-blue hover:bg-brand-blue/5"
              >
                <HiMiniPlus className="size-4" aria-hidden="true" />
                Use another folder or command
              </button>
            </li>
          </ul>
        ) : null}
      </div>
    </section>
  );
}

function ProjectOption(props: {
  project: LocalCliItem;
  current: boolean;
  onChoose: (project: LocalCliItem) => void;
}) {
  const handleChoose = useCallback(() => props.onChoose(props.project), [props]);
  return (
    <button
      type="button"
      onClick={handleChoose}
      aria-current={props.current ? "true" : undefined}
      className="flex min-h-14 w-full items-center justify-between gap-3 px-4 py-2.5 text-left hover:bg-brand-blue/5 aria-[current]:bg-brand-blue/5"
    >
      <span className="min-w-0">
        <span className="block truncate text-sm font-semibold text-brand-dark">{props.project.name}</span>
        <span className="block truncate text-xs text-brand-dark/65">{projectMetaLine(props.project)}</span>
      </span>
      {props.current ? (
        <span className="inline-flex shrink-0 items-center gap-1 text-xs font-semibold text-brand-blue">
          <HiMiniCheck className="size-4" aria-hidden="true" />
          Selected
        </span>
      ) : null}
    </button>
  );
}
