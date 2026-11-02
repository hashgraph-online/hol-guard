import { useEffect, useId, useRef, useState } from "react";
import { HiMiniCheck, HiMiniChevronRight, HiMiniDocumentText, HiMiniFolder } from "react-icons/hi2";
import { formatFileSize, listProjectFiles, type ProjectFile, type ProjectFileListing } from "./folders-api";
import { keptFiles } from "./recent-projects";

export const MAX_PROJECT_FILES = 32;
type Props = { workspace: string; selected: string[]; onChange: (paths: string[]) => void; disabled?: boolean; preset?: string[] | null };

const REASONS: Record<string, string> = { too_large: "Too big", not_text: "Not text", empty: "Empty" };
const chip = "inline-flex min-h-10 cursor-pointer items-center gap-2 rounded-full border px-3.5 text-sm transition-colors duration-150 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-brand-blue/40 has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-50 motion-reduce:transition-none";
const chipOn = " border-brand-blue/30 bg-brand-blue/[0.07] text-brand-dark";
const chipOff = " border-brand-dark/12 bg-white text-brand-dark/70 hover:border-brand-dark/25";
const row = "flex min-h-11 w-full items-center gap-3 rounded-lg px-3 text-left text-sm";

/** Lets someone tick the few files that explain their project, without typing paths. */
export function ProjectFilesPicker({ workspace, selected, onChange, disabled = false, preset = null }: Props) {
  const id = useId();
  const [root, setRoot] = useState<ProjectFileListing | null>(null);
  const [browsing, setBrowsing] = useState(false);
  const [listing, setListing] = useState<ProjectFileListing | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const latest = useRef(onChange);
  latest.current = onChange;
  const remembered = useRef(preset);
  remembered.current = preset;

  function load(path: string, onLoaded: (value: ProjectFileListing) => void) {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setLoading(true); setError(null);
    void listProjectFiles(workspace, path, controller.signal).then((value) => {
      if (!controller.signal.aborted) onLoaded(value);
    }).catch((cause) => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Guard could not list this folder.");
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
  }

  useEffect(() => {
    setRoot(null); setListing(null); setBrowsing(false);
    load("", (value) => {
      setRoot(value); setListing(value);
      // A project added back from Recent keeps the files chosen last time.
      const chosen = remembered.current ? keptFiles(remembered.current, value) : value.suggested.map((item) => item.relative);
      latest.current(chosen.slice(0, MAX_PROJECT_FILES));
    });
    return () => request.current?.abort();
    // A new folder starts a fresh selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspace]);

  const full = selected.length >= MAX_PROJECT_FILES;
  const toggle = (relative: string, on: boolean) => onChange(on ? [...selected, relative] : selected.filter((item) => item !== relative));
  const suggested = root?.suggested.map((item) => item.relative) ?? [];
  const chips = [...suggested, ...selected.filter((item) => !suggested.includes(item))];
  const sizes = new Map(root?.suggested.map((item) => [item.relative, item.size]) ?? []);
  const crumbs = listing?.path ? listing.path.split("/") : [];
  const name = workspace.split(/[\\/]/).filter(Boolean).pop() ?? workspace;

  return <div className="space-y-3">
    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
      <p className="max-w-[62ch] text-sm leading-6 text-brand-dark/70">Pick a few notes that explain your project, like the README. CIGAR reads only what you tick. You can skip this.</p>
      <p className="text-xs font-medium tabular-nums text-brand-dark/55" aria-live="polite">{selected.length} picked · up to {MAX_PROJECT_FILES}</p>
    </div>

    {!root && loading ? <div aria-hidden="true" className="flex gap-2">{[7, 9, 6].map((width) =>
      <span key={width} className="h-10 rounded-full bg-brand-dark/[0.06] motion-safe:animate-pulse" style={{ width: `${width}rem` }} />)}</div> : null}

    {root ? <fieldset disabled={disabled}>
      <legend className="sr-only">Files CIGAR may read</legend>
      {chips.length ? <ul className="flex flex-wrap gap-2">{chips.map((relative) => {
        const on = selected.includes(relative);
        const size = sizes.get(relative);
        return <li key={relative}><label className={chip + (on ? chipOn : chipOff)}>
          <span className="relative flex size-4 shrink-0">
            <input type="checkbox" className="peer size-4 cursor-pointer appearance-none rounded-full border border-brand-dark/25 bg-white transition-colors checked:border-brand-blue checked:bg-brand-blue focus-visible:outline-none disabled:cursor-not-allowed"
              checked={on} disabled={!on && full} onChange={(event) => toggle(relative, event.target.checked)} />
            <HiMiniCheck aria-hidden="true" className="pointer-events-none absolute inset-0.5 size-3 text-white opacity-0 peer-checked:opacity-100" />
          </span>
          <span className="font-medium">{relative}</span>
          {size !== undefined ? <span className="text-xs text-brand-dark/45">{formatFileSize(size)}</span> : null}
        </label></li>;
      })}</ul> : <p className="text-sm text-brand-dark/60">No project notes at the top of {name}. Browse to pick files, or skip this.</p>}
    </fieldset> : null}

    {error ? <p role="alert" className="text-sm text-red-700">{error}</p> : null}

    {root ? <div>
      <button type="button" disabled={disabled} aria-expanded={browsing} aria-controls={`${id}-browser`}
        className="inline-flex min-h-10 items-center gap-1.5 rounded-lg text-sm font-semibold text-brand-blue hover:text-brand-blue/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:opacity-50"
        onClick={() => { if (!browsing && listing?.path) load("", setListing); setBrowsing((value) => !value); }}>
        <HiMiniChevronRight aria-hidden="true" className={"size-4 transition-transform duration-200 motion-reduce:transition-none " + (browsing ? "rotate-90" : "")} />
        {browsing ? "Hide files" : "Browse all files"}</button>

      {browsing && listing ? <div id={`${id}-browser`} className="cigar-files mt-2 overflow-hidden rounded-xl border border-brand-dark/10 bg-white" aria-busy={loading}>
        <ol aria-label="Folder inside the project" className="flex flex-wrap items-center gap-0.5 border-b border-brand-dark/[0.07] bg-surface-1/60 px-2 py-1.5 text-sm">
          <li><button type="button" className="rounded-md px-1.5 py-1 font-medium text-brand-dark/70 hover:bg-brand-dark/[0.05] hover:text-brand-dark" onClick={() => load("", setListing)}>{name}</button></li>
          {crumbs.map((part, index) => <li key={index} className="flex items-center">
            <HiMiniChevronRight aria-hidden="true" className="size-3.5 text-brand-dark/30" />
            <button type="button" className="rounded-md px-1.5 py-1 text-brand-dark/70 hover:bg-brand-dark/[0.05] hover:text-brand-dark aria-[current=location]:font-semibold aria-[current=location]:text-brand-dark"
              aria-current={index === crumbs.length - 1 ? "location" : undefined} onClick={() => load(crumbs.slice(0, index + 1).join("/"), setListing)}>{part}</button>
          </li>)}
        </ol>
        <ul key={listing.path} className="cigar-picker-list max-h-72 overflow-y-auto p-1.5" data-direction="in">
          {listing.entries.map((entry) => <li key={entry.relative}>
            <button type="button" disabled={disabled || loading} className={row + " text-brand-dark hover:bg-brand-dark/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40"}
              onClick={() => load(entry.relative, setListing)}>
              <HiMiniFolder aria-hidden="true" className="size-5 shrink-0 text-brand-dark/35" />
              <span className="min-w-0 flex-1 truncate">{entry.name}</span>
              <HiMiniChevronRight aria-hidden="true" className="size-4 text-brand-dark/25" />
            </button></li>)}
          {listing.files.map((file) => <FileRow key={file.relative} file={file} checked={selected.includes(file.relative)}
            disabled={disabled || (!selected.includes(file.relative) && full)} onToggle={toggle} />)}
          {!listing.entries.length && !listing.files.length ? <li className="px-3 py-6 text-center text-sm text-brand-dark/55">Nothing CIGAR can read in this folder.</li> : null}
          {listing.truncated ? <li className="px-3 py-2 text-xs text-brand-dark/55">Showing the first 400 items.</li> : null}
        </ul>
      </div> : null}
    </div> : null}
  </div>;
}

function FileRow({ file, checked, disabled, onToggle }: { file: ProjectFile; checked: boolean; disabled: boolean; onToggle: (relative: string, on: boolean) => void }) {
  if (!file.available) {
    return <li className={row + " text-brand-dark/40"}>
      <HiMiniDocumentText aria-hidden="true" className="size-5 shrink-0" />
      <span className="min-w-0 flex-1 truncate">{file.name}</span>
      <span className="text-xs">{REASONS[file.reason ?? ""] ?? "Unavailable"}</span>
    </li>;
  }
  return <li><label className={row + " cursor-pointer text-brand-dark hover:bg-brand-dark/[0.04] has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-brand-blue/40 has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-50"}>
    <input type="checkbox" className="size-4 shrink-0 accent-brand-blue" checked={checked} disabled={disabled} onChange={(event) => onToggle(file.relative, event.target.checked)} />
    <span className="min-w-0 flex-1 truncate">{file.name}</span>
    <span className="text-xs tabular-nums text-brand-dark/45">{formatFileSize(file.size)}</span>
  </label></li>;
}
