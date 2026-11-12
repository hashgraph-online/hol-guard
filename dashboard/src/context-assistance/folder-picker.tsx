import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import {
  HiMiniArrowUturnLeft, HiMiniChevronRight, HiMiniCircleStack, HiMiniCodeBracketSquare, HiMiniComputerDesktop,
  HiMiniDocumentText, HiMiniFolder, HiMiniHome, HiMiniMagnifyingGlass, HiMiniPencilSquare, HiMiniXMark,
} from "react-icons/hi2";
import { useFocusTrap } from "../use-focus-trap";
import { folderCrumbs, listFolders, type FolderListing, type FolderPlace } from "./folders-api";
import { versionButton, versionPrimary } from "./versions-view";

type Props = { open: boolean; initialPath: string | null; onCancel: () => void; onChoose: (path: string) => void };
type Direction = "in" | "out" | "jump";

const PLACE_ICONS: Record<string, typeof HiMiniFolder> = { Home: HiMiniHome, Desktop: HiMiniComputerDesktop, Documents: HiMiniDocumentText };
const placeIcon = (place: FolderPlace) => PLACE_ICONS[place.label] ?? HiMiniFolder;
const rowClass = "group flex min-h-11 w-full items-center gap-3 rounded-xl px-3 text-left text-sm text-brand-dark transition-colors duration-150 hover:bg-brand-blue/[0.06] focus-visible:bg-brand-blue/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 motion-reduce:transition-none";
const placeClass = "flex min-h-10 w-auto shrink-0 items-center gap-2.5 rounded-lg px-2.5 text-left text-sm text-brand-dark/75 transition-colors hover:bg-brand-dark/[0.05] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 data-[current=true]:bg-brand-blue/10 data-[current=true]:font-semibold data-[current=true]:text-brand-blue sm:w-full";

/** Why the current folder cannot be chosen, or null when it can. */
export function folderChoiceBlock(listing: FolderListing): string | null {
  if (listing.parent === null) return "This is the top of the drive. Open the project folder you want inside it.";
  if (listing.path === listing.home) return "This is your whole home folder. Open the one project you want CIGAR to read.";
  return null;
}

export function FolderPickerDialog({ open, initialPath, onCancel, onChoose }: Props) {
  const id = useId();
  const dialog = useRef<HTMLDivElement>(null);
  const filterRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const request = useRef<AbortController | null>(null);
  const [listing, setListing] = useState<FolderListing | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [hidden, setHidden] = useState(false);
  const [typing, setTyping] = useState(false);
  const [typed, setTyped] = useState("");
  const [direction, setDirection] = useState<Direction>("jump");
  useFocusTrap(open, dialog);

  const go = useCallback((path: string | null, nextDirection: Direction, showHidden = hidden) => {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setLoading(true); setError(null);
    void listFolders(path, showHidden, controller.signal).then((value) => {
      if (controller.signal.aborted) return;
      setListing(value); setFilter(""); setTyping(false); setDirection(nextDirection);
      requestAnimationFrame(() => filterRef.current?.focus());
    }).catch((cause) => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Guard could not open that folder.");
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
  }, [hidden]);

  useEffect(() => {
    if (!open) return;
    // A reopened picker never offers rows from the last visit.
    setListing(null);
    go(initialPath, "jump");
    return () => request.current?.abort();
    // Re-open from the latest choice only when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const close = (event: globalThis.KeyboardEvent) => { if (event.key === "Escape" && !event.defaultPrevented) onCancel(); };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [open, onCancel]);

  if (!open) return null;
  const query = filter.trim().toLowerCase();
  const entries = (listing?.entries ?? []).filter((entry) => !query || entry.name.toLowerCase().includes(query));
  const block = listing ? folderChoiceBlock(listing) : null;
  const crumbs = listing ? folderCrumbs(listing.path, listing.separator) : [];
  const places = listing ? [...listing.places, ...listing.roots] : [];
  const up = () => { if (listing?.parent) go(listing.parent, "out"); };
  const choose = () => { if (listing && !block) onChoose(listing.path); };

  function focusRow(offset: number, from?: HTMLElement | null) {
    const rows = Array.from(listRef.current?.querySelectorAll<HTMLButtonElement>("[data-row]") ?? []);
    if (!rows.length) return;
    const at = from ? rows.indexOf(from as HTMLButtonElement) : -1;
    rows[Math.min(rows.length - 1, Math.max(0, at + offset))]?.focus();
  }
  function onFilterKey(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown") { event.preventDefault(); focusRow(1); }
    else if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) { event.preventDefault(); choose(); }
    else if (event.key === "Enter" && entries.length === 1) { event.preventDefault(); go(entries[0].path, "in"); }
    else if (event.key === "Backspace" && !filter) { event.preventDefault(); up(); }
  }
  function onRowKey(event: KeyboardEvent<HTMLUListElement>) {
    const target = event.target as HTMLElement;
    if (event.key === "ArrowDown") { event.preventDefault(); focusRow(1, target.closest("[data-row]")); }
    else if (event.key === "ArrowUp") {
      event.preventDefault();
      const rows = listRef.current?.querySelectorAll("[data-row]");
      if (rows && rows[0] === target.closest("[data-row]")) filterRef.current?.focus();
      else focusRow(-1, target.closest("[data-row]"));
    } else if (event.key === "Backspace" || (event.key === "ArrowLeft" && event.altKey)) { event.preventDefault(); up(); }
  }

  return <div className="fixed inset-0 z-50 flex items-end justify-center bg-brand-dark/40 backdrop-blur-[2px] sm:items-center sm:p-6"
    onMouseDown={(event) => { if (event.target === event.currentTarget) onCancel(); }}>
    <div ref={dialog} role="dialog" aria-modal="true" aria-labelledby={`${id}-title`} aria-describedby={`${id}-lead`}
      className="cigar-picker flex h-[min(92dvh,40rem)] w-full max-w-3xl flex-col overflow-hidden rounded-t-3xl bg-white shadow-[0_24px_60px_-12px_rgb(15_23_42/0.35)] sm:rounded-3xl">
      <header className="flex items-start gap-3 border-b border-brand-dark/[0.07] px-5 pb-4 pt-5 sm:px-6">
        <div className="min-w-0 flex-1">
          <h2 id={`${id}-title`} className="text-lg font-semibold tracking-[-0.02em] text-brand-dark">Choose a project folder</h2>
          <p id={`${id}-lead`} className="mt-0.5 text-sm text-brand-dark/65">Open folders until you reach your project, then use it. CIGAR only reads what you pick next.</p>
        </div>
        <button type="button" className="flex size-10 shrink-0 items-center justify-center rounded-full text-brand-dark/60 hover:bg-brand-dark/[0.06] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40"
          onClick={onCancel} aria-label="Close"><HiMiniXMark aria-hidden="true" className="size-5" /></button>
      </header>

      <div className="flex min-h-0 flex-1 flex-col sm:flex-row">
        <nav aria-label="Places" className="flex shrink-0 gap-1 overflow-x-auto border-b border-brand-dark/[0.07] px-4 py-2 sm:w-48 sm:flex-col sm:overflow-y-auto sm:border-b-0 sm:border-r sm:bg-surface-1/60 sm:p-3">
          {places.map((item) => {
            const Icon = item.kind ? placeIcon(item) : HiMiniCircleStack;
            return <button key={item.path} type="button" className={placeClass} data-current={listing?.path === item.path}
              onClick={() => go(item.path, "jump")}><Icon aria-hidden="true" className="size-4 shrink-0 opacity-70" /><span className="truncate">{item.label}</span></button>;
          })}
        </nav>

        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          <div className="flex items-center gap-1.5 px-4 pt-3 sm:px-5">
            <button type="button" className="flex size-9 shrink-0 items-center justify-center rounded-lg text-brand-dark/70 hover:bg-brand-dark/[0.06] disabled:opacity-35 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40"
              disabled={!listing?.parent || loading} onClick={up} aria-label="Go up one folder"><HiMiniArrowUturnLeft aria-hidden="true" className="size-4" /></button>
            {typing ? <form className="flex min-w-0 flex-1" onSubmit={(event) => { event.preventDefault(); if (typed.trim()) go(typed.trim(), "jump"); }}>
              <label htmlFor={`${id}-path`} className="sr-only">Folder path</label>
              <input id={`${id}-path`} autoFocus value={typed} onChange={(event) => setTyped(event.target.value)} spellCheck={false} autoComplete="off"
                onKeyDown={(event) => { if (event.key === "Escape") { event.preventDefault(); setTyping(false); } }}
                className="min-h-9 w-full rounded-lg border border-brand-blue/40 bg-white px-3 font-mono text-sm text-brand-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/25" />
            </form> : <ol aria-label="Current folder" className="flex min-w-0 flex-1 items-center overflow-x-auto text-sm [scrollbar-width:none]">
              {crumbs.map((crumb, index) => <li key={crumb.path} className="flex shrink-0 items-center">
                {index > 0 ? <HiMiniChevronRight aria-hidden="true" className="size-3.5 text-brand-dark/30" /> : null}
                <button type="button" onClick={() => go(crumb.path, "out")} aria-current={index === crumbs.length - 1 ? "location" : undefined}
                  className="max-w-[12rem] truncate rounded-md px-1.5 py-1 text-brand-dark/65 hover:bg-brand-dark/[0.05] hover:text-brand-dark aria-[current=location]:font-semibold aria-[current=location]:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40">{crumb.label}</button>
              </li>)}
            </ol>}
            <button type="button" className="flex size-9 shrink-0 items-center justify-center rounded-lg text-brand-dark/60 hover:bg-brand-dark/[0.06] aria-pressed:bg-brand-blue/10 aria-pressed:text-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40"
              aria-pressed={typing} aria-label="Type a path" onClick={() => { setTyped(listing?.path ?? ""); setTyping((value) => !value); }}>
              <HiMiniPencilSquare aria-hidden="true" className="size-4" /></button>
          </div>

          <div className="flex items-center gap-3 px-4 pb-2 pt-2.5 sm:px-5">
            <label className="relative min-w-0 flex-1">
              <span className="sr-only">Filter folders</span>
              <HiMiniMagnifyingGlass aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/40" />
              <input ref={filterRef} value={filter} onChange={(event) => setFilter(event.target.value)} onKeyDown={onFilterKey}
                placeholder={listing ? `Search in ${listing.name}` : "Search"} autoComplete="off" spellCheck={false}
                className="min-h-10 w-full rounded-xl border border-brand-dark/10 bg-surface-1/70 pl-9 pr-3 text-sm text-brand-dark placeholder:text-brand-dark/45 focus:border-brand-blue focus:bg-white focus:outline-none focus:ring-2 focus:ring-brand-blue/20" />
            </label>
            <label className="flex shrink-0 cursor-pointer items-center gap-2 text-xs text-brand-dark/65">
              <input type="checkbox" className="size-4 accent-brand-blue" checked={hidden}
                onChange={(event) => { setHidden(event.target.checked); go(listing?.path ?? null, "jump", event.target.checked); }} />Hidden folders
            </label>
          </div>

          <div className="relative min-h-0 flex-1 overflow-y-auto px-2 pb-2 sm:px-3" aria-busy={loading}>
            {error ? <div role="alert" className="mx-2 mt-2 rounded-xl bg-red-50 px-4 py-3 text-sm text-red-800">
              <p className="font-medium">{error}</p>
              <button type="button" className="mt-1.5 text-sm font-semibold text-red-900 underline underline-offset-2" onClick={() => go(null, "jump")}>Go to your home folder</button>
            </div> : null}
            {!listing && loading ? <ul aria-hidden="true" className="space-y-1 p-1">{Array.from({ length: 7 }, (_, index) =>
              <li key={index} className="flex h-11 items-center gap-3 px-3"><span className="size-5 rounded-md bg-brand-dark/[0.07] motion-safe:animate-pulse" />
                <span className="h-3 rounded bg-brand-dark/[0.07] motion-safe:animate-pulse" style={{ width: `${30 + ((index * 17) % 45)}%` }} /></li>)}</ul> : null}
            {listing ? <ul key={listing.path} ref={listRef} onKeyDown={onRowKey} data-direction={direction}
              aria-label={`Folders in ${listing.name}`} className="cigar-picker-list space-y-0.5 p-1">
              {entries.map((entry) => <li key={entry.path} className="flex items-center gap-1">
                <button type="button" data-row="" className={rowClass} onClick={() => go(entry.path, "in")} aria-label={`Open ${entry.name}${entry.project ? ", project" : ""}`}>
                  {entry.project ? <HiMiniCodeBracketSquare aria-hidden="true" className="size-5 shrink-0 text-brand-blue" />
                    : <HiMiniFolder aria-hidden="true" className="size-5 shrink-0 text-brand-dark/35" />}
                  <span className="min-w-0 flex-1 truncate">{entry.name}</span>
                  {entry.project ? <span className="rounded-full bg-brand-blue/10 px-2 py-0.5 text-xs font-semibold text-brand-blue">Project</span> : null}
                  <HiMiniChevronRight aria-hidden="true" className="size-4 shrink-0 text-brand-dark/25 transition-transform group-hover:translate-x-0.5 motion-reduce:transition-none" />
                </button>
                {entry.project ? <button type="button" disabled={loading} className="min-h-9 shrink-0 rounded-lg px-3 text-xs font-semibold text-brand-blue hover:bg-brand-blue/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:opacity-50"
                  onClick={() => onChoose(entry.path)} aria-label={`Use ${entry.name}`}>Use</button> : null}
              </li>)}
              {!entries.length && !loading ? <li className="px-3 py-10 text-center text-sm text-brand-dark/55">
                {query ? `No folder here matches “${filter.trim()}”.` : "No folders inside this one."}</li> : null}
              {listing.truncated ? <li className="px-3 py-2 text-xs text-brand-dark/55">Showing the first 400 folders. Search or type a path to find others.</li> : null}
            </ul> : null}
          </div>
        </div>
      </div>

      <footer className="flex flex-col gap-3 border-t border-brand-dark/[0.07] bg-surface-1/50 px-5 py-4 sm:flex-row sm:items-center sm:px-6">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <span aria-hidden="true" className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
            {listing?.project ? <HiMiniCodeBracketSquare className="size-5" /> : <HiMiniFolder className="size-5" />}</span>
          <div className="min-w-0" role="status">
            <p className="truncate text-sm font-semibold text-brand-dark">{listing?.name ?? "Loading…"}{listing?.project ? <span className="ml-2 text-xs font-medium text-brand-blue">Looks like a project</span> : null}</p>
            <p className="truncate text-xs text-brand-dark/55">{block ?? listing?.path ?? ""}</p>
          </div>
        </div>
        <div className="flex gap-2 sm:shrink-0">
          <button type="button" className={versionButton + " flex-1 sm:flex-none"} onClick={onCancel}>Cancel</button>
          <button type="button" className={versionPrimary + " flex-1 sm:flex-none"} disabled={!listing || !!block || loading} onClick={choose}>Use this folder</button>
        </div>
      </footer>
    </div>
  </div>;
}
