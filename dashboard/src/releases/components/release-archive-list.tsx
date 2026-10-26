import { useCallback, useRef } from "react";
import { HiMiniCheckCircle } from "react-icons/hi2";

import { ActionButton } from "../../approval-center-primitives";
import {
  channelLabel,
  formatReleaseDate,
  groupReleasesByTrain,
  hasNextPage,
  hasPreviousPage,
  normalizeVersionLabel,
  pageRangeLabel,
} from "../releases-model";
import type { ReleaseIndex, ReleaseSummary } from "../releases-types";

/** The node this release occupies on the rail's timeline. Installed is a
 * filled stop with a halo, the open release is a ring, everything else is a
 * tick — so the reader's own position and their place in the history are two
 * different marks rather than one shared highlight. */
function nodeClass(selected: boolean, installed: boolean): string {
  if (installed) return "size-2.5 bg-brand-blue ring-4 ring-brand-blue/15";
  if (selected) return "size-2.5 border-2 border-brand-blue bg-white";
  return "size-1.5 bg-brand-dark/25 group-hover:bg-brand-dark/45";
}

function ReleaseRow(props: {
  release: ReleaseSummary;
  selected: boolean;
  installed: boolean;
  tabbable: boolean;
  onSelect: (slug: string) => void;
  registerRef: (slug: string, node: HTMLButtonElement | null) => void;
}) {
  const { release } = props;
  return (
    <li>
      <button
        type="button"
        ref={(node) => props.registerRef(release.slug, node)}
        // Roving focus: one stop for the whole rail, then the arrow keys. A
        // page of twenty versions must not cost twenty tabs to walk past.
        tabIndex={props.tabbable ? 0 : -1}
        aria-current={props.selected ? "true" : undefined}
        onClick={() => props.onSelect(release.slug)}
        className={`group relative flex min-h-11 w-full items-center gap-2.5 rounded-lg py-2 pl-9 pr-2.5 text-left transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none ${
          props.selected ? "bg-brand-blue/[0.07]" : "hover:bg-brand-dark/[0.035]"
        }`}
      >
        <span
          aria-hidden="true"
          className="absolute left-4 top-1/2 flex size-4 -translate-x-1/2 -translate-y-1/2 items-center justify-center"
        >
          <span
            className={`rounded-full transition-all duration-200 motion-reduce:transition-none ${nodeClass(props.selected, props.installed)}`}
          />
        </span>
        <span className="min-w-0 flex-1">
          <span
            className={`block truncate font-mono text-[13px] tabular-nums ${
              props.selected ? "font-semibold text-brand-dark" : "text-brand-dark/85"
            }`}
          >
            {normalizeVersionLabel(release.versionLabel)}
          </span>
          <span className="mt-0.5 block text-xs text-brand-dark/75">
            {formatReleaseDate(release.publishedAt)}
            {release.channel === "preview" ? ` · ${channelLabel(release.channel)}` : ""}
          </span>
        </span>
        {props.installed ? (
          <span className="flex shrink-0 items-center gap-1 rounded-full bg-brand-blue/10 px-2 py-0.5 text-[11px] font-semibold text-brand-blue">
            <HiMiniCheckCircle className="size-3.5" aria-hidden="true" />
            Installed here
          </span>
        ) : release.isRecommended ? (
          // The one release the publisher says to move to. Worth a mark only
          // when the reader is not already on it.
          <span className="shrink-0 rounded-full bg-brand-green-bg px-2 py-0.5 text-[11px] font-semibold text-brand-green-text">
            Recommended
          </span>
        ) : null}
      </button>
    </li>
  );
}

/** Every published version, newest first, grouped by the train it belongs to
 * and strung along one timeline, with the one running on this device marked so
 * the reader can place themselves in the history. */
export function ReleaseArchiveList(props: {
  index: ReleaseIndex;
  selectedSlug: string | null;
  installedSlug: string | null;
  onSelect: (slug: string, options?: { scroll?: boolean }) => void;
  onPage: (page: number) => void;
}) {
  const groups = groupReleasesByTrain(props.index.releases);
  // With nothing open yet the rail still needs one tab stop, or the keyboard
  // cannot reach it at all.
  const tabbableSlug =
    props.selectedSlug !== null &&
    props.index.releases.some((release) => release.slug === props.selectedSlug)
      ? props.selectedSlug
      : (props.index.releases[0]?.slug ?? null);
  const rows = useRef(new Map<string, HTMLButtonElement>());
  const registerRef = useCallback((slug: string, node: HTMLButtonElement | null) => {
    if (node) rows.current.set(slug, node);
    else rows.current.delete(slug);
  }, []);

  const { index, selectedSlug, onSelect } = props;
  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLElement>) => {
      const order = index.releases;
      if (order.length === 0) return;
      // Movement starts at the row the reader is actually on. The selection
      // can move under them — the installed version arrives from Guard after
      // the archive does — and an arrow press has to continue from their
      // focus, not from wherever the screen just jumped.
      let origin = selectedSlug;
      for (const [slug, node] of rows.current) {
        if (node === event.target) {
          origin = slug;
          break;
        }
      }
      const current = order.findIndex((release) => release.slug === origin);
      let next = -1;
      if (event.key === "ArrowDown") next = Math.min(order.length - 1, current + 1);
      else if (event.key === "ArrowUp") next = Math.max(0, current <= 0 ? 0 : current - 1);
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = order.length - 1;
      else return;
      event.preventDefault();
      const slug = order[next].slug;
      // Walking the rail must not drag the page to the detail panel on every
      // keystroke; the reader is still reading the rail.
      if (slug !== selectedSlug) onSelect(slug, { scroll: false });
      rows.current.get(slug)?.focus();
    },
    [index.releases, selectedSlug, onSelect],
  );

  return (
    <nav aria-label="Published Guard releases" className="flex min-h-0 flex-1 flex-col">
      {/* The rail's arrow keys belong to the rail. On the <nav> they also
          caught Newer and Older below, so paging with the keyboard threw the
          reader back into the list and changed the release under them. */}
      <div className="min-h-0 flex-1 overflow-y-auto px-1.5 pb-2" onKeyDown={onKeyDown}>
        {groups.map((group, position) => (
          <section key={`${group.train}-${position}`} aria-label={`${group.train} series`}>
            <h3 className="sticky top-0 z-10 bg-white/90 px-1.5 py-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-brand-dark/75 backdrop-blur">
              {group.train}
            </h3>
            {/* One line down the rail, behind the rows: the history is
                continuous, and each release is a stop on it. */}
            <ul className="relative space-y-0.5 pb-2">
              <span
                aria-hidden="true"
                className="absolute inset-y-0 left-4 w-px -translate-x-1/2 bg-brand-dark/10"
              />
              {group.releases.map((release) => (
                <ReleaseRow
                  key={release.slug}
                  release={release}
                  selected={release.slug === props.selectedSlug}
                  installed={release.slug === props.installedSlug}
                  tabbable={release.slug === tabbableSlug}
                  onSelect={props.onSelect}
                  registerRef={registerRef}
                />
              ))}
            </ul>
          </section>
        ))}
      </div>
      {/* The shared pagination control derives its range from page × pageSize.
          hol.org clamps the page size it was asked for, so that arithmetic
          would reintroduce the overcount this feed was fixed for; the honest
          echo the daemon returns is used instead. */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-brand-dark/10 px-3 py-2.5">
        <p className="text-xs tabular-nums text-brand-dark/75">{pageRangeLabel(props.index)}</p>
        <div className="flex items-center gap-1.5">
          <ActionButton
            variant="outline"
            disabled={!hasPreviousPage(props.index)}
            onClick={() => props.onPage(props.index.page - 1)}
          >
            Newer
          </ActionButton>
          <ActionButton
            variant="outline"
            disabled={!hasNextPage(props.index)}
            onClick={() => props.onPage(props.index.page + 1)}
          >
            Older
          </ActionButton>
        </div>
      </div>
    </nav>
  );
}
