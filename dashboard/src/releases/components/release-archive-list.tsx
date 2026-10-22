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

function ReleaseRow(props: {
  release: ReleaseSummary;
  selected: boolean;
  installed: boolean;
  onSelect: (slug: string) => void;
}) {
  const { release } = props;
  return (
    <li>
      <button
        type="button"
        aria-current={props.selected ? "true" : undefined}
        onClick={() => props.onSelect(release.slug)}
        className={`group relative flex min-h-11 w-full items-center gap-2.5 rounded-lg py-2 pl-3 pr-2.5 text-left transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none ${
          props.selected ? "bg-brand-blue/[0.07]" : "hover:bg-brand-dark/[0.035]"
        }`}
      >
        {/* The selected run is marked on the rail itself, so the eye can find
            its place without a second border around every row. */}
        <span
          aria-hidden="true"
          className={`absolute inset-y-1.5 left-0 w-0.5 rounded-full transition-colors duration-150 motion-reduce:transition-none ${
            props.selected ? "bg-brand-blue" : "bg-transparent"
          }`}
        />
        <span className="min-w-0 flex-1">
          <span
            className={`block truncate font-mono text-[13px] tabular-nums ${
              props.selected ? "font-semibold text-brand-dark" : "text-brand-dark/85"
            }`}
          >
            {normalizeVersionLabel(release.versionLabel)}
          </span>
          <span className="mt-0.5 block text-xs text-brand-dark/50">
            {formatReleaseDate(release.publishedAt)}
            {release.channel === "preview" ? ` · ${channelLabel(release.channel)}` : ""}
          </span>
        </span>
        {props.installed ? (
          <span className="flex shrink-0 items-center gap-1 rounded-full bg-brand-blue/10 px-2 py-0.5 text-[11px] font-semibold text-brand-blue">
            <HiMiniCheckCircle className="size-3.5" aria-hidden="true" />
            Installed here
          </span>
        ) : null}
      </button>
    </li>
  );
}

/** Every published version, newest first, grouped by the train it belongs to,
 * with the one running on this device marked so the reader can place
 * themselves in the history. */
export function ReleaseArchiveList(props: {
  index: ReleaseIndex;
  selectedSlug: string | null;
  installedSlug: string | null;
  onSelect: (slug: string) => void;
  onPage: (page: number) => void;
}) {
  const groups = groupReleasesByTrain(props.index.releases);
  return (
    <nav aria-label="Published Guard releases" className="flex min-h-0 flex-1 flex-col">
      <div className="min-h-0 flex-1 overflow-y-auto px-1.5 pb-2">
        {groups.map((group, position) => (
          <section key={`${group.train}-${position}`} aria-label={`${group.train} series`}>
            <h3 className="sticky top-0 z-10 bg-white/90 px-1.5 py-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-brand-dark/45 backdrop-blur">
              {group.train}
            </h3>
            <ul className="space-y-0.5 pb-2">
              {group.releases.map((release) => (
                <ReleaseRow
                  key={release.slug}
                  release={release}
                  selected={release.slug === props.selectedSlug}
                  installed={release.slug === props.installedSlug}
                  onSelect={props.onSelect}
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
        <p className="text-xs tabular-nums text-brand-dark/50">{pageRangeLabel(props.index)}</p>
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
