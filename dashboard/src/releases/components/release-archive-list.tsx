import { HiMiniChevronRight } from "react-icons/hi2";

import { ActionButton, Tag } from "../../approval-center-primitives";
import {
  channelLabel,
  formatReleaseDate,
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
        className={`group flex w-full min-h-11 items-center gap-3 rounded-xl border px-3 py-3 text-left transition-colors duration-150 motion-reduce:transition-none ${
          props.selected
            ? "border-brand-blue/40 bg-brand-blue/[0.06]"
            : "border-transparent hover:border-brand-dark/10 hover:bg-brand-dark/[0.03]"
        }`}
      >
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <strong className="text-sm font-semibold text-brand-dark">{normalizeVersionLabel(release.versionLabel)}</strong>
            {release.channel === "preview" ? <Tag tone="amber">Preview</Tag> : null}
            {props.installed ? <Tag tone="blue">Installed here</Tag> : null}
          </span>
          <span className="mt-0.5 block truncate text-sm text-brand-dark/70">{release.title}</span>
          <span className="mt-0.5 block text-xs text-brand-dark/55">
            {channelLabel(release.channel)} · {formatReleaseDate(release.publishedAt)}
          </span>
        </span>
        <HiMiniChevronRight
          className="size-5 shrink-0 text-brand-dark/35 transition-transform duration-150 group-hover:translate-x-0.5 motion-reduce:transition-none"
          aria-hidden="true"
        />
      </button>
    </li>
  );
}

/** Every published version, newest first, with the one running on this device
 * marked so the reader can place themselves in the history. */
export function ReleaseArchiveList(props: {
  index: ReleaseIndex;
  selectedSlug: string | null;
  installedSlug: string | null;
  onSelect: (slug: string) => void;
  onPage: (page: number) => void;
}) {
  return (
    <nav aria-label="Published Guard releases" className="space-y-3">
      <ul className="space-y-1">
        {props.index.releases.map((release) => (
          <ReleaseRow
            key={release.slug}
            release={release}
            selected={release.slug === props.selectedSlug}
            installed={release.slug === props.installedSlug}
            onSelect={props.onSelect}
          />
        ))}
      </ul>
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-brand-dark/10 pt-3">
        <p className="text-xs text-brand-dark/55">{pageRangeLabel(props.index)}</p>
        <div className="flex items-center gap-2">
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
