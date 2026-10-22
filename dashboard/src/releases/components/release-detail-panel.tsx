import { useMemo, useState } from "react";
import {
  HiMiniArrowDownTray,
  HiMiniArrowTopRightOnSquare,
  HiMiniChevronRight,
  HiMiniInformationCircle,
  HiMiniShieldCheck,
} from "react-icons/hi2";

import { Tag } from "../../approval-center-primitives";
import {
  channelLabel,
  comparisonLine,
  contributorMonogram,
  contributorName,
  contributorTone,
  mergeContributors,
  coverageNote,
  dedupeChanges,
  formatReleaseDate,
  groupChangesByKind,
  groupReleaseAssets,
  normalizeVersionLabel,
  verificationLabel,
} from "../releases-model";
import type { MergedContributor } from "../releases-model";
import type { ReleaseAsset, ReleaseChange, ReleaseDetail } from "../releases-types";
import { ReleaseInlineText, ReleaseNotes } from "./release-notes";

function CoverageNote({ note }: { note: string }) {
  return (
    <p className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2.5 text-sm leading-6 text-amber-900">
      <HiMiniInformationCircle className="mt-[3px] size-4 shrink-0" aria-hidden="true" />
      <span>{note}</span>
    </p>
  );
}

/** A collapsed section. Everything the feed carries stays reachable; only the
 * reading path is kept to what a reader came for. */
function Disclosure(props: { summary: string; count?: number; children: React.ReactNode }) {
  return (
    <details className="group rounded-xl border border-brand-dark/10 open:bg-brand-dark/[0.015]">
      <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 rounded-xl px-3 text-sm font-semibold text-brand-dark/80 transition-colors duration-150 hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none">
        <HiMiniChevronRight
          className="size-4 shrink-0 text-brand-dark/40 transition-transform duration-200 group-open:rotate-90 motion-reduce:transition-none"
          aria-hidden="true"
        />
        {props.summary}
        {props.count === undefined ? null : (
          <span className="tabular-nums text-xs font-medium text-brand-dark/45">{props.count}</span>
        )}
      </summary>
      <div className="px-3 pb-4 pt-1">{props.children}</div>
    </details>
  );
}

function ChangeItem({ change }: { change: ReleaseChange }) {
  return (
    <li className="text-sm leading-6 text-brand-dark/80 marker:text-brand-blue/45">
      <ReleaseInlineText source={change.summary} />
      {change.evidenceUrl ? (
        <>
          {" "}
          <a
            href={change.evidenceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-sm font-medium text-brand-blue underline decoration-brand-blue/35 underline-offset-[3px] transition-colors duration-150 hover:decoration-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none"
          >
            Evidence
            <HiMiniArrowTopRightOnSquare className="size-3.5" aria-hidden="true" />
          </a>
        </>
      ) : null}
    </li>
  );
}

function ContributorChip({ contributor }: { contributor: MergedContributor }) {
  const name = contributorName(contributor);
  const body = (
    <>
      <span
        className={`flex size-7 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold tabular-nums ${contributorTone(contributor)}`}
        aria-hidden="true"
      >
        {contributorMonogram(contributor)}
      </span>
      <span className="min-w-0 truncate font-medium text-brand-dark">{name}</span>
      <span className="shrink-0 text-xs text-brand-dark/50">
        {contributor.roles.join(", ")}
        {contributor.credits > 1 ? ` · ${contributor.credits} changes` : null}
      </span>
    </>
  );
  const shared =
    "flex min-h-11 max-w-full items-center gap-2 rounded-full border border-brand-dark/10 py-1 pl-1 pr-3 text-sm";
  return (
    <li title={verificationLabel(contributor.verificationMethod)}>
      {contributor.evidenceUrl ? (
        <a
          href={contributor.evidenceUrl}
          target="_blank"
          rel="noopener noreferrer"
          className={`${shared} transition-colors duration-150 hover:border-brand-blue/40 hover:bg-brand-blue/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none`}
        >
          {body}
        </a>
      ) : (
        <span className={shared}>{body}</span>
      )}
    </li>
  );
}

function AssetLink({ asset }: { asset: ReleaseAsset }) {
  return (
    <li>
      <a
        href={asset.url}
        target="_blank"
        rel="noopener noreferrer"
        className="flex min-h-11 items-center gap-2 rounded-xl border border-brand-dark/10 px-3 font-mono text-[13px] text-brand-dark/80 transition-colors duration-150 hover:border-brand-blue/40 hover:bg-brand-blue/[0.04] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none"
      >
        <HiMiniArrowDownTray className="size-4 shrink-0 text-brand-dark/40" aria-hidden="true" />
        <span className="truncate">{asset.name}</span>
      </a>
    </li>
  );
}

/** One release, in full: what changed, who is verified to have changed it,
 * what you can download, and what Guard cannot vouch for.
 *
 * The feed says the same thing several ways — authored notes, classified
 * changes, and the raw merge commits behind them. Whichever of those is the
 * maintainer's own words leads; the rest stays one click away instead of
 * repeating the release two more times down the page. */
export function ReleaseDetailPanel({
  detail,
  isInstalled = false,
}: {
  detail: ReleaseDetail;
  isInstalled?: boolean;
}) {
  const notes = detail.sourceNotes;
  // The notes carry the whole release when they were written for it, so the
  // itemised list derived from the same commits is a second telling.
  const notesLead = notes !== null && notes.scope === "exact_release";
  // Train-scoped notes describe a series, not this version, so a documented
  // change here is the only record of what shipped and has to survive.
  const changes = useMemo(() => dedupeChanges(detail.changes, notesLead), [detail.changes, notesLead]);
  const sections = useMemo(() => groupChangesByKind(changes), [changes]);
  const assets = useMemo(() => groupReleaseAssets(detail.assets), [detail.assets]);
  const roster = useMemo(() => mergeContributors(detail.roster), [detail.roster]);
  const note = coverageNote(detail.coverage);
  const changeList =
    sections.length > 0 ? (
      <div className="space-y-5">
        {sections.map((section) => (
          <section key={section.kind} aria-labelledby={`release-changes-${section.kind}`} className="space-y-2">
            <h3 id={`release-changes-${section.kind}`} className="text-sm font-semibold text-brand-dark">
              {section.label}
            </h3>
            <ul className="list-disc space-y-2 pl-5">
              {section.changes.map((change) => (
                <ChangeItem key={change.id} change={change} />
              ))}
            </ul>
          </section>
        ))}
      </div>
    ) : null;

  return (
    <article
      key={detail.slug}
      aria-labelledby="release-detail-heading"
      className="guard-surface-in space-y-6 rounded-xl border border-brand-dark/10 bg-white p-4 sm:p-6"
    >
      <header className="space-y-2.5">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <h2
            id="release-detail-heading"
            className="text-2xl font-semibold tracking-[-0.02em] text-brand-dark"
          >
            Guard {normalizeVersionLabel(detail.versionLabel)}
          </h2>
          <Tag tone={detail.channel === "stable" ? "green" : "amber"}>{channelLabel(detail.channel)}</Tag>
          {isInstalled ? (
            <Tag tone="blue">
              <HiMiniShieldCheck className="size-3.5" aria-hidden="true" />
              Running here
            </Tag>
          ) : null}
        </div>
        <p className="text-sm text-brand-dark/65">
          Released {formatReleaseDate(detail.publishedAt)}
          {detail.title && detail.title !== detail.rawTag ? ` · ${detail.title}` : ""} ·{" "}
          <span className="font-mono text-[13px]">{detail.rawTag}</span>
        </p>
        <p className="text-sm text-brand-dark/55">{comparisonLine(detail.comparison)}</p>
      </header>

      {note ? <CoverageNote note={note} /> : null}

      {notes !== null ? (
        <section aria-labelledby="release-notes-heading" className="space-y-3">
          <h3
            id="release-notes-heading"
            className="text-xs font-semibold uppercase tracking-[0.06em] text-brand-dark/45"
          >
            {notesLead ? "Published release notes" : `Release notes for the ${detail.train} series`}
          </h3>
          {notesLead ? null : (
            <p className="text-sm text-brand-dark/60">
              Published for the {detail.train} series rather than this exact release.
            </p>
          )}
          <ReleaseNotes source={notes.text} />
        </section>
      ) : null}

      {notesLead || !detail.summary ? null : (
        <section aria-labelledby="release-summary-heading" className="space-y-3">
          <h3
            id="release-summary-heading"
            className="text-xs font-semibold uppercase tracking-[0.06em] text-brand-dark/45"
          >
            {notes === null ? "Release notes" : "Notes for this release"}
          </h3>
          <ReleaseNotes source={detail.summary} />
        </section>
      )}

      {changeList === null ? (
        <p className="text-sm text-brand-dark/70">No itemised changes were published for this release.</p>
      ) : notesLead ? (
        <Disclosure summary="Itemised changes" count={changes.length}>
          {changeList}
        </Disclosure>
      ) : (
        changeList
      )}

      {detail.roster.length > 0 ? (
        <section aria-labelledby="release-roster-heading" className="space-y-2.5">
          <h3 id="release-roster-heading" className="text-sm font-semibold text-brand-dark">
            Verified contributors
          </h3>
          <ul className="flex flex-wrap gap-2">
            {roster.map((contributor) => (
              <ContributorChip key={contributor.creditId} contributor={contributor} />
            ))}
          </ul>
        </section>
      ) : null}

      {detail.assets.length > 0 ? (
        <Disclosure summary="Downloads" count={detail.assets.length}>
          <div className="space-y-4 pt-2">
            {assets.groups.map((group) => (
              <section key={group.id} className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-[0.06em] text-brand-dark/50">
                  {group.label}
                </h4>
                <ul className="grid gap-2 sm:grid-cols-2">
                  {group.assets.map((asset) => (
                    <AssetLink key={asset.url} asset={asset} />
                  ))}
                </ul>
              </section>
            ))}
            {assets.provenance.length > 0 ? (
              <section className="space-y-2">
                <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.06em] text-brand-dark/50">
                  <HiMiniShieldCheck className="size-3.5" aria-hidden="true" />
                  Provenance
                </h4>
                <ul className="grid gap-2 sm:grid-cols-2">
                  {assets.provenance.map((asset) => (
                    <AssetLink key={asset.url} asset={asset} />
                  ))}
                </ul>
              </section>
            ) : null}
          </div>
        </Disclosure>
      ) : null}
    </article>
  );
}
