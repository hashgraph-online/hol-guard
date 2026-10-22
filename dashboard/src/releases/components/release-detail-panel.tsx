import { HiMiniArrowDownTray, HiMiniArrowTopRightOnSquare, HiMiniInformationCircle } from "react-icons/hi2";

import { Tag } from "../../approval-center-primitives";
import {
  channelLabel,
  comparisonLine,
  contributorName,
  coverageNote,
  formatReleaseDate,
  groupChangesByKind,
  normalizeVersionLabel,
  verificationLabel,
} from "../releases-model";
import type { ReleaseChange, ReleaseContributor, ReleaseDetail } from "../releases-types";

function CoverageNote({ note }: { note: string }) {
  return (
    <p className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
      <HiMiniInformationCircle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{note}</span>
    </p>
  );
}

function ChangeItem({ change }: { change: ReleaseChange }) {
  return (
    <li className="text-sm leading-6 text-brand-dark/80">
      <span className="whitespace-pre-line">{change.summary}</span>
      {change.evidenceUrl ? (
        <>
          {" "}
          <a
            href={change.evidenceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-semibold text-brand-blue underline decoration-brand-blue/40 underline-offset-2 hover:decoration-brand-blue"
          >
            Evidence
            <HiMiniArrowTopRightOnSquare className="size-3.5" aria-hidden="true" />
          </a>
        </>
      ) : null}
    </li>
  );
}

function ContributorRow({ contributor }: { contributor: ReleaseContributor }) {
  const name = contributorName(contributor);
  return (
    <li className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm">
      {contributor.evidenceUrl ? (
        <a
          href={contributor.evidenceUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="font-semibold text-brand-blue underline decoration-brand-blue/40 underline-offset-2 hover:decoration-brand-blue"
        >
          {name}
        </a>
      ) : (
        <span className="font-semibold text-brand-dark">{name}</span>
      )}
      <span className="text-brand-dark/70">{contributor.roles.join(", ")}</span>
      <span className="text-xs text-brand-dark/55">{verificationLabel(contributor.verificationMethod)}</span>
    </li>
  );
}

/** One release, in full: what changed, who is verified to have changed it,
 * what you can download, and what Guard cannot vouch for. */
export function ReleaseDetailPanel({ detail }: { detail: ReleaseDetail }) {
  const sections = groupChangesByKind(detail.changes);
  const note = coverageNote(detail.coverage);
  return (
    <article
      key={detail.slug}
      aria-labelledby="release-detail-heading"
      className="guard-surface-in space-y-6 rounded-xl border border-brand-dark/10 bg-white p-4 sm:p-6"
    >
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h2 id="release-detail-heading" className="text-xl font-semibold tracking-tight text-brand-dark">
            Guard {normalizeVersionLabel(detail.versionLabel)}
          </h2>
          <Tag tone={detail.channel === "stable" ? "green" : "amber"}>{channelLabel(detail.channel)}</Tag>
        </div>
        <p className="text-sm text-brand-dark/70">
          {detail.title} · released {formatReleaseDate(detail.publishedAt)} · tagged {detail.rawTag}
        </p>
        <p className="text-sm text-brand-dark/60">{comparisonLine(detail.comparison)}</p>
      </header>

      {note ? <CoverageNote note={note} /> : null}

      {detail.summary ? <p className="whitespace-pre-line text-sm leading-6 text-brand-dark/80">{detail.summary}</p> : null}

      {sections.length > 0 ? (
        <div className="space-y-5">
          {sections.map((section) => (
            <section key={section.kind} aria-labelledby={`release-changes-${section.kind}`} className="space-y-2">
              <h3
                id={`release-changes-${section.kind}`}
                className="text-sm font-semibold text-brand-dark"
              >
                {section.label}
              </h3>
              <ul className="list-disc space-y-1.5 pl-5">
                {section.changes.map((change) => (
                  <ChangeItem key={change.id} change={change} />
                ))}
              </ul>
            </section>
          ))}
        </div>
      ) : (
        <p className="text-sm text-brand-dark/70">
          No itemised changes were published for this release.
        </p>
      )}

      {detail.roster.length > 0 ? (
        <section aria-labelledby="release-roster-heading" className="space-y-2">
          <h3 id="release-roster-heading" className="text-sm font-semibold text-brand-dark">
            Verified contributors
          </h3>
          <ul className="space-y-1.5">
            {detail.roster.map((contributor) => (
              <ContributorRow key={contributor.creditId} contributor={contributor} />
            ))}
          </ul>
        </section>
      ) : null}

      {detail.assets.length > 0 ? (
        <section aria-labelledby="release-assets-heading" className="space-y-2">
          <h3 id="release-assets-heading" className="text-sm font-semibold text-brand-dark">
            Downloads
          </h3>
          <ul className="flex flex-wrap gap-2">
            {detail.assets.map((asset) => (
              <li key={asset.url}>
                <a
                  href={asset.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-brand-dark/15 px-3 text-sm font-semibold text-brand-dark hover:border-brand-blue/40 hover:bg-brand-blue/[0.04]"
                >
                  <HiMiniArrowDownTray className="size-4" aria-hidden="true" />
                  {asset.name}
                </a>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {detail.sourceNotes ? (
        <section aria-labelledby="release-source-heading" className="space-y-2 border-t border-brand-dark/10 pt-4">
          <h3 id="release-source-heading" className="text-sm font-semibold text-brand-dark">
            {detail.sourceNotes.scope === "exact_release"
              ? "Published release notes"
              : `Release notes for the ${detail.train} series`}
          </h3>
          <p className="whitespace-pre-line text-sm leading-6 text-brand-dark/75">{detail.sourceNotes.text}</p>
        </section>
      ) : null}
    </article>
  );
}
