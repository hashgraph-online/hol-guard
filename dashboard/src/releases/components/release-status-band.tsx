import {
  HiMiniArrowUpCircle,
  HiMiniCheckCircle,
  HiMiniInformationCircle,
  HiMiniXMark,
} from "react-icons/hi2";

import { ActionButton, Tag } from "../../approval-center-primitives";
import { channelLabel, normalizeVersionLabel, standingCopy } from "../releases-model";
import type { InstalledStanding } from "../releases-model";

/**
 * Where this device stands in the published history, said outright.
 *
 * A list of version numbers cannot answer the question a reader actually
 * arrives with — am I current, and if not, by how much — so the screen
 * answers it first and lets the archive below be an archive. The band is
 * status, not a notice: it stays. Only its call to action is dismissible,
 * once per version, so a reader who has read the notes is not asked again
 * until the next release.
 */

function Marker({ standing }: { standing: InstalledStanding }) {
  if (standing.kind === "behind") {
    return (
      <span
        className="flex size-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-brand-blue"
        aria-hidden="true"
      >
        <HiMiniArrowUpCircle className="size-5" />
      </span>
    );
  }
  if (standing.kind === "current") {
    return (
      <span
        className="flex size-9 shrink-0 items-center justify-center rounded-full bg-brand-green-bg text-brand-green-text"
        aria-hidden="true"
      >
        <HiMiniCheckCircle className="size-5" />
      </span>
    );
  }
  return (
    <span
      className="flex size-9 shrink-0 items-center justify-center rounded-full bg-brand-dark/[0.06] text-brand-dark/45"
      aria-hidden="true"
    >
      <HiMiniInformationCircle className="size-5" />
    </span>
  );
}

function surfaceClass(standing: InstalledStanding): string {
  if (standing.kind === "behind") return "border-brand-blue/20 bg-brand-blue/[0.04]";
  if (standing.kind === "current") return "border-brand-dark/10 bg-white";
  return "border-brand-dark/10 bg-surface-1";
}

export function ReleaseStatusBand(props: {
  standing: InstalledStanding;
  /** Open the release the call to action names. Absent while the archive is
   * still loading, which is also when there is nothing to call for. */
  onRead?: () => void;
  onDismiss?: () => void;
  ctaDismissed?: boolean;
}) {
  const { standing } = props;
  const copy = standingCopy(standing);
  const release =
    standing.kind === "current" || standing.kind === "behind" ? standing.release : null;
  const isVersion = release !== null || standing.kind === "off-page";
  // Only a release the band can actually open is worth a button, and only
  // until the reader says they have read it.
  const target =
    standing.kind === "behind" ? (standing.newest ?? standing.release) : (release ?? null);
  const showCta = target !== null && props.onRead !== undefined && props.ctaDismissed !== true;
  const ctaLabel =
    standing.kind === "behind" && standing.newest
      ? `What's new in ${normalizeVersionLabel(standing.newest.versionLabel)}`
      : "Read the notes";

  return (
    <section
      aria-labelledby="releases-standing-heading"
      className={`guard-surface-in rounded-2xl border p-4 sm:p-5 ${surfaceClass(standing)}`}
    >
      <div className="flex flex-wrap items-start gap-x-6 gap-y-4">
        <div className="flex min-w-0 flex-[1_1_20rem] items-start gap-3.5">
          <Marker standing={standing} />
          <div className="min-w-0 space-y-2">
            <h1
              id="releases-standing-heading"
              className="flex flex-wrap items-center gap-x-3 gap-y-2"
            >
              <span
                className={
                  isVersion
                    ? "font-mono text-[1.75rem] font-semibold leading-none tracking-[-0.02em] tabular-nums text-brand-dark"
                    : "text-xl font-semibold leading-tight tracking-[-0.01em] text-brand-dark"
                }
              >
                {copy.title}
              </span>
              {release ? (
                <Tag tone={release.channel === "stable" ? "green" : "amber"}>
                  {channelLabel(release.channel)}
                </Tag>
              ) : null}
            </h1>
            <p className="max-w-[62ch] text-sm leading-6 text-brand-dark/75">{copy.body}</p>
          </div>
        </div>
        {showCta ? (
          <div className="flex shrink-0 items-center gap-1.5">
            <ActionButton variant="primary" onClick={props.onRead}>
              {ctaLabel}
            </ActionButton>
            {props.onDismiss ? (
              <button
                type="button"
                onClick={props.onDismiss}
                aria-label={`Dismiss ${ctaLabel}`}
                className="flex size-11 items-center justify-center rounded-xl text-brand-dark/50 transition-colors duration-150 hover:bg-brand-dark/[0.06] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none"
              >
                <HiMiniXMark className="size-5" aria-hidden="true" />
              </button>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
