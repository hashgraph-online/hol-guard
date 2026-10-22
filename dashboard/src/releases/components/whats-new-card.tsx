import { HiMiniSparkles, HiMiniXMark } from "react-icons/hi2";

import { ActionButton } from "../../approval-center-primitives";
import { channelLabel, formatReleaseDate, normalizeVersionLabel } from "../releases-model";
import type { ReleaseSummary } from "../releases-types";

/**
 * The lead card after an update lands: what the version running on this device
 * changed. It is dismissible per version, so it returns once — the next
 * release raises it again rather than nagging about one the reader has read.
 */
export function WhatsNewCard(props: {
  release: ReleaseSummary;
  onRead: () => void;
  onDismiss: () => void;
}) {
  return (
    <section
      aria-labelledby="whats-new-heading"
      className="guard-surface-in relative overflow-hidden rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-4 sm:p-5"
    >
      <div className="flex flex-wrap items-start gap-3">
        <span
          className="flex size-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-brand-blue"
          aria-hidden="true"
        >
          <HiMiniSparkles className="size-5" />
        </span>
        <div className="min-w-0 flex-1 space-y-1">
          <h2 id="whats-new-heading" className="text-base font-semibold text-brand-dark">
            What's new in Guard {normalizeVersionLabel(props.release.versionLabel)}
          </h2>
          <p className="text-sm text-brand-dark/70">
            {props.release.title} · {channelLabel(props.release.channel)} · released{" "}
            {formatReleaseDate(props.release.publishedAt)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <ActionButton variant="primary" onClick={props.onRead}>
            Read the notes
          </ActionButton>
          <button
            type="button"
            onClick={props.onDismiss}
            aria-label={`Dismiss what's new in Guard ${normalizeVersionLabel(props.release.versionLabel)}`}
            className="flex size-11 items-center justify-center rounded-xl text-brand-dark/55 hover:bg-brand-dark/5 hover:text-brand-dark"
          >
            <HiMiniXMark className="size-5" aria-hidden="true" />
          </button>
        </div>
      </div>
    </section>
  );
}
