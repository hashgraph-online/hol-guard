/**
 * What the release screen says when a read fails or a list was trimmed, and
 * where the reader can go instead. Kept apart from the archive model so the
 * wording can be reviewed on its own.
 */
import type { ReleaseFeedFailure } from "./releases-types";

export type ReleaseFailureCopy = { title: string; body: string };

/** The public archive on hol.org: every release Guard lists is readable there
 * too, so it is the way out when this device cannot show one. */
export const HOL_RELEASES_URL = "https://hol.org/guard/releases";

export function holReleaseUrl(slug: string | null): string {
  return slug && /^[a-z0-9][a-z0-9.-]{0,127}$/.test(slug) ? `${HOL_RELEASES_URL}/${slug}` : HOL_RELEASES_URL;
}

const FAILURE_COPY: Record<ReleaseFeedFailure, ReleaseFailureCopy> = {
  offline: {
    title: "Guard could not reach the release archive",
    body: "The archive is published by hol.org and read through Guard on this device. Check this device's connection and try again.",
  },
  unavailable: {
    title: "The release archive did not answer",
    body: "hol.org could not serve the archive just now. Nothing on this device is affected; try again in a few minutes.",
  },
  "not-found": {
    title: "That release is not published",
    body: "Guard only shows releases that have been published and verified. Pick another version from the list.",
  },
  unsupported: {
    title: "This Guard build cannot read the archive",
    body: "The release archive needs Guard's native runtime. Update Guard to see release history here.",
  },
  unreadable: {
    title: "Guard can't show this release here",
    body: "hol.org answered, but this release isn't in a form Guard can safely display. Nothing on this device is affected. Read it on hol.org; a Guard update may show it here.",
  },
  session: {
    title: "This window's session has ended",
    body: "Guard is still running on this device. Open the dashboard again from Guard to keep reading release history.",
  },
  disabled: {
    title: "Release history is turned off on this device",
    body: "Guard is set to skip the release archive (HOL_GUARD_RELEASE_FEED=off). Nothing on hol.org is affected; clear that setting and restart Guard to read release history here.",
  },
};

export function failureCopy(failure: ReleaseFeedFailure): ReleaseFailureCopy {
  return FAILURE_COPY[failure];
}

/** Only a failure that could clear on its own is worth a retry button: an old
 * build and a switched-off archive both stay failed however often the reader
 * presses it, a release that was never published stays unpublished, and an
 * ended session needs the dashboard opened again from Guard. */
export function isRetryable(failure: ReleaseFeedFailure): boolean {
  return failure === "unavailable" || failure === "offline";
}

/** Only a release Guard declined to display is still worth reading somewhere
 * else; every other failure leaves hol.org just as unreachable, or is local. */
export function readsOnHol(failure: ReleaseFeedFailure): boolean {
  return failure === "unreadable";
}

/** The note under a list Guard trimmed, or null when it shows everything. */
export function trimmedNote(shown: number, total: number, noun: string): string | null {
  if (!Number.isFinite(total) || total <= shown) return null;
  const format = new Intl.NumberFormat("en-US");
  return `Showing the first ${format.format(shown)} of ${format.format(total)} ${noun}.`;
}
