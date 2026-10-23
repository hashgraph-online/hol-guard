import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ActionButton, EmptyState } from "../approval-center-primitives";
import { ReleaseArchiveList } from "./components/release-archive-list";
import { ReleaseDetailPanel } from "./components/release-detail-panel";
import { ReleaseStatusBand } from "./components/release-status-band";
import { fetchReleaseDetail, fetchReleaseIndex } from "./releases-api";
import {
  dismissWhatsNew,
  failureCopy,
  installedStanding,
  isRetryable,
  isWhatsNewDismissed,
  openingSlug,
} from "./releases-model";
import type { InstalledStanding } from "./releases-model";
import type { ReleaseDetail, ReleaseFeedFailure, ReleaseIndex } from "./releases-types";

type IndexState =
  | { kind: "loading" }
  | { kind: "ready"; index: ReleaseIndex }
  | { kind: "failed"; failure: ReleaseFeedFailure };

type DetailState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; detail: ReleaseDetail }
  | { kind: "failed"; failure: ReleaseFeedFailure };

function FailureNotice(props: { failure: ReleaseFeedFailure; onRetry?: () => void }) {
  const copy = failureCopy(props.failure);
  return (
    <EmptyState
      title={copy.title}
      body={copy.body}
      action={
        props.onRetry ? (
          <ActionButton variant="outline" onClick={props.onRetry}>
            Try again
          </ActionButton>
        ) : undefined
      }
    />
  );
}

function LoadingNotice({ label }: { label: string }) {
  return (
    <p role="status" className="py-8 text-center text-sm text-brand-dark/75">
      {label}
    </p>
  );
}

/** The detail panel's own shape while it loads, so switching releases moves
 * the page as little as the content will. */
function DetailSkeleton() {
  return (
    <div
      role="status"
      aria-label="Reading this release"
      className="guard-surface-in space-y-6 rounded-xl border border-brand-dark/10 bg-white p-4 sm:p-6"
    >
      <div className="space-y-2.5">
        <div className="h-7 w-56 rounded-lg bg-brand-dark/[0.07]" />
        <div className="h-4 w-72 rounded bg-brand-dark/[0.05]" />
      </div>
      <div className="max-w-[68ch] space-y-2.5">
        {[100, 94, 88, 62].map((width) => (
          <div key={width} className="h-4 rounded bg-brand-dark/[0.05]" style={{ width: `${width}%` }} />
        ))}
      </div>
      <div className="h-11 w-full rounded-xl bg-brand-dark/[0.04]" />
    </div>
  );
}

/**
 * The release archive: every published Guard version, what each one changed,
 * and who is verified to have changed it. The daemon reads hol.org on this
 * screen's behalf; the browser never leaves the device's own origin.
 */
export function ReleasesWorkspace({ installedVersion }: { installedVersion?: string | null }) {
  const [page, setPage] = useState(1);
  const [indexState, setIndexState] = useState<IndexState>({ kind: "loading" });
  const [selectedSlug, setSelectedSlug] = useState<string | null>(null);
  const [detailState, setDetailState] = useState<DetailState>({ kind: "idle" });
  const [dismissedLabel, setDismissedLabel] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [detailToken, setDetailToken] = useState(0);
  const detailHeadingRef = useRef<HTMLDivElement | null>(null);
  // A release the reader opened themselves outranks the one the screen would
  // have opened for them.
  const readerChose = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    setIndexState({ kind: "loading" });
    fetchReleaseIndex({ page, signal: controller.signal })
      .then((result) => {
        if (controller.signal.aborted) return;
        if (result.status === "failed") {
          setIndexState({ kind: "failed", failure: result.failure });
          return;
        }
        setIndexState({ kind: "ready", index: result.index });
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setIndexState({ kind: "failed", failure: "unavailable" });
        }
      });
    return () => controller.abort();
  }, [page, reloadToken]);

  // Open the release this device runs when the archive page holds it,
  // otherwise the newest one, so the screen is never blank on arrival. The
  // installed version arrives from Guard on its own schedule: when it lands
  // after the archive, the screen moves to it rather than leaving the reader
  // on the newest release they did not ask for.
  useEffect(() => {
    if (indexState.kind !== "ready") return;
    const releases = indexState.index.releases;
    setSelectedSlug((current) => openingSlug(releases, installedVersion, current, readerChose.current));
  }, [indexState, installedVersion]);

  useEffect(() => {
    if (!selectedSlug) {
      setDetailState({ kind: "idle" });
      return;
    }
    const controller = new AbortController();
    setDetailState({ kind: "loading" });
    fetchReleaseDetail(selectedSlug, { signal: controller.signal })
      .then((result) => {
        if (controller.signal.aborted) return;
        setDetailState(
          result.status === "failed"
            ? { kind: "failed", failure: result.failure }
            : { kind: "ready", detail: result.detail },
        );
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setDetailState({ kind: "failed", failure: "unavailable" });
        }
      });
    return () => controller.abort();
  }, [selectedSlug, detailToken]);

  const standing: InstalledStanding = useMemo(
    () =>
      indexState.kind === "ready"
        ? installedStanding(indexState.index, installedVersion)
        : { kind: "unknown" },
    [indexState, installedVersion],
  );

  // The standing already found this device's row on the page in hand; the
  // archive and the detail panel mark the same row.
  const installed =
    standing.kind === "current" || standing.kind === "behind" ? standing.release : null;

  const handleSelect = useCallback((slug: string, options?: { scroll?: boolean }) => {
    readerChose.current = true;
    setSelectedSlug(slug);
    if (options?.scroll === false) return;
    detailHeadingRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  // The band calls for the newest release when this device is behind, and for
  // the installed one when it is not.
  const standingTarget =
    standing.kind === "behind"
      ? (standing.newest ?? standing.release)
      : standing.kind === "current"
        ? standing.release
        : null;
  // Dismissal belongs to the release the button names, not to the one this
  // device runs. Saved under the installed version, a reader who dismissed
  // the call for 3.53.0 would never be offered 3.54.0 while they stayed put.
  const targetLabel = standingTarget?.versionLabel ?? null;

  // Read during render, not in an effect: an effect would paint the call once
  // before hiding it, so a reader who dismissed it last week sees it flash on
  // every visit.
  const dismissedBefore = useMemo(
    () => (targetLabel === null ? false : isWhatsNewDismissed(targetLabel)),
    [targetLabel],
  );
  const whatsNewDismissed = dismissedBefore || dismissedLabel === targetLabel;

  const handleReadWhatsNew = useCallback(() => {
    if (standingTarget) handleSelect(standingTarget.slug);
  }, [standingTarget, handleSelect]);

  const handleDismissWhatsNew = useCallback(() => {
    if (!targetLabel) return;
    dismissWhatsNew(targetLabel);
    setDismissedLabel(targetLabel);
  }, [targetLabel]);

  return (
    <div className="guard-releases space-y-6 pb-10">
      <ReleaseStatusBand
        standing={standing}
        onRead={standingTarget ? handleReadWhatsNew : undefined}
        onDismiss={targetLabel ? handleDismissWhatsNew : undefined}
        ctaDismissed={whatsNewDismissed}
      />

      {indexState.kind === "loading" ? <LoadingNotice label="Reading the release archive…" /> : null}

      {indexState.kind === "failed" ? (
        <FailureNotice
          failure={indexState.failure}
          onRetry={isRetryable(indexState.failure) ? () => setReloadToken((token) => token + 1) : undefined}
        />
      ) : null}

      {indexState.kind === "ready" && indexState.index.releases.length === 0 ? (
        <EmptyState
          title="No releases are published yet"
          body="Once a Guard release is published and verified, it appears here with its notes and contributors."
        />
      ) : null}

      {indexState.kind === "ready" && indexState.index.releases.length > 0 ? (
        <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
          {/* The rail scrolls on its own so the reader keeps their place in
              the history while reading a release that runs long. */}
          <div className="flex max-h-[32rem] flex-col overflow-hidden rounded-xl border border-brand-dark/10 bg-white lg:sticky lg:top-4 lg:max-h-[calc(100vh-8rem)]">
            <ReleaseArchiveList
              index={indexState.index}
              selectedSlug={selectedSlug}
              installedSlug={installed?.slug ?? null}
              onSelect={handleSelect}
              onPage={setPage}
            />
          </div>
          <div ref={detailHeadingRef} className="min-w-0">
            {detailState.kind === "loading" ? <DetailSkeleton /> : null}
            {detailState.kind === "failed" ? (
              <FailureNotice
                failure={detailState.failure}
                onRetry={
                  isRetryable(detailState.failure) ? () => setDetailToken((token) => token + 1) : undefined
                }
              />
            ) : null}
            {detailState.kind === "ready" ? (
              <ReleaseDetailPanel
                detail={detailState.detail}
                isInstalled={installed?.slug === detailState.detail.slug}
              />
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
