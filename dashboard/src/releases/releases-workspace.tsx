import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ActionButton, EmptyState } from "../approval-center-primitives";
import { ReleaseArchiveList } from "./components/release-archive-list";
import { ReleaseDetailPanel } from "./components/release-detail-panel";
import { WhatsNewCard } from "./components/whats-new-card";
import { fetchReleaseDetail, fetchReleaseIndex } from "./releases-api";
import {
  dismissWhatsNew,
  failureCopy,
  installedNote,
  installedRelease,
  isRetryable,
  isWhatsNewDismissed,
  openingSlug,
} from "./releases-model";
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
    <p role="status" className="py-8 text-center text-sm text-brand-dark/60">
      {label}
    </p>
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

  const installed =
    indexState.kind === "ready" ? installedRelease(indexState.index.releases, installedVersion) : null;
  const installedLabel = installed?.versionLabel ?? null;

  // Read during render, not in an effect: an effect would paint the card once
  // before hiding it, so a reader who dismissed it last week sees it flash on
  // every visit.
  const dismissedBefore = useMemo(
    () => (installedLabel === null ? false : isWhatsNewDismissed(installedLabel)),
    [installedLabel],
  );
  const whatsNewDismissed = dismissedBefore || dismissedLabel === installedLabel;

  const handleSelect = useCallback((slug: string) => {
    readerChose.current = true;
    setSelectedSlug(slug);
    detailHeadingRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  const handleReadWhatsNew = useCallback(() => {
    if (installed) handleSelect(installed.slug);
  }, [installed, handleSelect]);

  const handleDismissWhatsNew = useCallback(() => {
    if (!installedLabel) return;
    dismissWhatsNew(installedLabel);
    setDismissedLabel(installedLabel);
  }, [installedLabel]);

  return (
    <div className="space-y-6 pb-10">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight text-brand-dark">Releases</h1>
        <p className="text-sm text-brand-dark/65">
          Every published Guard version, what it changed, and who is verified to have changed it.
          {indexState.kind === "ready" ? installedNote(indexState.index.releases, installedVersion) : ""}
        </p>
      </header>

      {installed && !whatsNewDismissed ? (
        <WhatsNewCard release={installed} onRead={handleReadWhatsNew} onDismiss={handleDismissWhatsNew} />
      ) : null}

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
        <div className="grid gap-6 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
          <ReleaseArchiveList
            index={indexState.index}
            selectedSlug={selectedSlug}
            installedSlug={installed?.slug ?? null}
            onSelect={handleSelect}
            onPage={setPage}
          />
          <div ref={detailHeadingRef} className="min-w-0">
            {detailState.kind === "loading" ? <LoadingNotice label="Reading this release…" /> : null}
            {detailState.kind === "failed" ? (
              <FailureNotice
                failure={detailState.failure}
                onRetry={
                  isRetryable(detailState.failure) ? () => setDetailToken((token) => token + 1) : undefined
                }
              />
            ) : null}
            {detailState.kind === "ready" ? <ReleaseDetailPanel detail={detailState.detail} /> : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
