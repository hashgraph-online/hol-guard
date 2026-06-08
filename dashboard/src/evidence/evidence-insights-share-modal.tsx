import { useCallback, useState } from "react";
import type { GuardReceiptAnalytics, GuardRuntimeSnapshot } from "../guard-types";
import { ActionButton } from "../approval-center-primitives";
import { GuardModalLayer } from "../guard-modal-layer";
import { publishInsightsShare, type GuardInsightsShareResult } from "../guard-api";
import { EvidenceInsightsHeadlineBento } from "./evidence-insights-headline-bento";
import { EvidenceInsightsShareSheet } from "./evidence-insights-share-sheet";

interface EvidenceInsightsShareModalProps {
  analytics: GuardReceiptAnalytics;
  runtime: GuardRuntimeSnapshot | null;
  onClose: () => void;
}

export function EvidenceInsightsShareModal({
  analytics,
  runtime,
  onClose,
}: EvidenceInsightsShareModalProps) {
  const [includeTopArtifacts, setIncludeTopArtifacts] = useState(false);
  const [showDisplayName, setShowDisplayName] = useState(true);
  const [displayName, setDisplayName] = useState("");
  const [publishing, setPublishing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shareResult, setShareResult] = useState<GuardInsightsShareResult | null>(null);

  const cloudConnected = runtime?.cloud_state === "paired_active";
  const connectUrl = runtime?.connect_url ?? "https://hol.org/guard/connect";

  const handlePublish = useCallback(async () => {
    setPublishing(true);
    setError(null);
    try {
      const result = await publishInsightsShare({
        includeTopArtifacts,
        showDisplayName,
        displayName: showDisplayName && displayName.trim() ? displayName.trim() : undefined,
      });
      setShareResult(result);
    } catch (publishError) {
      setError(publishError instanceof Error ? publishError.message : "Unable to publish share link.");
    } finally {
      setPublishing(false);
    }
  }, [displayName, includeTopArtifacts, showDisplayName]);

  if (shareResult) {
    return (
      <EvidenceInsightsShareSheet
        publicUrl={shareResult.publicUrl}
        onClose={() => {
          setShareResult(null);
          onClose();
        }}
      />
    );
  }

  return (
    <GuardModalLayer ariaLabel="Share your Guard stats" onClose={onClose}>
      <div className="rounded-2xl border border-slate-200 bg-white shadow-xl">
        <div className="border-b border-slate-100 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-brand-dark">Share your Guard stats</h2>
              <p className="mt-1 text-sm text-slate-500">
                Publish a redacted snapshot to HOL Guard Cloud for social sharing.
              </p>
            </div>
            <button type="button" onClick={onClose} className="text-sm font-medium text-slate-500 hover:text-brand-dark">
              Close
            </button>
          </div>
        </div>

        {!cloudConnected ? (
          <div className="space-y-4 px-5 py-5">
            <p className="text-sm text-slate-600">
              Connect Guard Cloud to publish a public share link with preview image support.
            </p>
            <ActionButton
              onClick={() => {
                window.open(connectUrl, "_blank", "noopener,noreferrer");
              }}
            >
              Connect Guard Cloud
            </ActionButton>
          </div>
        ) : (
          <>
            <div className="space-y-4 px-5 py-5">
              <div className="overflow-hidden rounded-2xl border border-slate-200">
                <EvidenceInsightsHeadlineBento analytics={analytics} variant="compact" />
              </div>

              <label className="flex items-center gap-3 text-sm text-brand-dark">
                <input
                  type="checkbox"
                  checked={showDisplayName}
                  onChange={(event) => setShowDisplayName(event.target.checked)}
                  className="h-4 w-4 rounded border-slate-300"
                />
                Show display name on the public card
              </label>

              {showDisplayName ? (
                <label className="block text-sm text-brand-dark">
                  <span className="mb-1 block text-slate-500">Display name</span>
                  <input
                    type="text"
                    value={displayName}
                    onChange={(event) => setDisplayName(event.target.value)}
                    placeholder="Your name"
                    className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
                    maxLength={120}
                  />
                </label>
              ) : null}

              <label className="flex items-center gap-3 text-sm text-brand-dark">
                <input
                  type="checkbox"
                  checked={includeTopArtifacts}
                  onChange={(event) => setIncludeTopArtifacts(event.target.checked)}
                  className="h-4 w-4 rounded border-slate-300"
                />
                Include top recurring action labels (redacted)
              </label>

              {error ? <p className="text-sm text-amber-700">{error}</p> : null}
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-slate-100 px-5 py-4">
              <ActionButton variant="outline" onClick={onClose}>
                Cancel
              </ActionButton>
              <ActionButton onClick={handlePublish} disabled={publishing}>
                {publishing ? "Publishing…" : "Publish share link"}
              </ActionButton>
            </div>
          </>
        )}
      </div>
    </GuardModalLayer>
  );
}
