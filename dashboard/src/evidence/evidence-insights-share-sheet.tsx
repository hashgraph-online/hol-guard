"use client";

import { useCallback, useState } from "react";
import { FiCheck, FiCopy, FiShare2 } from "react-icons/fi";
import { GuardModalLayer } from "../guard-modal-layer";

interface EvidenceInsightsShareSheetProps {
  publicUrl: string;
  onClose: () => void;
}

export function EvidenceInsightsShareSheet({ publicUrl, onClose }: EvidenceInsightsShareSheetProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(publicUrl);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }, [publicUrl]);

  const handleNativeShare = useCallback(async () => {
    if (typeof navigator !== "undefined" && navigator.share) {
      try {
        await navigator.share({
          title: "My HOL Guard stats",
          text: "See my Guard protection stats.",
          url: publicUrl,
        });
        return;
      } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
          return;
        }
      }
    }
    await handleCopy();
  }, [handleCopy, publicUrl]);

  const xShareUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent("My HOL Guard protection stats")}&url=${encodeURIComponent(publicUrl)}`;

  return (
    <GuardModalLayer ariaLabel="Share link ready" onClose={onClose} panelClassName="w-full max-w-md">
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xl">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-brand-dark">Share link ready</h2>
            <p className="mt-1 text-sm text-slate-500">Your public stats card is live on HOL Guard Cloud.</p>
          </div>
          <button type="button" onClick={onClose} className="text-sm font-medium text-slate-500 hover:text-brand-dark">
            Close
          </button>
        </div>

        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600 break-all">
          {publicUrl}
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark hover:bg-slate-50"
          >
            {copied ? <FiCheck className="h-4 w-4 text-emerald-500" /> : <FiCopy className="h-4 w-4" />}
            {copied ? "Copied" : "Copy link"}
          </button>
          <button
            type="button"
            onClick={handleNativeShare}
            className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark hover:bg-slate-50"
          >
            <FiShare2 className="h-4 w-4" />
            Share
          </button>
          <a
            href={xShareUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark hover:bg-slate-50"
          >
            Post on X
          </a>
        </div>
      </div>
    </GuardModalLayer>
  );
}
