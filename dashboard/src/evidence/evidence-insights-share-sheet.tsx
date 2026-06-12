"use client";

import { useCallback } from "react";
import { FiCheck, FiCopy, FiShare2 } from "react-icons/fi";
import { GuardModalLayer } from "../guard-modal-layer";
import { useCopyFeedbackTimeout } from "../use-copy-feedback-timeout";

interface EvidenceInsightsShareSheetProps {
  publicUrl: string;
  onClose: () => void;
}

export function EvidenceInsightsShareSheet({ publicUrl, onClose }: EvidenceInsightsShareSheetProps) {
  const { copied, flashCopied, resetCopied } = useCopyFeedbackTimeout(2000);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(publicUrl);
      flashCopied();
    } catch {
      resetCopied();
    }
  }, [flashCopied, publicUrl, resetCopied]);

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

        <div className="mt-4 rounded-xl border border-brand-blue/10 bg-gradient-to-br from-white to-[#f0f6ff] px-4 py-3">
          <p className="text-sm font-medium text-brand-dark">A referral link is shown on your public stats page.</p>
          <p className="mt-1 text-xs text-slate-500">
            Visitors who sign up through it get 20% off HOL Guard Pro or Team for 12 months. Track referrals and payouts in the{" "}
            <a
              href="https://hol.org/guard/affiliate"
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium text-brand-blue hover:underline"
            >
              affiliate dashboard
            </a>
            .
          </p>
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
