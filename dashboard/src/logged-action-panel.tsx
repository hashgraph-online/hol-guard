import { useCallback, useEffect, useMemo, useState } from "react";
import {
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniClipboard,
  HiMiniClipboardDocumentCheck,
} from "react-icons/hi2";

import { useCopyFeedbackTimeout } from "./use-copy-feedback-timeout";

const EXPAND_CHAR_THRESHOLD = 180;
const EXPAND_LINE_THRESHOLD = 4;

export function shouldOfferLoggedActionExpand(text: string): boolean {
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    return false;
  }
  if (trimmed.length > EXPAND_CHAR_THRESHOLD) {
    return true;
  }
  return trimmed.split(/\r?\n/).length > EXPAND_LINE_THRESHOLD;
}

export function LoggedActionPanel(props: {
  label: string;
  text: string;
  copyAriaLabel?: string;
  expandAriaLabel?: string;
  collapseAriaLabel?: string;
}) {
  const canExpand = useMemo(() => shouldOfferLoggedActionExpand(props.text), [props.text]);
  const [expanded, setExpanded] = useState(!canExpand);
  const { copied, flashCopied, resetCopied } = useCopyFeedbackTimeout(2000);

  useEffect(() => {
    setExpanded(!canExpand);
    resetCopied();
  }, [canExpand, props.text, resetCopied]);

  const handleCopy = useCallback(async () => {
    if (!navigator.clipboard?.writeText) {
      resetCopied();
      return;
    }
    try {
      await navigator.clipboard.writeText(props.text);
      flashCopied();
    } catch {
      resetCopied();
    }
  }, [flashCopied, props.text, resetCopied]);

  const handleToggleExpanded = useCallback(() => {
    setExpanded((value) => !value);
  }, []);

  return (
    <div className="overflow-hidden rounded-xl bg-[#0f172a]">
      <div className="flex min-h-11 flex-wrap items-center gap-1.5 border-b border-white/10 px-3 py-2 sm:flex-nowrap">
        <span className="h-2.5 w-2.5 rounded-full bg-brand-purple" />
        <span className="h-2.5 w-2.5 rounded-full bg-brand-blue" />
        <span className="h-2.5 w-2.5 rounded-full bg-brand-green" />
        <span className="ml-2 min-w-0 flex-1 truncate font-mono text-[10px] uppercase tracking-[0.2em] text-white/45">
          {props.label}
        </span>
        <span className="ml-auto flex shrink-0 items-center gap-1.5">
          <button
            type="button"
            onClick={handleCopy}
            aria-label={props.copyAriaLabel ?? `Copy full ${props.label.toLowerCase()} to clipboard`}
            className="inline-flex h-7 shrink-0 items-center gap-1 rounded-lg border border-white/15 bg-white/[0.08] px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-white/70 transition-colors hover:border-white/25 hover:bg-white/15 hover:text-white focus-visible:outline-white/50"
          >
            {copied ? (
              <HiMiniClipboardDocumentCheck className="h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <HiMiniClipboard className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            <span className="hidden sm:inline">{copied ? "Copied" : "Copy"}</span>
          </button>
          {canExpand ? (
            <button
              type="button"
              onClick={handleToggleExpanded}
              aria-label={
                expanded
                  ? (props.collapseAriaLabel ?? `Collapse full ${props.label.toLowerCase()}`)
                  : (props.expandAriaLabel ?? `Expand full ${props.label.toLowerCase()}`)
              }
              aria-expanded={expanded}
              className="inline-flex h-7 shrink-0 items-center gap-1 rounded-lg border border-white/15 bg-white/[0.08] px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-white/70 transition-colors hover:border-white/25 hover:bg-white/15 hover:text-white focus-visible:outline-white/50"
            >
              {expanded ? (
                <HiMiniChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
              ) : (
                <HiMiniChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
              )}
              <span className="hidden sm:inline">{expanded ? "Collapse" : "Expand"}</span>
            </button>
          ) : null}
        </span>
      </div>
      <div className="relative">
        <pre
          className={`whitespace-pre-wrap break-words px-3 py-3 font-mono text-[13px] leading-6 text-white/90 sm:text-sm ${
            expanded
              ? "max-h-[min(34rem,48vh)] overflow-auto [scrollbar-gutter:stable]"
              : "max-h-40 overflow-hidden"
          }`}
        >
          {props.text}
        </pre>
        {canExpand && !expanded ? (
          <div className="pointer-events-none absolute inset-x-0 bottom-0 h-14 bg-gradient-to-t from-[#0f172a] to-transparent" />
        ) : null}
      </div>
    </div>
  );
}
