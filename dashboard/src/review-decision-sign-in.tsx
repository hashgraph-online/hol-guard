import { useCallback, useEffect, useId, useRef, useState } from "react";
import { HiMiniLockClosed } from "react-icons/hi2";

import { ActionButton } from "./approval-center-primitives";
import type { DecisionSignInReason } from "./dashboard-session-scope";
import { approvalsOpenCommand, desktopRequestUrl } from "./queue-connection-copy";

type SignInCopy = { headline: string; detail: string };

/** What the panel says for each reason this tab cannot decide a request. */
export function decisionSignInCopy(reason: DecisionSignInReason): SignInCopy {
  switch (reason) {
    case "other_request":
      return {
        headline: "This tab is signed in for a different request",
        detail:
          "The link you opened earlier lets this tab decide only that request. Open this one from Guard on this device to approve or block it.",
      };
    case "expired":
      return {
        headline: "Your session for this request has ended",
        detail:
          "Guard sessions last a limited time and end when Guard restarts. Open the request from Guard on this device again to get a new one.",
      };
    case "no_session":
      return {
        headline: "Sign in to approve or block this request",
        detail:
          "You can read the request here, but Guard saves a decision only from a signed local session. Open the request from Guard on this device to sign in.",
      };
  }
}

export const DECISION_SIGN_IN_RECHECK_HINT =
  "Once it opens signed in, this tab picks up the session. If it does not, check again.";

/**
 * Shown in place of Approve and Block when this tab's session cannot decide
 * the request. Every route here goes through Guard on this device, which
 * proves the person deciding is the local user; the tab never asks for a
 * secret and never decides anything itself.
 */
export function ReviewDecisionSignIn(props: {
  requestId: string;
  reason: DecisionSignInReason;
  onRecheck: () => void;
}) {
  const headingId = useId();
  const { headline, detail } = decisionSignInCopy(props.reason);
  const desktopUrl = desktopRequestUrl(props.requestId);
  const openCommand = approvalsOpenCommand(props.requestId);
  const [copied, setCopied] = useState(false);
  const copiedTimer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (copiedTimer.current !== null) window.clearTimeout(copiedTimer.current);
    },
    [],
  );

  const handleCopy = useCallback(() => {
    if (openCommand === null || navigator.clipboard === undefined) return;
    void navigator.clipboard.writeText(openCommand).then(
      () => {
        setCopied(true);
        if (copiedTimer.current !== null) window.clearTimeout(copiedTimer.current);
        copiedTimer.current = window.setTimeout(() => setCopied(false), 2000);
      },
      () => {},
    );
  }, [openCommand]);

  return (
    <section
      aria-labelledby={headingId}
      aria-live="polite"
      className="guard-fade-in mt-6 rounded-xl border border-slate-200 bg-slate-50 p-4 sm:p-5"
      data-testid="review-decision-sign-in"
    >
      <div className="flex items-start gap-3">
        <HiMiniLockClosed className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <h3 id={headingId} className="text-sm font-semibold text-brand-dark">
            {headline}
          </h3>
          <p className="mt-1 max-w-prose text-sm text-slate-600">{detail}</p>

          <div className="mt-4 flex flex-wrap gap-3">
            {desktopUrl !== null && <ActionButton href={desktopUrl}>Open in HOL Guard Desktop</ActionButton>}
            <ActionButton variant="outline" onClick={props.onRecheck}>
              Check again
            </ActionButton>
          </div>

          {openCommand !== null && (
            <div className="mt-4">
              <p className="text-sm text-slate-600">Or run this in a terminal on this device:</p>
              <div className="mt-2 flex items-stretch gap-2">
                <code className="flex min-h-10 min-w-0 flex-1 items-center overflow-x-auto rounded-lg border border-slate-200 bg-white px-3 font-mono text-sm text-brand-dark select-all">
                  {openCommand}
                </code>
                <ActionButton variant="outline" onClick={handleCopy}>
                  <span aria-live="polite">{copied ? "Copied" : "Copy"}</span>
                </ActionButton>
              </div>
            </div>
          )}
          <p className="mt-3 text-xs text-slate-500">{DECISION_SIGN_IN_RECHECK_HINT}</p>
        </div>
      </div>
    </section>
  );
}
