import { HiMiniKey } from "react-icons/hi2";
import { approvalGateProofReady } from "../approval-proof-inline";
import { guardAwareHref } from "../guard-api";
import type { GuardApprovalGatePublicConfig, GuardApprovalRequest, GuardBrowserProfileLineV1 } from "../guard-types";
import { parseBrowserCard } from "../mcp-call/browser-card";

/** Profiles the agent shares with the person, so a page it opens there is one it can reach. */
/** The approval setup page, with the Guard session when a browser renders it. */
function approvalSetupHref(): string {
  const href = "/settings?section=approval";
  return typeof window === "undefined" ? href : guardAwareHref(href);
}

const SHARED_PROFILES: ReadonlySet<GuardBrowserProfileLineV1> = new Set(["shared", "remote-debugging"]);

/**
 * R-GATE: a step in the person's own browser, with no password, authenticator
 * or Pulse to prove who approves. A gate that has not loaded asks nothing.
 */
export function browserGateNeedsSetup(
  profile: GuardBrowserProfileLineV1,
  gate: GuardApprovalGatePublicConfig | null | undefined,
): boolean {
  return SHARED_PROFILES.has(profile) && gate != null && !approvalGateProofReady(gate);
}

/** Whether this request's browser card already carries the setup prompt. */
export function browserGatePromptShown(
  item: GuardApprovalRequest,
  gate: GuardApprovalGatePublicConfig | null | undefined,
): boolean {
  const card = parseBrowserCard(item.browser_card);
  return card !== null && browserGateNeedsSetup(card.profile_line, gate);
}

/** One line that links to approval setup. It never replaces or hides a choice. */
export function BrowserGatePrompt() {
  return (
    <p
      role="note"
      data-browser-gate-prompt=""
      className="flex flex-wrap items-center gap-x-2 gap-y-1 border-t border-slate-100 px-4 py-2.5 text-sm text-brand-dark/80 sm:px-5"
    >
      <HiMiniKey className="h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
      <span className="min-w-0 flex-1">The agent uses your own browser. Set up approval so only you can approve.</span>
      <a
        href={approvalSetupHref()}
        className="font-medium text-brand-blue underline-offset-2 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30"
      >
        Set up approval
      </a>
    </p>
  );
}
