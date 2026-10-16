import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { HiMiniArrowTopRightOnSquare, HiMiniExclamationTriangle, HiMiniSparkles } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { approvalExtensionRecommendationCopy } from "./approval-extension-recommendation";
import {
  approvalGateIsLocked,
  approvalGateLockRemainingSeconds,
  approvalGateRequiredForResolution,
} from "./approval-gate-utils";
import { approvalGateProofReady } from "./approval-proof-inline";
import { ApprovalProofModal } from "./approval-proof-modal";
import { buildDecisionPayload } from "./approval-scopes";
import {
  approveWithExtensionAllow,
  defaultExtensionAllowDeps,
  extensionAllowFailureMessage,
  type ExtensionAllowCredentials,
} from "./approve-with-extension-allow";
import { commitDashboardLocation } from "./dashboard-location";
import { extensionPatternHref } from "./extension-pattern-href";
import type { DecisionScope, GuardApprovalGatePublicConfig, GuardApprovalRequest } from "./guard-types";
import type { ReviewWorkspaceProps } from "./review-workspace";

export function ApprovalExtensionRecommendationCard(props: {
  item: GuardApprovalRequest;
  approvalGate: GuardApprovalGatePublicConfig | null;
  allowScope: DecisionScope;
  disabled: boolean;
  onResolve: ReviewWorkspaceProps["onResolve"];
  onApproved: (message: string) => void;
  /** Lets the parent pause its own decision shortcuts while this dialog is open or saving. */
  onDialogActiveChange?: (active: boolean) => void;
}) {
  const recommendation = props.item.extension_recommendation;
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  // Set synchronously so a second submit before the re-render cannot start another save.
  const inFlight = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);
  const copy = useMemo(
    () => (recommendation ? approvalExtensionRecommendationCopy(recommendation) : null),
    [recommendation],
  );
  const primary = recommendation?.permissions[0] ?? null;
  const { item, allowScope, approvalGate, onResolve, onApproved, onDialogActiveChange } = props;
  const dialogActive = confirmOpen || busy;
  useEffect(() => {
    onDialogActiveChange?.(dialogActive);
  }, [dialogActive, onDialogActiveChange]);
  useEffect(() => () => onDialogActiveChange?.(false), [onDialogActiveChange]);

  const openPattern = useCallback(() => {
    if (primary) commitDashboardLocation(extensionPatternHref(primary.extension_id, primary.rule_id));
  }, [primary]);
  const openConfirm = useCallback(() => {
    setError(null);
    setConfirmOpen(true);
  }, []);
  const closeConfirm = useCallback(() => {
    if (!busy) setConfirmOpen(false);
  }, [busy]);

  const confirm = useCallback(
    (credentials: ExtensionAllowCredentials) => {
      if (!recommendation || !copy || inFlight.current) return;
      inFlight.current = true;
      setBusy(true);
      setError(null);
      void (async () => {
        try {
          const outcome = await approveWithExtensionAllow(
            {
              ...defaultExtensionAllowDeps,
              resolve: async (proof) => {
                await onResolve({
                  ...buildDecisionPayload({
                    item,
                    action: "allow",
                    scope: allowScope,
                    reason: "approved in review; extension setting allowed",
                    persistExactAction: false,
                  }),
                  ...(approvalGateRequiredForResolution(approvalGate, "allow", allowScope) ? proof : {}),
                });
              },
            },
            recommendation.permissions.map((permission) => permission.permission_id),
            credentials,
          );
          setConfirmOpen(false);
          if (outcome.status === "approved") {
            onApproved(copy.successMessage);
          } else {
            setSavedMessage(outcome.message);
          }
        } catch (caught) {
          setError(extensionAllowFailureMessage(caught));
        } finally {
          inFlight.current = false;
          setBusy(false);
        }
      })();
    },
    [allowScope, approvalGate, copy, item, onApproved, onResolve, recommendation],
  );

  if (!recommendation || !copy || !primary) return null;

  const caution = recommendation.caution;
  const authorityUnavailable = recommendation.status === "authority_unavailable";
  const gateReady = approvalGateProofReady(approvalGate);
  const gateLocked = approvalGateIsLocked(approvalGate);
  const tone = caution
    ? "border-brand-attention/30 bg-brand-attention/[0.05]"
    : "border-brand-blue/20 bg-brand-blue/[0.04]";

  return (
    <section
      className={`mt-5 rounded-xl border p-4 ${tone}`}
      aria-labelledby="approval-extension-recommendation-title"
      data-testid="approval-extension-recommendation"
    >
      <div className="flex items-start gap-3">
        {caution ? (
          <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
        ) : (
          <HiMiniSparkles className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" aria-hidden="true" />
        )}
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Recommended setting</p>
          <h3 id="approval-extension-recommendation-title" className="mt-1 text-sm font-semibold text-brand-dark">
            {copy.title}
          </h3>
          <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">{copy.body}</p>
          {copy.cautionLines.length > 0 && (
            <ul className="mt-2 space-y-1" aria-label="Before you allow this">
              {copy.cautionLines.map((line) => (
                <li key={line} className="text-sm font-medium text-brand-attention">
                  {line}
                </li>
              ))}
            </ul>
          )}
          {authorityUnavailable && (
            <p className="mt-2 text-sm text-brand-dark/80">
              Protection settings need attention before Guard can change them from here.
            </p>
          )}
          {savedMessage && (
            <p className="mt-2 text-sm font-medium text-brand-green-text" role="status">
              {savedMessage}
            </p>
          )}
          {error && !confirmOpen && (
            <p className="mt-2 text-sm text-brand-purple" role="alert">
              {error}
            </p>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {!authorityUnavailable && savedMessage === null && gateReady && (
              <ActionButton
                variant={caution ? "outline" : "primary"}
                onClick={openConfirm}
                disabled={props.disabled || busy || gateLocked}
              >
                {copy.primaryLabel}
              </ActionButton>
            )}
            {!authorityUnavailable && savedMessage === null && !gateReady && (
              <ActionButton href="/settings?section=approval" variant="outline">
                Set up approval password
              </ActionButton>
            )}
            <button
              type="button"
              onClick={openPattern}
              className="inline-flex min-h-9 items-center gap-1 rounded-lg px-2 text-sm font-medium text-brand-blue underline-offset-2 hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            >
              {copy.configureLabel}
              <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
          {gateReady && gateLocked && !authorityUnavailable && (
            <p className="mt-2 text-xs text-slate-500">
              Approval gate is temporarily locked. Try again in {approvalGateLockRemainingSeconds(approvalGate)} seconds.
            </p>
          )}
          {!gateReady && !authorityUnavailable && (
            <p className="mt-2 text-xs text-slate-500">
              Changing protection settings needs an approval password so agents cannot change them on their own.
            </p>
          )}
        </div>
      </div>
      {confirmOpen && (
        <ApprovalProofModal
          title={copy.confirmTitle}
          detail={caution ? `${copy.confirmDetail} ${copy.cautionLines.join(" ")}` : copy.confirmDetail}
          confirmLabel={copy.primaryLabel}
          approvalGate={approvalGate}
          busy={busy}
          busyLabel="Saving and approving…"
          error={error}
          onCancel={closeConfirm}
          onConfirm={confirm}
        />
      )}
    </section>
  );
}
