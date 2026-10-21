import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniNoSymbol,
} from "react-icons/hi2";
import { ActionButton, Badge, EmptyState, SectionLabel } from "./approval-center-primitives";
import {
  buildRetryAfterApprovalCopy,
  formatRelativeTime,
  harnessDisplayName,
  isWatchOnlyObservation,
  requestResolutionBlockReason,
} from "./approval-center-utils";
import {
  oneTimeRetryWindowMinutes,
  receiptDescribesRequest,
  retryCannotReuseApproval,
  retryCannotReuseApprovalHint,
} from "./approval-retry-guidance";
import { GuardRequestResolutionError } from "./guard-api";
import { ApprovalPasswordModal } from "./approval-center-review-cards";
import {
  approvalDecisionContractKey,
  approvalDecisionSubjectKey,
  advancedScopeChoicesForRequest,
  buildDecisionPayload,
  normalizeDecisionScope,
  recommendedScopeForAction,
  scopeChoicesForRequest,
  standardScopeChoicesForRequest,
  taskCapabilityExplanation,
  willPersistExactAction,
} from "./approval-scopes";
import { ApprovalGateRecommendationNotice, approvalGateNeedsSetup } from "./approval-proof-inline";
import { guardAwareHref } from "./guard-api";
import { ConsolidatedEvidenceAlert } from "./consolidated-evidence-alert";
import { plainEnglishRequestTitle } from "./evidence/plain-english";
import type { DecisionScope, GuardApprovalGatePublicConfig, GuardApprovalRequest } from "./guard-types";
import { guardActionPresentation } from "./guard-action";
import { buildEvidenceItems, buildTopAlertItems } from "./review-evidence";
import {
  allowButtonLabel,
  blockButtonLabel,
  ReviewScopeControls,
} from "./review-scope-controls";
import { buildWhatWouldHappen, pastDecisionVerb, PrimaryActionCard } from "./review-states";
import type { ReviewViewModel, ReviewWorkspaceProps } from "./review-workspace";
import { BusinessReviewSummaryPanel } from "./business-review-summary-panel";
import { ApprovalExtensionRecommendationCard } from "./approval-extension-recommendation-card";
import { useReviewDecisionResolve } from "./use-review-decision-resolve";
import { approvalLeftActionStopped } from "./evidence/approval-outcome";

const commonScopeValues = new Set<DecisionScope>(["artifact", "workspace"]);

function resolvedActionCopy(
  item: GuardApprovalRequest | null,
  action: "allow" | "block",
  persistedExactAction: boolean,
): string {
  if (item !== null) return buildRetryAfterApprovalCopy(item, action, persistedExactAction);
  if (action === "allow") return "Approved: action can proceed";
  return "Blocked: action stopped";
}

export function ReviewDecisionCard(props: {
  detail: ReviewViewModel | null;
  detailError?: string | null;
  detailLoading?: boolean;
  onRetryDetail?: () => void;
  onResolve: ReviewWorkspaceProps["onResolve"];
  onGoHome: () => void;
  approvalGate: GuardApprovalGatePublicConfig | null;
}) {
  const detail = props.detail;
  const item = detail?.item ?? null;
  const resolutionBlockReason = item ? requestResolutionBlockReason(item) : null;
  const [allowScope, setAllowScope] = useState<DecisionScope>("artifact");
  const [blockScope, setBlockScope] = useState<DecisionScope>("artifact");
  const [showConsequences, setShowConsequences] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);
  const [extensionDialogActive, setExtensionDialogActive] = useState(false);
  const [rememberExactAction, setRememberExactAction] = useState(false);
  const allowButtonRef = useRef<HTMLButtonElement>(null);
  const availableScopeChoices = useMemo(
    () => (item ? standardScopeChoicesForRequest(item, "allow") : []),
    [item]
  );
  const commonScopeOptions = useMemo(
    () => availableScopeChoices.filter((choice) => commonScopeValues.has(choice.value)),
    [availableScopeChoices]
  );
  const broaderScopeOptions = useMemo(
    () => availableScopeChoices.filter((choice) => !commonScopeValues.has(choice.value)),
    [availableScopeChoices]
  );
  const advancedScopeOptions = useMemo(
    () => (item ? advancedScopeChoicesForRequest(item, "allow") : []),
    [item]
  );
  const blockScopeOptions = useMemo(
    () => (item ? scopeChoicesForRequest(item, "block") : []),
    [item],
  );
  const taskCapabilityCopy = item ? taskCapabilityExplanation(item) : null;
  const watchOnlyObservation = item !== null && isWatchOnlyObservation(item);
  const hasAllowScope = availableScopeChoices.length + advancedScopeOptions.length > 0;
  const canSubmitAllow = hasAllowScope && (item === null || !retryCannotReuseApproval(item) ||
    (allowScope === "artifact" && rememberExactAction && item.exact_action_persistence_eligible === true));
  const decisionContractKey = item ? approvalDecisionContractKey(item) : null;
  const decisionSubjectKey = item ? approvalDecisionSubjectKey(item) : null;

  useEffect(() => {
    if (item) {
      setAllowScope(recommendedScopeForAction(item, "allow") ?? "artifact");
      setBlockScope(recommendedScopeForAction(item, "block") ?? "artifact");
      setRememberExactAction(false);
    }
  }, [decisionSubjectKey]);

  useEffect(() => {
    if (!item) return;
    setAllowScope((current) =>
      normalizeDecisionScope(item, "allow", current) ?? recommendedScopeForAction(item, "allow") ?? "artifact"
    );
    setBlockScope((current) =>
      normalizeDecisionScope(item, "block", current) ?? recommendedScopeForAction(item, "block") ?? "artifact"
    );
    if (item.exact_action_persistence_eligible !== true) {
      setRememberExactAction(false);
    }
  }, [decisionContractKey]);

  const {
    approvalGate,
    approvalPassword,
    approvalTotpCode,
    errorMessage,
    handleAllow,
    handleApprovalPasswordChange,
    handleApprovalTotpCodeChange,
    handleBlock,
    handleModalCancel,
    handleModalSubmit,
    handleRetryLastAction,
    handleUseCooldownChange,
    pendingAction,
    resolved,
    setResolved,
    submitting,
    useCooldown,
  } = useReviewDecisionResolve({
    item,
    approvalGate: props.approvalGate,
    onResolve: props.onResolve,
    resolutionBlockReason,
    allowScope,
    blockScope,
    setAllowScope,
    availableScopeChoices,
    blockScopeOptions,
    hasAllowScope,
    canSubmitAllow,
    watchOnlyObservation,
    rememberExactAction,
    extensionDialogActive,
    decisionContractKey,
    decisionSubjectKey,
  });

  const handleToggleConsequences = useCallback(() => {
    setShowConsequences((visible) => !visible);
  }, []);
  const handleToggleEvidence = useCallback(() => {
    setShowEvidence((visible) => !visible);
  }, []);
  const reviewedRequestId = item?.request_id ?? null;
  const handleExtensionApproved = useCallback(
    (message: string) => {
      if (reviewedRequestId === null) return;
      setResolved({ requestId: reviewedRequestId, action: "allow", persistedExactAction: false, message });
    },
    [reviewedRequestId],
  );

  if (!detail || !item) {
    if (props.detailError) {
      return <section role="alert" className="rounded-xl border border-brand-attention/30 bg-brand-attention/[0.06] p-5">
        <h3 className="text-lg font-semibold text-brand-dark">Request details are unavailable</h3>
        <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{props.detailError}</p>
        {props.onRetryDetail && <ActionButton className="mt-4" variant="outline" onClick={props.onRetryDetail}>
          Refresh request
        </ActionButton>}
      </section>;
    }
    if (props.detailLoading) {
      return <div aria-busy="true" aria-live="polite" className="p-5 text-sm text-brand-dark/80">
        Loading request details…
      </div>;
    }
    return (
      <EmptyState
        title="Select an action"
        body="Choose an action or Watch-only finding to review."
        tone="teach"
      />
    );
  }

  const nativeDisplayOnly = item.native_business_review_display_only === true;
  const versionBoundScript = item.artifact_type === "native_bash_request";
  const plainTitle = nativeDisplayOnly ? item.artifact_name : plainEnglishRequestTitle(item);
  const harnessName = harnessDisplayName(item.harness);
  const whatWouldHappen = nativeDisplayOnly ? null : buildWhatWouldHappen(item);
  const topAlertItems = nativeDisplayOnly ? [] : buildTopAlertItems(item);
  const evidenceItems = nativeDisplayOnly ? [] : buildEvidenceItems(item);
  const actionPresentation = guardActionPresentation(item.policy_action);
  let sectionLabel = "Paused action";
  let badgeLabel = actionPresentation.label;
  if (nativeDisplayOnly) {
    sectionLabel = "Saved request";
    badgeLabel = "Read-only";
  } else if (watchOnlyObservation) {
    sectionLabel = "Watch-only finding";
    badgeLabel = "Would have stopped";
  }
  const persistExactAllow = item !== null && willPersistExactAction(item, "allow", allowScope, rememberExactAction);
  const persistExactBlock = item !== null && willPersistExactAction(item, "block", blockScope, watchOnlyObservation);
  let resolvedAllowButtonLabel = allowButtonLabel(allowScope, versionBoundScript, persistExactAllow);
  if (watchOnlyObservation) {
    resolvedAllowButtonLabel = "Keep allowing";
  } else if (persistExactAllow && !versionBoundScript) {
    resolvedAllowButtonLabel = "Approve and remember";
  } else if (retryCannotReuseApproval(item)) {
    resolvedAllowButtonLabel = "Choose an available approval duration";
  }
  let resolvedBlockButtonLabel = blockButtonLabel(blockScope);
  if (watchOnlyObservation || persistExactBlock) {
    resolvedBlockButtonLabel = "Stop this next time";
  }
  return (
    <div className="min-w-0 space-y-5">
      {resolved && (
        <div
          className={`guard-fade-in flex items-center gap-3 rounded-xl border px-4 py-3 transition-all ${
            resolved.action === "allow"
              ? "border-brand-green/25 bg-brand-green-bg/30"
              : "border-brand-attention/25 bg-brand-attention/[0.04]"
          }`}
          role="status"
          aria-live="polite"
        >
          <HiMiniCheckCircle
            className={`h-5 w-5 shrink-0 ${resolved.action === "allow" ? "text-brand-green" : "text-brand-attention"}`}
            aria-hidden="true"
          />
          <p className={`text-sm font-medium ${resolved.action === "allow" ? "text-brand-green-text" : "text-brand-attention"}`}>
            {resolved.message ?? resolvedActionCopy(item, resolved.action, resolved.persistedExactAction)}
          </p>
        </div>
      )}

      <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            {!nativeDisplayOnly && <SectionLabel>{sectionLabel}</SectionLabel>}
            <h2 className={`${nativeDisplayOnly ? "" : "mt-2 "}text-lg font-semibold text-brand-dark`}>{plainTitle}</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              From {harnessName}
            </p>
          </div>
          <Badge tone={item.native_business_review_display_only || watchOnlyObservation ? "info" : actionPresentation.tone}>
            {badgeLabel}
          </Badge>
        </div>

        {!nativeDisplayOnly && <PrimaryActionCard item={item} />}
        {nativeDisplayOnly && <BusinessReviewSummaryPanel key={item.request_id} requestId={item.request_id} />}
        {resolved === null && retryCannotReuseApproval(item) && !rememberExactAction ? (
          <p className="mt-4 text-sm leading-6 text-brand-dark">
            {retryCannotReuseApprovalHint(item, harnessName)}
          </p>
        ) : null}
        {item.scope_restrictions?.includes("provider_account_unverified_once_only") ? (
          <p className="mt-4 text-sm leading-6 text-brand-dark">
            Guard cannot verify this provider account. Approval applies once to this exact call; remembered approvals are unavailable.
          </p>
        ) : null}

        {resolutionBlockReason !== null && (
          <div className="mt-5 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.06] p-4" role="alert">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle
                className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention"
                aria-hidden="true"
              />
              <div>
                <p className="text-sm font-semibold text-brand-attention">
                  {item.native_business_review_display_only ? "Review is not connected yet" : "This decision cannot be overridden"}
                </p>
                <p className="mt-1 text-sm text-brand-dark">{resolutionBlockReason}</p>
                {item.superseded_by_request_id ? (
                  <a className="mt-3 inline-flex min-h-11 items-center font-semibold text-brand-blue underline"
                    href={guardAwareHref(`/requests/${encodeURIComponent(item.superseded_by_request_id)}`)}>
                    Open the fresh review
                  </a>
                ) : null}
              </div>
            </div>
          </div>
        )}

        {topAlertItems.length > 0 && (
          <div className="mt-5 rounded-xl border border-slate-100 bg-slate-50/50 p-4">
            <ConsolidatedEvidenceAlert key={item.request_id} items={topAlertItems} />
          </div>
        )}

        {whatWouldHappen && (
          <div className="mt-5">
            <button
              type="button"
              onClick={handleToggleConsequences}
              className="flex items-center gap-2 text-sm font-medium text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 rounded-lg px-2 py-1 -ml-2"
              aria-expanded={showConsequences}
            >
              <HiMiniInformationCircle className="h-4 w-4" aria-hidden="true" />
              {watchOnlyObservation ? "What Protected mode would do" : "What would happen without Guard?"}
              {showConsequences ? (
                <HiMiniChevronUp className="h-3 w-3" aria-hidden="true" />
              ) : (
                <HiMiniChevronDown className="h-3 w-3" aria-hidden="true" />
              )}
            </button>
            {showConsequences && (
              <div className="mt-3 rounded-xl border border-slate-200/70 bg-slate-50 p-4">
                <p className="text-sm text-brand-dark">{whatWouldHappen}</p>
              </div>
            )}
          </div>
        )}

        {resolutionBlockReason === null && resolved === null && !watchOnlyObservation && (
          <ApprovalExtensionRecommendationCard
            key={item.request_id}
            item={item}
            approvalGate={approvalGate}
            allowScope={allowScope}
            persistExactAction={persistExactAllow}
            disabled={!canSubmitAllow || submitting !== null || pendingAction !== null}
            onResolve={props.onResolve}
            onApproved={handleExtensionApproved}
            onDialogActiveChange={setExtensionDialogActive}
          />
        )}

        {resolutionBlockReason === null && resolved === null && (
          <ReviewScopeControls
            commonScopeOptions={commonScopeOptions}
            broaderScopeOptions={broaderScopeOptions}
            advancedScopeOptions={advancedScopeOptions}
            blockScopeOptions={blockScopeOptions}
            hasAllowScope={hasAllowScope}
            taskCapabilityCopy={taskCapabilityCopy}
            exactActionPersistenceEligible={item.exact_action_persistence_eligible === true}
            versionBoundScript={versionBoundScript}
            rememberExactAction={rememberExactAction}
            oneTimeRetryBlocked={retryCannotReuseApproval(item)}
            retryWindowMinutes={oneTimeRetryWindowMinutes(item)}
            allowScope={allowScope}
            blockScope={blockScope}
            onAllowScopeChange={setAllowScope}
            onBlockScopeChange={setBlockScope}
            onRememberExactActionChange={setRememberExactAction}
          />
        )}
        {errorMessage && (
          <div className="guard-fade-in mt-4 rounded-xl border border-brand-purple/25 bg-brand-purple/[0.05] p-4">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-purple" aria-hidden="true" />
              <div className="flex-1">
                <p className="text-sm text-brand-purple">{errorMessage}</p>
                <button
                  type="button"
                  onClick={handleRetryLastAction}
                  className="mt-2 inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
                >
                  Retry
                </button>
              </div>
            </div>
          </div>
        )}

        {resolutionBlockReason === null && resolved === null && <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2">
          {hasAllowScope && <ActionButton
            ref={allowButtonRef}
            variant="success"
            onClick={handleAllow}
            disabled={!canSubmitAllow || submitting !== null || pendingAction !== null}
          >
            {submitting === "allow" ? (
              <span className="flex items-center gap-2">
                <HiMiniArrowPath className="h-4 w-4 animate-spin" aria-hidden="true" />
                Approving...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
                {resolvedAllowButtonLabel}
              </span>
            )}
          </ActionButton>}
          <ActionButton
            variant="outline"
            onClick={handleBlock}
            disabled={blockScopeOptions.length === 0 || submitting !== null || pendingAction !== null}
          >
            {submitting === "block" ? (
              <span className="flex items-center gap-2">
                <HiMiniArrowPath className="h-4 w-4 animate-spin" aria-hidden="true" />
                Blocking...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <HiMiniNoSymbol className="h-4 w-4" aria-hidden="true" />
                {resolvedBlockButtonLabel}
              </span>
            )}
          </ActionButton>
        </div>}
        {resolutionBlockReason === null && resolved === null && approvalGateNeedsSetup(approvalGate) && (
          <ApprovalGateRecommendationNotice />
        )}
      </div>

      {evidenceItems.length > 0 && (
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <button
            type="button"
            onClick={handleToggleEvidence}
            className="flex w-full items-center justify-between text-left focus:outline-none focus:ring-2 focus:ring-brand-blue/20 rounded-lg px-2 py-1 -ml-2"
            aria-expanded={showEvidence}
          >
            <SectionLabel>Review details</SectionLabel>
            {showEvidence ? (
              <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
            ) : (
              <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
            )}
          </button>
          {showEvidence && (
            <div className="mt-4">
              <ConsolidatedEvidenceAlert key={item.request_id} items={evidenceItems} />
            </div>
          )}
        </div>
      )}

      {detail.receipt && receiptDescribesRequest(item, detail.receipt) && (
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <SectionLabel>Last time</SectionLabel>
          <p className="mt-2 text-sm text-muted-foreground">
            {approvalLeftActionStopped(detail.receipt) ? (
              <>
                You approved a similar action once {formatRelativeTime(detail.receipt.timestamp)}, but it stayed
                stopped.
              </>
            ) : (
              <>
                You previously {pastDecisionVerb(detail.receipt.policy_decision)} a similar action{" "}
                {formatRelativeTime(detail.receipt.timestamp)}.
              </>
            )}
          </p>
          {detail.diff && detail.diff.changed_fields.length > 0 && (
            <div className="mt-3 rounded-xl border border-slate-200/70 bg-slate-50 p-4">
              <p className="text-sm font-medium text-brand-dark">What changed since then:</p>
              <ul className="mt-2 space-y-1">
                {detail.diff.changed_fields.map((field) => (
                  <li key={field} className="flex items-center gap-2 text-sm text-brand-dark">
                    <HiMiniCheckCircle className="h-3.5 w-3.5 shrink-0 text-brand-blue" aria-hidden="true" />
                    {field}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {pendingAction !== null && approvalGate !== null && (
        <ApprovalPasswordModal
          gate={approvalGate}
          approvalPassword={approvalPassword}
          approvalTotpCode={approvalTotpCode}
          useCooldown={useCooldown}
          onApprovalPasswordChange={handleApprovalPasswordChange}
          onApprovalTotpCodeChange={handleApprovalTotpCodeChange}
          onUseCooldownChange={handleUseCooldownChange}
          onSubmit={handleModalSubmit}
          busy={submitting !== null}
          onCancel={handleModalCancel}
          submitLabel={pendingAction === "allow" ? resolvedAllowButtonLabel : resolvedBlockButtonLabel}
        />
      )}
    </div>
  );
}
