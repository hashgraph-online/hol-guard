import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
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
} from "./approval-center-utils";
import { ApprovalPasswordModal } from "./approval-center-review-cards";
import {
  advancedScopeChoicesForRequest,
  buildDecisionPayload,
  recommendedScopeForAction,
  scopeChoicesForRequest,
  standardScopeChoicesForRequest,
  taskCapabilityExplanation,
} from "./approval-scopes";
import { approvalProofRequiresPassword } from "./approval-proof-inline";
import { ConsolidatedEvidenceAlert } from "./consolidated-evidence-alert";
import { plainEnglishRequestTitle } from "./evidence/plain-english";
import type { DecisionScope, GuardApprovalGatePublicConfig } from "./guard-types";
import { requiresApprovalPasswordPrompt } from "./approval-gate-utils";
import { buildEvidenceItems, buildTopAlertItems } from "./review-evidence";
import {
  allowButtonLabel,
  blockButtonLabel,
  ReviewScopeControls,
} from "./review-scope-controls";
import { buildWhatWouldHappen, pastDecisionVerb, PrimaryActionCard } from "./review-states";
import type { ReviewViewModel, ReviewWorkspaceProps } from "./review-workspace";

const commonScopeValues = new Set<DecisionScope>(["artifact"]);

export function ReviewDecisionCard(props: {
  detail: ReviewViewModel | null;
  onResolve: ReviewWorkspaceProps["onResolve"];
  onGoHome: () => void;
  approvalGate: GuardApprovalGatePublicConfig | null;
}) {
  const detail = props.detail;
  const item = detail?.item ?? null;
  const [allowScope, setAllowScope] = useState<DecisionScope>("artifact");
  const [blockScope, setBlockScope] = useState<DecisionScope>("artifact");
  const [submitting, setSubmitting] = useState<"allow" | "block" | null>(null);
  const [resolved, setResolved] = useState<"allow" | "block" | null>(null);
  const [showConsequences, setShowConsequences] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);
  const [lastAction, setLastAction] = useState<"allow" | "block" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [approvalPassword, setApprovalPassword] = useState("");
  const [approvalTotpCode, setApprovalTotpCode] = useState("");
  const [useCooldown, setUseCooldown] = useState(false);
  const [pendingAction, setPendingAction] = useState<"allow" | "block" | null>(null);
  const [pendingContractKey, setPendingContractKey] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
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
  const hasAllowScope = availableScopeChoices.length + advancedScopeOptions.length > 0;
  const decisionContractKey = item
    ? `${item.request_id}:${item.scope_contract_version ?? "legacy"}:${item.scope_contract_digest ?? "legacy"}`
    : null;

  useEffect(() => {
    if (item) {
      setAllowScope(recommendedScopeForAction(item, "allow") ?? "artifact");
      setBlockScope(recommendedScopeForAction(item, "block") ?? "artifact");
      setResolved(null);
      setSubmitting(null);
      setLastAction(null);
      setErrorMessage(null);
      setApprovalPassword("");
      setApprovalTotpCode("");
      setUseCooldown(false);
      setPendingAction(null);
      setPendingContractKey(null);
    }
  }, [item?.request_id, item?.scope_contract_version, item?.scope_contract_digest]);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const handleResolve = useCallback(
    async (action: "allow" | "block") => {
      if (!item) return;
      setSubmitting(action);
      setErrorMessage(null);
      try {
        const requestedScope = action === "allow" ? allowScope : blockScope;
        const gate = props.approvalGate;
        const needsPassword = approvalProofRequiresPassword(gate);
        const includeGateFields =
          gate?.enabled === true &&
          gate?.configured === true &&
          requiresApprovalPasswordPrompt(gate.cooldown_active, gate.strict_all_decisions, requestedScope);
        await props.onResolve({
          ...buildDecisionPayload({
            item,
            action,
            scope: requestedScope,
            reason: action === "allow" ? "approved in review" : "blocked in review",
          }),
          ...(includeGateFields && needsPassword ? { approval_password: approvalPassword } : {}),
          ...(includeGateFields && !needsPassword ? { approval_totp_code: approvalTotpCode } : {}),
          ...(includeGateFields ? { approval_gate_use_cooldown: useCooldown } : {}),
        });
        setResolved(action);
        setApprovalPassword("");
        setApprovalTotpCode("");
        setUseCooldown(false);
        setPendingAction(null);
        setPendingContractKey(null);
        timerRef.current = setTimeout(() => setResolved(null), 2000);
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : "Something went wrong. Try again.");
      } finally {
        setSubmitting(null);
      }
    },
    [
      item,
      allowScope,
      blockScope,
      props.onResolve,
      props.approvalGate,
      approvalPassword,
      approvalTotpCode,
      useCooldown,
    ]
  );

  const handleRequestResolve = useCallback(
    (action: "allow" | "block") => {
      if (action === "allow" && !hasAllowScope) {
        setErrorMessage("This action has no eligible approval scope.");
        return;
      }
      if (action === "block" && blockScopeOptions.length === 0) {
        setErrorMessage("This action has no eligible block scope.");
        return;
      }
      setLastAction(action);
      const requestedScope = action === "allow" ? allowScope : blockScope;
      const gate = props.approvalGate;
      const gateRequiresPassword =
        gate?.enabled === true &&
        gate?.configured === true &&
        requiresApprovalPasswordPrompt(gate.cooldown_active, gate.strict_all_decisions, requestedScope);
      if (gateRequiresPassword) {
        setPendingAction(action);
        setPendingContractKey(decisionContractKey);
        setErrorMessage(null);
        return;
      }
      void handleResolve(action);
    },
    [
      allowScope,
      blockScope,
      blockScopeOptions.length,
      decisionContractKey,
      handleResolve,
      hasAllowScope,
      props.approvalGate,
    ]
  );

  const handleAllow = useCallback(() => {
    handleRequestResolve("allow");
  }, [handleRequestResolve]);
  const handleBlock = useCallback(() => {
    handleRequestResolve("block");
  }, [handleRequestResolve]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (submitting !== null || pendingAction !== null) return;
      const target = event.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return;

      if (event.key === "a" || event.key === "A") {
        event.preventDefault();
        handleRequestResolve("allow");
      }
      if (event.key === "b" || event.key === "B") {
        event.preventDefault();
        handleRequestResolve("block");
      }
      const scopeIndex = parseInt(event.key, 10);
      if (scopeIndex >= 1 && scopeIndex <= availableScopeChoices.length) {
        event.preventDefault();
        setAllowScope(availableScopeChoices[scopeIndex - 1].value);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [availableScopeChoices, handleRequestResolve, pendingAction, submitting]);

  const handleModalSubmit = useCallback(() => {
    if (pendingAction === null) {
      return;
    }
    if (pendingContractKey !== decisionContractKey) {
      setPendingAction(null);
      setPendingContractKey(null);
      setErrorMessage("This request changed while you were reviewing it. Review the current scopes and try again.");
      return;
    }
    void handleResolve(pendingAction);
  }, [decisionContractKey, handleResolve, pendingAction, pendingContractKey]);

  const handleModalCancel = useCallback(() => {
    setPendingAction(null);
    setPendingContractKey(null);
    setApprovalPassword("");
    setApprovalTotpCode("");
    setUseCooldown(false);
  }, []);

  const handleToggleConsequences = useCallback(() => {
    setShowConsequences((visible) => !visible);
  }, []);
  const handleToggleEvidence = useCallback(() => {
    setShowEvidence((visible) => !visible);
  }, []);
  const handleRetryLastAction = useCallback(() => {
    setErrorMessage(null);
    if (lastAction !== null) {
      handleRequestResolve(lastAction);
    }
  }, [handleRequestResolve, lastAction]);

  const handleApprovalPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalPassword(event.target.value);
  }, []);
  const handleApprovalTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalTotpCode(event.target.value);
  }, []);

  const handleUseCooldownChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setUseCooldown(event.target.checked);
  }, []);

  if (!detail || !item) {
    return (
      <EmptyState
        title="Select an action"
        body="Choose a paused action from the queue to review and decide."
        tone="teach"
      />
    );
  }

  const plainTitle = plainEnglishRequestTitle(item);
  const harnessName = harnessDisplayName(item.harness);
  const whatWouldHappen = buildWhatWouldHappen(item);
  const topAlertItems = buildTopAlertItems(item);
  const evidenceItems = buildEvidenceItems(item);
  return (
    <div className="space-y-5">
      {resolved && (
        <div
          className={`guard-fade-in flex items-center gap-3 rounded-xl border px-4 py-3 transition-all ${
            resolved === "allow"
              ? "border-brand-green/25 bg-brand-green-bg/30"
              : "border-brand-attention/25 bg-brand-attention/[0.04]"
          }`}
          role="status"
          aria-live="polite"
        >
          <HiMiniCheckCircle
            className={`h-5 w-5 shrink-0 ${resolved === "allow" ? "text-brand-green" : "text-brand-attention"}`}
            aria-hidden="true"
          />
          <p className={`text-sm font-medium ${resolved === "allow" ? "text-brand-green-text" : "text-brand-attention"}`}>
            {item ? buildRetryAfterApprovalCopy(item, resolved) : (resolved === "allow" ? "Approved: action can proceed" : "Blocked: action stopped")}
          </p>
        </div>
      )}

      <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <SectionLabel>Paused action</SectionLabel>
            <h2 className="mt-2 text-lg font-semibold text-brand-dark">{plainTitle}</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              From {harnessName}
            </p>
          </div>
          <Badge tone={item.policy_action === "block" ? "attention" : "info"}>
            {item.policy_action === "block" ? "Blocked" : "Needs review"}
          </Badge>
        </div>

        <PrimaryActionCard item={item} />

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
              What would happen without Guard?
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

        <ReviewScopeControls
          commonScopeOptions={commonScopeOptions}
          broaderScopeOptions={broaderScopeOptions}
          advancedScopeOptions={advancedScopeOptions}
          blockScopeOptions={blockScopeOptions}
          hasAllowScope={hasAllowScope}
          taskCapabilityCopy={taskCapabilityCopy}
          allowScope={allowScope}
          blockScope={blockScope}
          onAllowScopeChange={setAllowScope}
          onBlockScopeChange={setBlockScope}
        />
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

        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <ActionButton
            ref={allowButtonRef}
            variant="success"
            onClick={handleAllow}
            disabled={!hasAllowScope || submitting !== null || pendingAction !== null}
          >
            {submitting === "allow" ? (
              <span className="flex items-center gap-2">
                <HiMiniArrowPath className="h-4 w-4 animate-spin" aria-hidden="true" />
                Approving...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
                {allowButtonLabel(allowScope)}
              </span>
            )}
          </ActionButton>
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
                {blockButtonLabel(blockScope)}
              </span>
            )}
          </ActionButton>
        </div>

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

      {detail.receipt && (
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <SectionLabel>Last time</SectionLabel>
          <p className="mt-2 text-sm text-muted-foreground">
            You previously {pastDecisionVerb(detail.receipt.policy_decision)} a similar action{" "}
            {formatRelativeTime(detail.receipt.timestamp)}.
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

      {pendingAction !== null && props.approvalGate !== null && (
        <ApprovalPasswordModal
          gate={props.approvalGate}
          approvalPassword={approvalPassword}
          approvalTotpCode={approvalTotpCode}
          useCooldown={useCooldown}
          onApprovalPasswordChange={handleApprovalPasswordChange}
          onApprovalTotpCodeChange={handleApprovalTotpCodeChange}
          onUseCooldownChange={handleUseCooldownChange}
          onSubmit={handleModalSubmit}
          onCancel={handleModalCancel}
          submitLabel={pendingAction === "allow" ? allowButtonLabel(allowScope) : blockButtonLabel(blockScope)}
        />
      )}
    </div>
  );
}
