import { useCallback, useEffect, useState, type ChangeEvent } from "react";

import {
  approvalGateIsLocked,
  approvalGateLockRemainingSeconds,
  approvalGateRequiredForResolution,
  defaultUseApprovalCooldown,
  requiresApprovalPasswordPrompt,
} from "./approval-gate-utils";
import { approvalProofRecentlySatisfied, buildApprovalProofCredentials } from "./approval-proof-inline";
import { buildDecisionPayload, willPersistExactAction } from "./approval-scopes";
import { approvalGateRefreshNeeded, resolvedStateForItem, useShownRequestCheck } from "./review-decision-state";
import { fetchResolvedApprovalGate } from "./use-resolved-approval-gate";
import type { DecisionScope, GuardApprovalGatePublicConfig, GuardApprovalRequest } from "./guard-types";
import type { ReviewWorkspaceProps } from "./review-workspace";

export function approvalGateRefreshFailureMessage(message: string): string {
  return `${message} Unable to refresh approval settings. Retry to refresh.`;
}

type ResolvedState = {
  requestId: string;
  action: "allow" | "block";
  persistedExactAction: boolean;
  message?: string;
};

type ScopeChoice = { value: DecisionScope };

type ReviewDecisionResolveParams = {
  item: GuardApprovalRequest | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onResolve: ReviewWorkspaceProps["onResolve"];
  resolutionBlockReason: string | null;
  allowScope: DecisionScope;
  blockScope: DecisionScope;
  setAllowScope: (scope: DecisionScope) => void;
  availableScopeChoices: ScopeChoice[];
  blockScopeOptions: unknown[];
  hasAllowScope: boolean;
  canSubmitAllow: boolean;
  watchOnlyObservation: boolean;
  rememberExactAction: boolean;
  extensionDialogActive: boolean;
  decisionContractKey: string | null;
  decisionSubjectKey: string | null;
};

/** Own every piece of approval-gate state the review card's decision buttons drive. */
export function useReviewDecisionResolve(params: ReviewDecisionResolveParams) {
  const {
    item,
    onResolve,
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
  } = params;

  const [submitting, setSubmitting] = useState<"allow" | "block" | null>(null);
  // Keyed by request id: the parent may show the next request before onResolve settles.
  const [resolvedState, setResolved] = useState<ResolvedState | null>(null);
  const resolved = resolvedStateForItem(resolvedState, item);
  const isStillShown = useShownRequestCheck(item?.request_id ?? null);
  const [lastAction, setLastAction] = useState<"allow" | "block" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [approvalPassword, setApprovalPassword] = useState("");
  const [approvalTotpCode, setApprovalTotpCode] = useState("");
  const [cooldownOptOut, setCooldownOptOut] = useState(false);
  const [pendingAction, setPendingAction] = useState<"allow" | "block" | null>(null);
  const [pendingContractKey, setPendingContractKey] = useState<string | null>(null);
  // One decision at a time: the gate preflight runs before `submitting` is set.
  const [preflighting, setPreflighting] = useState(false);
  const [effectiveApprovalGate, setEffectiveApprovalGate] = useState(params.approvalGate);
  const approvalGate = effectiveApprovalGate;
  const useCooldown = defaultUseApprovalCooldown(approvalGate) && !cooldownOptOut;
  const decisionBusy = submitting !== null || preflighting;

  useEffect(() => {
    setEffectiveApprovalGate(params.approvalGate);
  }, [params.approvalGate]);

  useEffect(() => {
    if (!item) return;
    setResolved(null);
    setSubmitting(null);
    setPreflighting(false);
    setLastAction(null);
    setErrorMessage(null);
    setApprovalPassword("");
    setApprovalTotpCode("");
    setCooldownOptOut(false);
    setPendingAction(null);
    setPendingContractKey(null);
  }, [decisionSubjectKey]);

  const handleResolve = useCallback(
    async (action: "allow" | "block", gateOverride?: GuardApprovalGatePublicConfig | null) => {
      if (!item || resolutionBlockReason !== null) return;
      if (action === "allow" && !canSubmitAllow) {
        setErrorMessage(hasAllowScope
          ? "Choose 'Always allow exact action' before approving; run once is unavailable."
          : "This action has no eligible approval scope.");
        return;
      }
      const requestId = item.request_id;
      const requestedScope = action === "allow" ? allowScope : blockScope;
      const gate = gateOverride ?? approvalGate;
      const gateRequired = approvalGateRequiredForResolution(gate, action, requestedScope);
      if (gateRequired && approvalGateIsLocked(gate)) {
        setErrorMessage(
          `Approval gate is temporarily locked. Try again in ${approvalGateLockRemainingSeconds(gate)} seconds.`,
        );
        return;
      }
      setSubmitting(action);
      setErrorMessage(null);
      try {
        const persistExactAction = willPersistExactAction(
          item,
          action,
          requestedScope,
          action === "allow" ? rememberExactAction : watchOnlyObservation,
        );
        const includeGateFields =
          gateRequired &&
          gate?.configured === true &&
          requiresApprovalPasswordPrompt(
            gate.cooldown_active,
            gate.strict_all_decisions,
            requestedScope,
          );
        const proof = includeGateFields
          ? buildApprovalProofCredentials(gate, { approvalPassword, approvalTotpCode })
          : {};
        await onResolve({
          ...buildDecisionPayload({
            item,
            action,
            scope: requestedScope,
            reason: action === "allow" ? "approved in review" : "blocked in review",
            persistExactAction,
          }),
          ...proof,
          ...(includeGateFields
            ? {
                approval_gate_use_cooldown:
                  defaultUseApprovalCooldown(gate) && !cooldownOptOut,
              }
            : {}),
        });
        // The next request may already be on screen; never reset its form for this decision.
        if (!isStillShown(requestId)) return;
        setResolved({ requestId, action, persistedExactAction: persistExactAction });
        setApprovalPassword("");
        setApprovalTotpCode("");
        setCooldownOptOut(false);
        setPendingAction(null);
        setPendingContractKey(null);
        if (gateRequired && (gate?.cooldown_seconds ?? 0) > 0) {
          // A password approval may have opened the cooldown window; pick it up without a reload.
          // A refresh that finds no gate is authoritative too: a removed gate must stop
          // asking for credentials, so the null result replaces the prior gate.
          void fetchResolvedApprovalGate()
            .then((refreshed) => {
              if (isStillShown(requestId)) setEffectiveApprovalGate(refreshed);
            })
            .catch(() => {});
        }
      } catch (err) {
        if (!isStillShown(requestId)) return;
        const message = err instanceof Error ? err.message : "Something went wrong. Try again.";
        setErrorMessage(message);
        if (approvalGateRefreshNeeded(err)) {
          setSubmitting(null);
          try {
            const refreshedGate = await fetchResolvedApprovalGate();
            setEffectiveApprovalGate(refreshedGate);
          } catch {
            setErrorMessage(approvalGateRefreshFailureMessage(message));
          }
        }
      } finally {
        if (isStillShown(requestId)) setSubmitting(null);
      }
    },
    [
      item,
      isStillShown,
      allowScope,
      blockScope,
      watchOnlyObservation,
      rememberExactAction,
      onResolve,
      approvalGate,
      approvalPassword,
      approvalTotpCode,
      cooldownOptOut,
      resolutionBlockReason,
      canSubmitAllow,
      hasAllowScope,
    ]
  );

  const handleRequestResolve = useCallback(
    (action: "allow" | "block") => {
      if (resolutionBlockReason !== null || decisionBusy) return;
      if (action === "allow" && !hasAllowScope) {
        setErrorMessage("This action has no eligible approval scope.");
        return;
      }
      if (action === "allow" && !canSubmitAllow) {
        setErrorMessage("Choose 'Always allow exact action' before approving; run once is unavailable.");
        return;
      }
      if (action === "block" && blockScopeOptions.length === 0) {
        setErrorMessage("This action has no eligible block scope.");
        return;
      }
      setLastAction(action);
      const requestedScope = action === "allow" ? allowScope : blockScope;
      const gate = approvalGate;
      const gateRequired = approvalGateRequiredForResolution(gate, action, requestedScope);
      if (gateRequired && approvalGateIsLocked(gate)) {
        setErrorMessage(
          `Approval gate is temporarily locked. Try again in ${approvalGateLockRemainingSeconds(gate)} seconds.`,
        );
        return;
      }
      // Claim the decision before the first await so repeated clicks and the
      // keyboard shortcuts cannot start a second continuation for this request.
      const requestId = item?.request_id ?? null;
      setPreflighting(true);
      void (async () => {
        try {
          let current = gate;
          if (gateRequired && (gate?.cooldown_seconds ?? 0) > 0 && gate?.totp_enabled !== true) {
            // The cached cooldown window may have opened or expired since the gate was loaded.
            const fresh = await fetchResolvedApprovalGate().then(
              (value) => ({ gate: value }),
              () => null,
            );
            if (requestId !== null && !isStillShown(requestId)) return;
            if (fresh) {
              current = fresh.gate;
              setEffectiveApprovalGate(fresh.gate);
            }
          }
          if (approvalGateRequiredForResolution(current, action, requestedScope) && approvalGateIsLocked(current)) {
            setErrorMessage(
              `Approval gate is temporarily locked. Try again in ${approvalGateLockRemainingSeconds(current)} seconds.`,
            );
            return;
          }
          const gateEnabled =
            approvalGateRequiredForResolution(current, action, requestedScope) &&
            current?.configured === true &&
            requiresApprovalPasswordPrompt(
              current.cooldown_active,
              current.strict_all_decisions,
              requestedScope,
            );
          if (!gateEnabled) {
            void handleResolve(action, current);
            return;
          }
          setErrorMessage(null);
          if (!approvalProofRecentlySatisfied(current)) {
            setPendingAction(action);
            setPendingContractKey(decisionContractKey);
            return;
          }
          const fresh = await fetchResolvedApprovalGate().catch(() => current);
          if (requestId !== null && !isStillShown(requestId)) return;
          if (approvalProofRecentlySatisfied(fresh ?? current)) {
            void handleResolve(action, fresh ?? current);
            return;
          }
          // The dialog renders from this state; keep the fresh gate so it asks for a code.
          if (fresh) setEffectiveApprovalGate(fresh);
          setPendingAction(action);
          setPendingContractKey(decisionContractKey);
        } finally {
          setPreflighting(false);
        }
      })();
    },
    [
      allowScope,
      blockScope,
      blockScopeOptions.length,
      decisionBusy,
      decisionContractKey,
      handleResolve,
      hasAllowScope,
      canSubmitAllow,
      isStillShown,
      item,
      approvalGate,
      resolutionBlockReason,
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
      if (
        decisionBusy ||
        pendingAction !== null ||
        extensionDialogActive ||
        resolved !== null ||
        resolutionBlockReason !== null
      ) {
        return;
      }
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
  }, [
    availableScopeChoices,
    decisionBusy,
    extensionDialogActive,
    handleRequestResolve,
    pendingAction,
    resolutionBlockReason,
    resolved,
    setAllowScope,
  ]);

  const handleModalSubmit = useCallback(() => {
    if (pendingAction === null || submitting !== null) {
      return;
    }
    if (pendingContractKey !== decisionContractKey) {
      setPendingAction(null);
      setPendingContractKey(null);
      setErrorMessage("This request changed while you were reviewing it. Review the current scopes and try again.");
      return;
    }
    void handleResolve(pendingAction);
  }, [decisionContractKey, handleResolve, pendingAction, pendingContractKey, submitting]);

  const handleModalCancel = useCallback(() => {
    setPendingAction(null);
    setPendingContractKey(null);
    setApprovalPassword("");
    setApprovalTotpCode("");
    setCooldownOptOut(false);
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
    setCooldownOptOut(!event.target.checked);
  }, []);

  return {
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
  };
}
