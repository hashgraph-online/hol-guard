import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import type { ChangeEvent } from "react";
import {
  HiMiniCheckCircle,
  HiMiniNoSymbol,
  HiMiniExclamationTriangle,
  HiMiniArrowPath,
  HiMiniClock,
  HiMiniDocumentPlus,
  HiMiniDocumentMagnifyingGlass,
  HiMiniShieldCheck,
  HiMiniKey,
} from "react-icons/hi2";
import {
  fetchMcpPolicyRequest,
  GuardHarnessActionError,
  resolveMcpPolicyRequest,
  type McpPolicyDecisionResult,
  type McpPolicyRequest,
} from "./guard-api";
import {
  ActionButton,
  Badge,
  EmptyState,
  SectionLabel,
} from "./approval-center-primitives";
import { WorkspacePageHeader } from "./workspace-page-header";
import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { RECOVERY_SOURCE_ERRORS, inspectBusinessPolicy, recoverBusinessPolicy, type BusinessRecoveryInspection } from "./business-policy-recovery-api";
import { STATUS_LABELS, FAILURE_CODE_LABELS, resolveOutcomeMessage, statusTone, isActable, truncateDigest, formatTimestamp } from "./mcp-policy-request-copy";
import { SummaryField, PlanCountCard } from "./mcp-policy-request-fields";

const BusinessPolicyRecoveryPanel = lazy(() => import("./business-policy-recovery-panel").then(
  (module) => ({ default: module.BusinessPolicyRecoveryPanel }),
));

export type McpPolicyRequestPanelState =
  | { kind: "loading" }
  | { kind: "not-found" }
  | { kind: "error"; message: string }
  | { kind: "ready"; request: McpPolicyRequest }
  | { kind: "resolving"; request: McpPolicyRequest; action: "approve" | "decline" };

type ResolveOutcome =
  | { kind: "resolved"; result: McpPolicyDecisionResult }
  | { kind: "failed"; message: string };

export interface McpPolicyRequestPanelProps {
  requestId: string;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onResolved?: () => void;
}

export function McpPolicyRequestPanel(props: McpPolicyRequestPanelProps) {
  const [state, setState] = useState<McpPolicyRequestPanelState>({ kind: "loading" });
  const [outcome, setOutcome] = useState<ResolveOutcome | null>(null);
  const [approvalPassword, setApprovalPassword] = useState("");
  const [approvalTotpCode, setApprovalTotpCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  const [installationRecovered, setInstallationRecovered] = useState(false);
  const [inspection, setInspection] = useState<BusinessRecoveryInspection | null>(null);
  const [inspectionError, setInspectionError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    setOutcome(null);
    setRecoveryCode(null);
    setInstallationRecovered(false);
    setInspection(null);
    setInspectionError(null);
    setApprovalPassword("");
    setApprovalTotpCode("");
    try {
      const request = await fetchMcpPolicyRequest(props.requestId);
      if (request === null) {
        setState({ kind: "not-found" });
        return;
      }
      try {
        const inspected = await inspectBusinessPolicy(request.requestId, request.candidateDigest);
        setInspection(inspected);
        setInstallationRecovered(inspected.state === "installed");
      } catch {
        setInspectionError("Saved installation state could not be verified. Refresh before approving; you can still decline this request.");
      }
      setState({ kind: "ready", request });
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : "Unable to load the request.";
      setState({ kind: "error", message });
    }
  }, [props.requestId]);

  useEffect(() => {
    load();
  }, [load]);

  const handleResolve = useCallback(
    async (action: "approve" | "decline") => {
      if (state.kind !== "ready") return;
      const request = state.request;
      const proof =
        action === "approve"
          ? buildApprovalProofCredentials(props.approvalGate, {
              approvalPassword,
              approvalTotpCode,
            })
          : {};
      setApprovalPassword("");
      setApprovalTotpCode("");
      setState({ kind: "resolving", request, action });
      setOutcome(null);
      try {
        const result = await resolveMcpPolicyRequest({
          requestId: request.requestId,
          action,
          ...proof,
        });
        setOutcome({ kind: "resolved", result });
        try {
          const refreshed = await fetchMcpPolicyRequest(request.requestId);
          if (refreshed !== null) {
            setState({ kind: "ready", request: refreshed });
          } else {
            setState({ kind: "not-found" });
          }
        } catch {
          setState({ kind: "ready", request });
        }
        props.onResolved?.();
      } catch (error) {
        setRecoveryCode(error instanceof GuardHarnessActionError ? error.payload?.error ?? null : null);
        const message =
          error instanceof Error && error.message
            ? error.message
            : `Unable to ${action} this request.`;
        setOutcome({ kind: "failed", message });
        try {
          const inspected = await inspectBusinessPolicy(request.requestId, request.candidateDigest);
          setInspection(inspected);
          setInstallationRecovered(inspected.state === "installed");
        } catch { setInspection(null); }
        setState({ kind: "ready", request });
      }
    },
    [approvalPassword, approvalTotpCode, props, state],
  );

  const handleApprove = useCallback(() => {
    void handleResolve("approve");
  }, [handleResolve]);

  const handleDecline = useCallback(() => {
    void handleResolve("decline");
  }, [handleResolve]);

  const handleApprovalPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalPassword(event.target.value);
  }, []);

  const handleApprovalTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalTotpCode(event.target.value);
  }, []);

  if (state.kind === "loading") {
    return (
      <div className="space-y-4" aria-busy="true" aria-live="polite">
        <div className="guard-skeleton h-8 w-72" />
        <div className="guard-skeleton h-24 w-full" />
        <div className="guard-skeleton h-40 w-full" />
      </div>
    );
  }

  if (state.kind === "not-found") {
    return (
      <EmptyState
        title="Request not found"
        body="This MCP policy request does not exist or has been removed from the approval queue."
        action={
          <ActionButton variant="outline" onClick={load}>
            <HiMiniArrowPath className="mr-1.5 h-4 w-4" aria-hidden="true" />
            Try again
          </ActionButton>
        }
      />
    );
  }

  if (state.kind === "error") {
    return (
      <EmptyState
        title="Couldn't load the request"
        body={state.message}
        action={
          <ActionButton variant="outline" onClick={load}>
            <HiMiniArrowPath className="mr-1.5 h-4 w-4" aria-hidden="true" />
            Retry
          </ActionButton>
        }
      />
    );
  }

  const request = state.request;
  const recoveryRequired = inspection?.state === "interrupted" || RECOVERY_SOURCE_ERRORS.has(recoveryCode ?? request.failureCode ?? "");
  const requestRecovered = inspection?.requestRecovered === true;
  let failureMessage = "";
  if (outcome?.kind === "failed") failureMessage = outcome.message;
  if (recoveryRequired) failureMessage = "Policy installation needs attention. Review the saved policy below before approving recovery.";
  const actable = isActable(request);
  const resolving = state.kind === "resolving";
  const approving = resolving && state.action === "approve";
  const declining = resolving && state.action === "decline";
  const approveDisabled =
    recoveryRequired ||
    installationRecovered ||
    requestRecovered ||
    inspectionError !== null ||
    !actable ||
    resolving ||
    isApprovalProofSubmitDisabled(
      props.approvalGate,
      { approvalPassword, approvalTotpCode },
      resolving,
    );

  const { writePlan, semanticDiff } = request;
  const hasPlanEntries =
    writePlan.additions.length > 0 ||
    writePlan.replacements.length > 0 ||
    writePlan.removals.length > 0;

  return (
    <div className="space-y-6">
      <WorkspacePageHeader
        eyebrow="MCP policy review"
        title="Policy creation request"
        description="A staged MCP policy change is waiting for your review. Approve to apply it, or decline to discard it."
        actions={
          <Badge tone={statusTone(request.status)}>
            <HiMiniShieldCheck className="h-3 w-3" aria-hidden="true" />
            {STATUS_LABELS[request.status]}
          </Badge>
        }
      />

      {outcome !== null ? (
        <div
          role="status"
          aria-live="polite"
          className={
            outcome.kind === "resolved"
              ? "rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800"
              : "rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800"
          }
        >
          {outcome.kind === "resolved" ? (
            <span className="inline-flex items-center gap-2">
              <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
              {resolveOutcomeMessage(outcome.result)}
            </span>
          ) : (
            <span className="inline-flex items-center gap-2">
              <HiMiniExclamationTriangle className="h-4 w-4" aria-hidden="true" />
              {failureMessage}
            </span>
          )}
        </div>
      ) : null}

      {request.activeEnforcementWarning && !recoveryRequired ? (
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          <span className="inline-flex items-center gap-2">
            <HiMiniExclamationTriangle className="h-4 w-4" aria-hidden="true" />
            This request is active and waiting for your decision.
          </span>
        </div>
      ) : null}

      {request.failureCode !== null && request.failureCode.length > 0 && !recoveryRequired ? (
        <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
          <p className="font-semibold">Policy write failed</p>
          <p className="mt-1">
            {FAILURE_CODE_LABELS[request.failureCode] ?? `Failure code: ${request.failureCode}`}
          </p>
        </div>
      ) : null}

      <section aria-labelledby="mcp-policy-summary" className="space-y-3">
        <SectionLabel>Summary</SectionLabel>
        <dl className="grid grid-cols-1 gap-px overflow-hidden rounded-xl border border-border bg-surface-2 sm:grid-cols-2">
          <SummaryField label="Mode">
            <Badge tone={request.mode === "replace" ? "warning" : "info"}>{request.mode}</Badge>
          </SummaryField>
          <SummaryField label="Status">
            <span className="inline-flex items-center gap-2 text-sm text-brand-dark">
              {STATUS_LABELS[request.status]}
            </span>
          </SummaryField>
          <SummaryField label="Created">
            <span className="inline-flex items-center gap-1.5 font-mono text-[13px] text-brand-dark">
              <HiMiniClock className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              {formatTimestamp(request.createdAt)}
            </span>
          </SummaryField>
          <SummaryField label="Expires">
            <span className="inline-flex items-center gap-1.5 font-mono text-[13px] text-brand-dark">
              <HiMiniClock className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              {formatTimestamp(request.expiresAt)}
            </span>
          </SummaryField>
          {request.resolvedAt !== null ? (
            <SummaryField label="Resolved">
              <span className="font-mono text-[13px] text-brand-dark">
                {formatTimestamp(request.resolvedAt)}
              </span>
            </SummaryField>
          ) : null}
          {request.expectedPolicyGeneration !== null ? (
            <SummaryField label="Expected generation">
              <span className="font-mono text-[13px] text-brand-dark">
                {request.expectedPolicyGeneration}
              </span>
            </SummaryField>
          ) : null}
        </dl>
      </section>

      <section aria-labelledby="mcp-policy-digests" className="space-y-3">
        <SectionLabel>Digests</SectionLabel>
        <dl className="grid grid-cols-1 gap-px overflow-hidden rounded-xl border border-border bg-surface-2 sm:grid-cols-2">
          <SummaryField label="Candidate digest">
            <code className="block break-all font-mono text-[13px] text-brand-dark">
              {truncateDigest(request.candidateDigest)}
            </code>
          </SummaryField>
          <SummaryField label="Expected current digest">
            <code className="block break-all font-mono text-[13px] text-brand-dark">
              {request.expectedCurrentDigest ? truncateDigest(request.expectedCurrentDigest) : "—"}
            </code>
          </SummaryField>
          <SummaryField label="Document ID">
            <code className="block break-all font-mono text-[13px] text-brand-dark">
              {request.documentId || "—"}
            </code>
          </SummaryField>
        </dl>
      </section>

      <section aria-labelledby="mcp-policy-plan" className="space-y-3">
        <SectionLabel>Write plan</SectionLabel>
        <p className="text-sm text-slate-500">
          A summary of the changes this policy would introduce. The full policy text is not shown.
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <PlanCountCard
            label="Additions"
            count={semanticDiff.additionCount}
            items={writePlan.additions}
            tone="emerald"
            icon={<HiMiniDocumentPlus className="h-4 w-4" aria-hidden="true" />}
          />
          <PlanCountCard
            label="Replacements"
            count={semanticDiff.replacementCount}
            items={writePlan.replacements}
            tone="amber"
            icon={<HiMiniDocumentMagnifyingGlass className="h-4 w-4" aria-hidden="true" />}
          />
          <PlanCountCard
            label="Removals"
            count={semanticDiff.removalCount}
            items={writePlan.removals}
            tone="rose"
            icon={<HiMiniNoSymbol className="h-4 w-4" aria-hidden="true" />}
          />
        </div>
        {!hasPlanEntries ? (
          <p className="text-sm text-slate-500">
            No structured changes were reported for this request.
          </p>
        ) : null}
      </section>

      {recoveryRequired || installationRecovered || requestRecovered ? (
        <Suspense fallback={<p role="status" className="text-sm text-slate-600">Loading saved policy review…</p>}>
        <BusinessPolicyRecoveryPanel key={request.requestId} requestId={request.requestId}
          candidateDigest={request.candidateDigest} approvalGate={props.approvalGate}
          policy={inspection?.policy} installed={installationRecovered}
          requestRecovered={requestRecovered}
          recoverPolicy={recoverBusinessPolicy}
          onRecovered={() => { setInstallationRecovered(true); setOutcome(null); props.onResolved?.(); }} />
        </Suspense>
      ) : null}

      {request.isTerminal || request.isExpired ? (
        <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
          <span className="inline-flex items-center gap-2">
            <HiMiniCheckCircle className="h-4 w-4 text-slate-400" aria-hidden="true" />
            This request is {request.isExpired ? "expired" : "resolved"} and can no longer be acted on.
          </span>
        </div>
      ) : null}

      <section aria-labelledby="mcp-policy-actions" className="space-y-3">
        <SectionLabel>Actions</SectionLabel>
        {inspectionError ? <p role="alert" className="text-sm text-slate-600">{inspectionError}</p> : null}
        {actable && !installationRecovered && !recoveryRequired && !requestRecovered && !inspectionError ? (
          <div className="max-w-md rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-4">
            <p className="mb-3 text-sm text-slate-600">
              Approval requires your local proof. It is sent once and never stored.
            </p>
            <ApprovalProofFieldInputs
              approvalGate={props.approvalGate ?? null}
              approvalPassword={approvalPassword}
              approvalTotpCode={approvalTotpCode}
              onApprovalPasswordChange={handleApprovalPasswordChange}
              onApprovalTotpCodeChange={handleApprovalTotpCodeChange}
            />
          </div>
        ) : null}
        <div className="flex flex-wrap items-center gap-3">
          <ActionButton
            variant="success"
            onClick={handleApprove}
            disabled={approveDisabled}
            aria-label="Approve policy creation request"
          >
            <HiMiniCheckCircle className="mr-1.5 h-4 w-4" aria-hidden="true" />
            {approving ? "Approving…" : "Approve"}
          </ActionButton>
          <ActionButton
            variant="danger"
            onClick={handleDecline}
            disabled={!actable || resolving}
            aria-label="Decline policy creation request"
          >
            <HiMiniNoSymbol className="mr-1.5 h-4 w-4" aria-hidden="true" />
            {declining ? "Declining…" : "Decline"}
          </ActionButton>
          <ActionButton variant="outline" onClick={load} disabled={resolving}>
            <HiMiniArrowPath className="mr-1.5 h-4 w-4" aria-hidden="true" />
            Refresh
          </ActionButton>
        </div>
        <p className="inline-flex items-center gap-1.5 text-xs text-slate-500">
          <HiMiniKey className="h-3.5 w-3.5" aria-hidden="true" />
          Actions are authenticated with your dashboard session and are safe to retry.
        </p>
      </section>
    </div>
  );
}
