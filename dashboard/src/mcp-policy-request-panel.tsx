import { useCallback, useEffect, useState } from "react";
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

export type McpPolicyRequestPanelState =
  | { kind: "loading" }
  | { kind: "not-found" }
  | { kind: "error"; message: string }
  | { kind: "ready"; request: McpPolicyRequest }
  | { kind: "resolving"; request: McpPolicyRequest; action: "approve" | "decline" };

type ResolveOutcome =
  | { kind: "resolved"; result: McpPolicyDecisionResult }
  | { kind: "failed"; message: string };

const STATUS_LABELS: Record<McpPolicyRequest["status"], string> = {
  pending: "Pending review",
  applied: "Applied",
  declined: "Declined",
  expired: "Expired",
  failed: "Failed",
};

const FAILURE_CODE_LABELS: Record<string, string> = {
  policy_write_failed: "Guard could not write the policy file.",
  approval_already_resolved: "This request was already resolved.",
  approval_gate_required: "Approval gate authentication is required.",
  missing_required_fields: "Required fields were missing from the request.",
  invalid_arguments: "The request contained invalid arguments.",
};

function resolveOutcomeMessage(result: McpPolicyDecisionResult): string {
  switch (result.status) {
    case "applied":
      return "Policy applied.";
    case "declined":
      return "Request declined.";
    default:
      return `Request is now ${STATUS_LABELS[result.status].toLowerCase()}.`;
  }
}

function planToneClass(tone: "emerald" | "amber" | "rose"): string {
  switch (tone) {
    case "emerald":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "amber":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "rose":
      return "border-rose-200 bg-rose-50 text-rose-700";
  }
}

function statusTone(status: McpPolicyRequest["status"]): BadgeProps["tone"] {
  switch (status) {
    case "applied":
      return "success";
    case "declined":
      return "default";
    case "expired":
      return "warning";
    case "failed":
      return "destructive";
    default:
      return "info";
  }
}

function isActable(request: McpPolicyRequest): boolean {
  return !request.isTerminal && !request.isExpired;
}

function truncateDigest(digest: string): string {
  if (digest.length <= 16) return digest;
  return `${digest.slice(0, 12)}…${digest.slice(-4)}`;
}

function formatTimestamp(iso: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

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

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    setOutcome(null);
    setApprovalPassword("");
    setApprovalTotpCode("");
    try {
      const request = await fetchMcpPolicyRequest(props.requestId);
      if (request === null) {
        setState({ kind: "not-found" });
        return;
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
        const message =
          error instanceof Error && error.message
            ? error.message
            : `Unable to ${action} this request.`;
        setOutcome({ kind: "failed", message });
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
  const actable = isActable(request);
  const resolving = state.kind === "resolving";
  const approving = resolving && state.action === "approve";
  const declining = resolving && state.action === "decline";
  const approveDisabled =
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
              {outcome.message}
            </span>
          )}
        </div>
      ) : null}

      {request.activeEnforcementWarning ? (
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          <span className="inline-flex items-center gap-2">
            <HiMiniExclamationTriangle className="h-4 w-4" aria-hidden="true" />
            This request is active and waiting for your decision.
          </span>
        </div>
      ) : null}

      {request.failureCode !== null && request.failureCode.length > 0 ? (
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
        {actable ? (
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

type BadgeProps = {
  tone?: "default" | "success" | "warning" | "info" | "destructive" | "attention";
};

function SummaryField(props: { label: string; children: React.ReactNode }) {
  return (
    <div className="bg-white px-4 py-3">
      <dt className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
        {props.label}
      </dt>
      <dd className="mt-1 min-w-0">{props.children}</dd>
    </div>
  );
}

function PlanCountCard(props: {
  label: string;
  count: number;
  items: readonly string[];
  tone: "emerald" | "amber" | "rose";
  icon: React.ReactNode;
}) {
  const toneClass = planToneClass(props.tone);
  return (
    <div className={`rounded-xl border px-4 py-3 ${toneClass}`}>
      <div className="flex items-center justify-between">
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider">
          {props.icon}
          {props.label}
        </span>
        <span className="text-lg font-semibold">{props.count}</span>
      </div>
      {props.items.length > 0 ? (
        <ul className="mt-2 space-y-1 text-[13px] leading-5 text-slate-700">
          {props.items.slice(0, 8).map((item, index) => (
            <li key={`${props.label}-${index}-${item}`} className="break-all">
              {item}
            </li>
          ))}
          {props.items.length > 8 ? (
            <li className="text-slate-400">+{props.items.length - 8} more</li>
          ) : null}
        </ul>
      ) : null}
    </div>
  );
}
