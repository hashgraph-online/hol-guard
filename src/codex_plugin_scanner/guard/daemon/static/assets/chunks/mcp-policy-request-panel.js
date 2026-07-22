import { r as reactExports, bI as fetchMcpPolicyRequest, aR as buildApprovalProofCredentials, bJ as resolveMcpPolicyRequest, j as jsxRuntimeExports, k as EmptyState, A as ActionButton, ar as HiMiniArrowPath, aS as isApprovalProofSubmitDisabled, bh as WorkspacePageHeader, M as Badge, q as HiMiniShieldCheck, m as HiMiniCheckCircle, K as HiMiniExclamationTriangle, S as SectionLabel, aW as HiMiniClock, bK as HiMiniDocumentPlus, bL as HiMiniDocumentMagnifyingGlass, bD as HiMiniNoSymbol, aT as ApprovalProofFieldInputs, Y as HiMiniKey } from "../guard-dashboard.js";
const STATUS_LABELS = {
  pending: "Pending review",
  applied: "Applied",
  declined: "Declined",
  expired: "Expired",
  failed: "Failed"
};
const FAILURE_CODE_LABELS = {
  policy_write_failed: "Guard could not write the policy file.",
  approval_already_resolved: "This request was already resolved.",
  approval_gate_required: "Approval gate authentication is required.",
  missing_required_fields: "Required fields were missing from the request.",
  invalid_arguments: "The request contained invalid arguments."
};
function resolveOutcomeMessage(result) {
  switch (result.status) {
    case "applied":
      return "Policy applied.";
    case "declined":
      return "Request declined.";
    default:
      return `Request is now ${STATUS_LABELS[result.status].toLowerCase()}.`;
  }
}
function planToneClass(tone) {
  switch (tone) {
    case "emerald":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "amber":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "rose":
      return "border-rose-200 bg-rose-50 text-rose-700";
  }
}
function statusTone(status) {
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
function isActable(request) {
  return !request.isTerminal && !request.isExpired;
}
function truncateDigest(digest) {
  if (digest.length <= 16) return digest;
  return `${digest.slice(0, 12)}…${digest.slice(-4)}`;
}
function formatTimestamp(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(void 0, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}
function McpPolicyRequestPanel(props) {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [outcome, setOutcome] = reactExports.useState(null);
  const [approvalPassword, setApprovalPassword] = reactExports.useState("");
  const [approvalTotpCode, setApprovalTotpCode] = reactExports.useState("");
  const load = reactExports.useCallback(async () => {
    setState({ kind: "loading" });
    setOutcome(null);
    setApprovalPassword("");
    setApprovalTotpCode("");
    try {
      const request2 = await fetchMcpPolicyRequest(props.requestId);
      if (request2 === null) {
        setState({ kind: "not-found" });
        return;
      }
      setState({ kind: "ready", request: request2 });
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : "Unable to load the request.";
      setState({ kind: "error", message });
    }
  }, [props.requestId]);
  reactExports.useEffect(() => {
    load();
  }, [load]);
  const handleResolve = reactExports.useCallback(
    async (action) => {
      if (state.kind !== "ready") return;
      const request2 = state.request;
      const proof = action === "approve" ? buildApprovalProofCredentials(props.approvalGate, {
        approvalPassword,
        approvalTotpCode
      }) : {};
      setApprovalPassword("");
      setApprovalTotpCode("");
      setState({ kind: "resolving", request: request2, action });
      setOutcome(null);
      try {
        const result = await resolveMcpPolicyRequest({
          requestId: request2.requestId,
          action,
          ...proof
        });
        setOutcome({ kind: "resolved", result });
        try {
          const refreshed = await fetchMcpPolicyRequest(request2.requestId);
          if (refreshed !== null) {
            setState({ kind: "ready", request: refreshed });
          } else {
            setState({ kind: "not-found" });
          }
        } catch {
          setState({ kind: "ready", request: request2 });
        }
        props.onResolved?.();
      } catch (error) {
        const message = error instanceof Error && error.message ? error.message : `Unable to ${action} this request.`;
        setOutcome({ kind: "failed", message });
        setState({ kind: "ready", request: request2 });
      }
    },
    [approvalPassword, approvalTotpCode, props, state]
  );
  const handleApprove = reactExports.useCallback(() => {
    void handleResolve("approve");
  }, [handleResolve]);
  const handleDecline = reactExports.useCallback(() => {
    void handleResolve("decline");
  }, [handleResolve]);
  const handleApprovalPasswordChange = reactExports.useCallback((event) => {
    setApprovalPassword(event.target.value);
  }, []);
  const handleApprovalTotpCodeChange = reactExports.useCallback((event) => {
    setApprovalTotpCode(event.target.value);
  }, []);
  if (state.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", "aria-busy": "true", "aria-live": "polite", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-8 w-72" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-24 w-full" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-40 w-full" })
    ] });
  }
  if (state.kind === "not-found") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "Request not found",
        body: "This MCP policy request does not exist or has been removed from the approval queue.",
        action: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: load, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "Try again"
        ] })
      }
    );
  }
  if (state.kind === "error") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "Couldn't load the request",
        body: state.message,
        action: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: load, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "Retry"
        ] })
      }
    );
  }
  const request = state.request;
  const actable = isActable(request);
  const resolving = state.kind === "resolving";
  const approving = resolving && state.action === "approve";
  const declining = resolving && state.action === "decline";
  const approveDisabled = !actable || resolving || isApprovalProofSubmitDisabled(
    props.approvalGate,
    { approvalPassword, approvalTotpCode },
    resolving
  );
  const { writePlan, semanticDiff } = request;
  const hasPlanEntries = writePlan.additions.length > 0 || writePlan.replacements.length > 0 || writePlan.removals.length > 0;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorkspacePageHeader,
      {
        eyebrow: "MCP policy review",
        title: "Policy creation request",
        description: "A staged MCP policy change is waiting for your review. Approve to apply it, or decline to discard it.",
        actions: /* @__PURE__ */ jsxRuntimeExports.jsxs(Badge, { tone: statusTone(request.status), children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-3 w-3", "aria-hidden": "true" }),
          STATUS_LABELS[request.status]
        ] })
      }
    ),
    outcome !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        role: "status",
        "aria-live": "polite",
        className: outcome.kind === "resolved" ? "rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800" : "rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800",
        children: outcome.kind === "resolved" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4", "aria-hidden": "true" }),
          resolveOutcomeMessage(outcome.result)
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4", "aria-hidden": "true" }),
          outcome.message
        ] })
      }
    ) : null,
    request.activeEnforcementWarning ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4", "aria-hidden": "true" }),
      "This request is active and waiting for your decision."
    ] }) }) : null,
    request.failureCode !== null && request.failureCode.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-semibold", children: "Policy write failed" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1", children: FAILURE_CODE_LABELS[request.failureCode] ?? `Failure code: ${request.failureCode}` })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "mcp-policy-summary", className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Summary" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid grid-cols-1 gap-px overflow-hidden rounded-xl border border-border bg-surface-2 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryField, { label: "Mode", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: request.mode === "replace" ? "warning" : "info", children: request.mode }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryField, { label: "Status", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex items-center gap-2 text-sm text-brand-dark", children: STATUS_LABELS[request.status] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryField, { label: "Created", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1.5 font-mono text-[13px] text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClock, { className: "h-3.5 w-3.5 text-slate-400", "aria-hidden": "true" }),
          formatTimestamp(request.createdAt)
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryField, { label: "Expires", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1.5 font-mono text-[13px] text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClock, { className: "h-3.5 w-3.5 text-slate-400", "aria-hidden": "true" }),
          formatTimestamp(request.expiresAt)
        ] }) }),
        request.resolvedAt !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryField, { label: "Resolved", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-[13px] text-brand-dark", children: formatTimestamp(request.resolvedAt) }) }) : null,
        request.expectedPolicyGeneration !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryField, { label: "Expected generation", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-[13px] text-brand-dark", children: request.expectedPolicyGeneration }) }) : null
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "mcp-policy-digests", className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Digests" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid grid-cols-1 gap-px overflow-hidden rounded-xl border border-border bg-surface-2 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryField, { label: "Candidate digest", children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "block break-all font-mono text-[13px] text-brand-dark", children: truncateDigest(request.candidateDigest) }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryField, { label: "Expected current digest", children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "block break-all font-mono text-[13px] text-brand-dark", children: request.expectedCurrentDigest ? truncateDigest(request.expectedCurrentDigest) : "—" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryField, { label: "Document ID", children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "block break-all font-mono text-[13px] text-brand-dark", children: request.documentId || "—" }) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "mcp-policy-plan", className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Write plan" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "A summary of the changes this policy would introduce. The full policy text is not shown." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-1 gap-3 sm:grid-cols-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PlanCountCard,
          {
            label: "Additions",
            count: semanticDiff.additionCount,
            items: writePlan.additions,
            tone: "emerald",
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentPlus, { className: "h-4 w-4", "aria-hidden": "true" })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PlanCountCard,
          {
            label: "Replacements",
            count: semanticDiff.replacementCount,
            items: writePlan.replacements,
            tone: "amber",
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentMagnifyingGlass, { className: "h-4 w-4", "aria-hidden": "true" })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PlanCountCard,
          {
            label: "Removals",
            count: semanticDiff.removalCount,
            items: writePlan.removals,
            tone: "rose",
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniNoSymbol, { className: "h-4 w-4", "aria-hidden": "true" })
          }
        )
      ] }),
      !hasPlanEntries ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "No structured changes were reported for this request." }) : null
    ] }),
    request.isTerminal || request.isExpired ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }),
      "This request is ",
      request.isExpired ? "expired" : "resolved",
      " and can no longer be acted on."
    ] }) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "mcp-policy-actions", className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Actions" }),
      actable ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-md rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-3 text-sm text-slate-600", children: "Approval requires your local proof. It is sent once and never stored." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          ApprovalProofFieldInputs,
          {
            approvalGate: props.approvalGate ?? null,
            approvalPassword,
            approvalTotpCode,
            onApprovalPasswordChange: handleApprovalPasswordChange,
            onApprovalTotpCodeChange: handleApprovalTotpCodeChange
          }
        )
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          ActionButton,
          {
            variant: "success",
            onClick: handleApprove,
            disabled: approveDisabled,
            "aria-label": "Approve policy creation request",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
              approving ? "Approving…" : "Approve"
            ]
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          ActionButton,
          {
            variant: "danger",
            onClick: handleDecline,
            disabled: !actable || resolving,
            "aria-label": "Decline policy creation request",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniNoSymbol, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
              declining ? "Declining…" : "Decline"
            ]
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: load, disabled: resolving, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "Refresh"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "inline-flex items-center gap-1.5 text-xs text-slate-500", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniKey, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
        "Actions are authenticated with your dashboard session and are safe to retry."
      ] })
    ] })
  ] });
}
function SummaryField(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-white px-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[11px] font-medium uppercase tracking-wider text-slate-500", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 min-w-0", children: props.children })
  ] });
}
function PlanCountCard(props) {
  const toneClass = planToneClass(props.tone);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-xl border px-4 py-3 ${toneClass}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider", children: [
        props.icon,
        props.label
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-lg font-semibold", children: props.count })
    ] }),
    props.items.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "mt-2 space-y-1 text-[13px] leading-5 text-slate-700", children: [
      props.items.slice(0, 8).map((item, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "break-all", children: item }, `${props.label}-${index}-${item}`)),
      props.items.length > 8 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "text-slate-400", children: [
        "+",
        props.items.length - 8,
        " more"
      ] }) : null
    ] }) : null
  ] });
}
export {
  McpPolicyRequestPanel
};
