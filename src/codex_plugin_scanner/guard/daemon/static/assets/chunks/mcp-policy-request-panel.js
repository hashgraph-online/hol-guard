const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/chunks/business-policy-recovery-panel.js","assets/guard-dashboard.js","assets/index.css"])))=>i.map(i=>d[i]);
import { bD as fetchGuardApi, bz as GuardHarnessActionError, j as jsxRuntimeExports, r as reactExports, cH as fetchMcpPolicyRequest, au as buildApprovalProofCredentials, cI as resolveMcpPolicyRequest, n as EmptyState, A as ActionButton, ar as HiMiniArrowPath, at as isApprovalProofSubmitDisabled, aM as WorkspacePageHeader, R as Badge, w as HiMiniShieldCheck, s as HiMiniCheckCircle, P as HiMiniExclamationTriangle, S as SectionLabel, b_ as HiMiniClock, cJ as HiMiniDocumentPlus, cK as HiMiniDocumentMagnifyingGlass, bb as HiMiniNoSymbol, as as ApprovalProofFieldInputs, ak as HiMiniKey, cl as __vitePreload } from "../guard-dashboard.js";
const RECOVERY_SOURCE_ERRORS = /* @__PURE__ */ new Set([
  "native_business_source_installation_incoherent",
  "native_business_source_transaction_not_committed",
  "native_business_source_retention_conflict",
  "native_business_source_recovery_required"
]);
const RECOVERY_ERROR_MESSAGES = {
  policy_import_disabled: "Policy imports are disabled. Enable local policy imports before retrying.",
  mcp_policy_write_disabled: "MCP policy writes are disabled. Enable local policy writes before retrying.",
  approval_gate_invalid_password: "The approval password was not accepted. Enter it again.",
  approval_gate_password_required: "Enter your local approval password before retrying.",
  approval_gate_totp_required: "Enter a fresh authenticator code before retrying.",
  approval_gate_configuration_required: "Set up local approval before recovering this policy.",
  approval_gate_recovery_required: "Restore local approval settings before recovering this policy.",
  approval_gate_grant_expired: "Approval expired during recovery. Review the saved policy and enter fresh proof.",
  approval_gate_locked: "Approval is temporarily locked. Wait before trying again.",
  approval_gate_totp_invalid: "The authenticator code was not accepted. Enter a fresh code.",
  approval_gate_required: "Fresh local approval proof is required.",
  business_source_recovery_candidate_unavailable: "This saved policy is unavailable or changed. Refresh and review the current policy.",
  native_business_source_recovery_identity_mismatch: "The saved installation differs from this request. Refresh before continuing.",
  native_business_source_retention_unavailable: "Retained installation state is unavailable. Restore access before retrying.",
  native_business_source_retention_conflict: "Retained installation state disagrees. Recovery requires checking every copy.",
  policy_authority_busy: "Another policy operation is running. Wait, then refresh.",
  native_business_source_unavailable: "The saved installation could not be verified. Restore its retained state before retrying."
};
function recoveryError(status, payload) {
  let code = "business_policy_recovery_failed";
  if (payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string" && Object.hasOwn(RECOVERY_ERROR_MESSAGES, payload.error)) code = payload.error;
  return new GuardHarnessActionError(status, { error: code, message: RECOVERY_ERROR_MESSAGES[code] ?? "The saved policy could not be recovered. Its approval or installation state needs attention." });
}
async function inspectBusinessPolicy(requestId, candidateDigest) {
  const response = await fetchGuardApi(`/v1/mcp-policy/requests/${encodeURIComponent(requestId)}/decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "inspect-recovery", candidateDigest })
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 409 && payload && typeof payload === "object" && "error" in payload && payload.error === "business_source_recovery_candidate_unavailable") return { state: "unavailable", candidateDigest };
    throw recoveryError(response.status, payload);
  }
  if (!payload || typeof payload !== "object" || !("candidateDigest" in payload) || payload.candidateDigest !== candidateDigest || !("state" in payload) || typeof payload.state !== "string" || !["unavailable", "interrupted", "installed"].includes(payload.state)) {
    throw new Error("The saved policy inspection was not confirmed. Refresh before continuing.");
  }
  if (payload.state !== "unavailable" && (!("policy" in payload) || !payload.policy || typeof payload.policy !== "object" || Array.isArray(payload.policy) || !("provenanceRedacted" in payload) || payload.provenanceRedacted !== true)) {
    throw new Error("The saved policy rules were not confirmed. Refresh before continuing.");
  }
  if (!("requestRecovered" in payload) || typeof payload.requestRecovered !== "boolean") {
    throw new Error("The request recovery state was not confirmed. Refresh before continuing.");
  }
  return payload;
}
async function recoverBusinessPolicy(input) {
  const response = await fetchGuardApi(`/v1/mcp-policy/requests/${encodeURIComponent(input.requestId)}/decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "recover", ...input })
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw recoveryError(response.status, payload);
  }
  if (!payload || typeof payload !== "object" || !("installationRecovered" in payload) || payload.installationRecovered !== true || !("sourceDigest" in payload) || payload.sourceDigest !== input.candidateDigest) {
    throw new Error("Recovery was not confirmed for this policy. Refresh before continuing.");
  }
}
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
  return digest.length <= 16 ? digest : `${digest.slice(0, 12)}…${digest.slice(-4)}`;
}
function formatTimestamp(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(void 0, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function SummaryField(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "bg-white px-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[11px] font-medium uppercase tracking-wider text-slate-500", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 min-w-0", children: props.children })
  ] });
}
function PlanCountCard(props) {
  const extraItems = props.items.length > 8 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "text-slate-400", children: [
    "+",
    props.items.length - 8,
    " more"
  ] }) : null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-xl border px-4 py-3 ${planToneClass(props.tone)}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider", children: [
        props.icon,
        props.label
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-lg font-semibold", children: props.count })
    ] }),
    props.items.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "mt-2 space-y-1 text-[13px] leading-5 text-slate-700", children: [
      props.items.slice(0, 8).map((item, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "break-all", children: item }, `${props.label}-${index}-${item}`)),
      extraItems
    ] }) : null
  ] });
}
const BusinessPolicyRecoveryPanel = reactExports.lazy(() => __vitePreload(() => import("./business-policy-recovery-panel.js"), true ? __vite__mapDeps([0,1,2]) : void 0).then(
  (module) => ({ default: module.BusinessPolicyRecoveryPanel })
));
function McpPolicyRequestPanel(props) {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [outcome, setOutcome] = reactExports.useState(null);
  const [approvalPassword, setApprovalPassword] = reactExports.useState("");
  const [approvalTotpCode, setApprovalTotpCode] = reactExports.useState("");
  const [recoveryCode, setRecoveryCode] = reactExports.useState(null);
  const [installationRecovered, setInstallationRecovered] = reactExports.useState(false);
  const [inspection, setInspection] = reactExports.useState(null);
  const [inspectionError, setInspectionError] = reactExports.useState(null);
  const load = reactExports.useCallback(async () => {
    setState({ kind: "loading" });
    setOutcome(null);
    setRecoveryCode(null);
    setInstallationRecovered(false);
    setInspection(null);
    setInspectionError(null);
    setApprovalPassword("");
    setApprovalTotpCode("");
    try {
      const request2 = await fetchMcpPolicyRequest(props.requestId);
      if (request2 === null) {
        setState({ kind: "not-found" });
        return;
      }
      try {
        const inspected = await inspectBusinessPolicy(request2.requestId, request2.candidateDigest);
        setInspection(inspected);
        setInstallationRecovered(inspected.state === "installed");
      } catch {
        setInspectionError("Saved installation state could not be verified. Refresh before approving; you can still decline this request.");
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
        setRecoveryCode(error instanceof GuardHarnessActionError ? error.payload?.error ?? null : null);
        const message = error instanceof Error && error.message ? error.message : `Unable to ${action} this request.`;
        setOutcome({ kind: "failed", message });
        try {
          const inspected = await inspectBusinessPolicy(request2.requestId, request2.candidateDigest);
          setInspection(inspected);
          setInstallationRecovered(inspected.state === "installed");
        } catch {
          setInspection(null);
        }
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
  const recoveryRequired = inspection?.state === "interrupted" || RECOVERY_SOURCE_ERRORS.has(recoveryCode ?? request.failureCode ?? "");
  const requestRecovered = inspection?.requestRecovered === true;
  let failureMessage = "";
  if (outcome?.kind === "failed") failureMessage = outcome.message;
  if (recoveryRequired) failureMessage = "Policy installation needs attention. Review the saved policy below before approving recovery.";
  const actable = isActable(request);
  const resolving = state.kind === "resolving";
  const approving = resolving && state.action === "approve";
  const declining = resolving && state.action === "decline";
  const approveDisabled = recoveryRequired || installationRecovered || requestRecovered || inspectionError !== null || !actable || resolving || isApprovalProofSubmitDisabled(
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
          failureMessage
        ] })
      }
    ) : null,
    request.activeEnforcementWarning && !recoveryRequired ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4", "aria-hidden": "true" }),
      "This request is active and waiting for your decision."
    ] }) }) : null,
    request.failureCode !== null && request.failureCode.length > 0 && !recoveryRequired ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800", children: [
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
    recoveryRequired || installationRecovered || requestRecovered ? /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-slate-600", children: "Loading saved policy review…" }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      BusinessPolicyRecoveryPanel,
      {
        requestId: request.requestId,
        candidateDigest: request.candidateDigest,
        approvalGate: props.approvalGate,
        policy: inspection?.policy,
        installed: installationRecovered,
        requestRecovered,
        recoverPolicy: recoverBusinessPolicy,
        onRecovered: () => {
          setInstallationRecovered(true);
          setOutcome(null);
          props.onResolved?.();
        }
      },
      request.requestId
    ) }) : null,
    request.isTerminal || request.isExpired ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }),
      "This request is ",
      request.isExpired ? "expired" : "resolved",
      " and can no longer be acted on."
    ] }) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "mcp-policy-actions", className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Actions" }),
      inspectionError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-sm text-slate-600", children: inspectionError }) : null,
      actable && !installationRecovered && !recoveryRequired && !requestRecovered && !inspectionError ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-md rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-4", children: [
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
export {
  McpPolicyRequestPanel
};
