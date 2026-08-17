import { r as reactExports, a7 as fetchSettings, ay as buildApprovalProofCredentials, aw as isApprovalProofSubmitDisabled, j as jsxRuntimeExports, S as SectionLabel, ax as ApprovalProofFieldInputs, A as ActionButton } from "../guard-dashboard.js";
async function fetchResolvedApprovalGate(fetcher = fetchSettings) {
  const payload = await fetcher();
  return payload.settings.approval_gate ?? null;
}
function useResolvedApprovalGate(initialGate) {
  const [resolvedApprovalGate, setResolvedApprovalGate] = reactExports.useState(initialGate);
  reactExports.useEffect(() => {
    setResolvedApprovalGate(initialGate);
  }, [initialGate]);
  const resolveApprovalGate = reactExports.useCallback(async (options) => {
    if (resolvedApprovalGate !== null) {
      return resolvedApprovalGate;
    }
    try {
      const gate = await fetchResolvedApprovalGate();
      setResolvedApprovalGate(gate);
      return gate;
    } catch (error) {
      if (options?.failClosed) {
        throw error;
      }
      return null;
    }
  }, [resolvedApprovalGate]);
  return { resolvedApprovalGate, resolveApprovalGate };
}
function ApprovalProofModal(props) {
  const { title, detail, confirmLabel, approvalGate, busy = false, error = null, onCancel, onConfirm } = props;
  const [password, setPassword] = reactExports.useState("");
  const [totpCode, setTotpCode] = reactExports.useState("");
  const handlePasswordChange = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotpChange = reactExports.useCallback((event) => {
    setTotpCode(event.target.value);
  }, []);
  const handleConfirm = reactExports.useCallback(() => {
    onConfirm(buildApprovalProofCredentials(approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }));
  }, [approvalGate, onConfirm, password, totpCode]);
  const confirmDisabled = isApprovalProofSubmitDisabled(
    approvalGate,
    { approvalPassword: password, approvalTotpCode: totpCode },
    busy
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 flex items-center justify-center bg-brand-dark/30 px-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "approval-proof-modal-title",
      className: "w-full max-w-md rounded-xl border border-slate-200 bg-white p-5 shadow-xl",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Approval required" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "approval-proof-modal-title", className: "mt-2 text-base font-semibold text-brand-dark", children: title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: detail }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          ApprovalProofFieldInputs,
          {
            approvalGate,
            approvalPassword: password,
            approvalTotpCode: totpCode,
            onApprovalPasswordChange: handlePasswordChange,
            onApprovalTotpCodeChange: handleTotpChange
          }
        ) }),
        error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.06] px-3 py-2 text-sm text-brand-attention", children: error }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex justify-end gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: onCancel, disabled: busy, children: "Cancel" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleConfirm, disabled: confirmDisabled, children: busy ? "Repairing…" : confirmLabel })
        ] })
      ]
    }
  ) });
}
export {
  ApprovalProofModal as A,
  useResolvedApprovalGate as u
};
