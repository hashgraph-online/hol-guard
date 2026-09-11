import { r as reactExports, L as useFocusTrap, ai as isApprovalProofSubmitDisabled, aM as buildApprovalProofCredentials, j as jsxRuntimeExports, S as SectionLabel, ak as ApprovalProofFieldInputs, A as ActionButton } from "../guard-dashboard.js";
function ApprovalProofModal(props) {
  const {
    title,
    detail,
    confirmLabel,
    approvalGate,
    busy = false,
    busyLabel = "Repairing…",
    error = null,
    requireFreshTotp = false,
    onCancel,
    onConfirm
  } = props;
  const [password, setPassword] = reactExports.useState("");
  const [totpCode, setTotpCode] = reactExports.useState("");
  const formRef = reactExports.useRef(null);
  useFocusTrap(true, formRef);
  const handlePasswordChange = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotpChange = reactExports.useCallback((event) => {
    setTotpCode(event.target.value);
  }, []);
  const confirmDisabled = isApprovalProofSubmitDisabled(
    approvalGate,
    { approvalPassword: password, approvalTotpCode: totpCode },
    busy,
    requireFreshTotp
  );
  const handleSubmit = reactExports.useCallback((event) => {
    event.preventDefault();
    if (confirmDisabled) {
      return;
    }
    onConfirm(buildApprovalProofCredentials(
      approvalGate,
      { approvalPassword: password, approvalTotpCode: totpCode },
      requireFreshTotp
    ));
  }, [approvalGate, confirmDisabled, onConfirm, password, requireFreshTotp, totpCode]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 flex items-center justify-center bg-brand-dark/30 px-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "form",
    {
      ref: formRef,
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "approval-proof-modal-title",
      "aria-describedby": "approval-proof-modal-detail",
      className: "w-full max-w-md rounded-xl border border-slate-200 bg-white p-5 shadow-xl",
      onSubmit: handleSubmit,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Approval required" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "approval-proof-modal-title", className: "mt-2 text-base font-semibold text-brand-dark", children: title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: "approval-proof-modal-detail", className: "mt-1 text-sm text-slate-500", children: detail }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          ApprovalProofFieldInputs,
          {
            approvalGate,
            approvalPassword: password,
            approvalTotpCode: totpCode,
            requireFreshTotp,
            onApprovalPasswordChange: handlePasswordChange,
            onApprovalTotpCodeChange: handleTotpChange
          }
        ) }),
        error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.06] px-3 py-2 text-sm text-brand-attention", children: error }) : null,
        busy ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "p",
          {
            role: "status",
            tabIndex: 0,
            className: "mt-4 text-sm font-medium text-brand-dark focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40",
            children: busyLabel
          }
        ) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex justify-end gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { type: "button", variant: "outline", onClick: onCancel, disabled: busy, children: "Cancel" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { type: "submit", disabled: confirmDisabled, children: busy ? busyLabel : confirmLabel })
        ] })
      ]
    }
  ) });
}
export {
  ApprovalProofModal as A
};
