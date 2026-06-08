import { r as reactExports, j as jsxRuntimeExports, S as SectionLabel, A as ActionButton, U as fetchSettings } from "../guard-dashboard.js";
function ApprovalProofModal(props) {
  const { title, detail, confirmLabel, approvalGate, onCancel, onConfirm } = props;
  const [password, setPassword] = reactExports.useState("");
  const [totpCode, setTotpCode] = reactExports.useState("");
  const handlePasswordChange = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotpChange = reactExports.useCallback((event) => {
    setTotpCode(event.target.value);
  }, []);
  const handleConfirm = reactExports.useCallback(() => {
    onConfirm({
      approval_password: password,
      ...approvalGate?.totp_enabled === true ? { approval_totp_code: totpCode } : {}
    });
  }, [approvalGate, onConfirm, password, totpCode]);
  const confirmDisabled = password.trim() === "" || approvalGate?.totp_enabled === true && totpCode.trim() === "";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 px-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full max-w-md rounded-xl border border-slate-200 bg-white p-5 shadow-xl", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Approval required" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "mt-2 text-base font-semibold text-brand-dark", children: title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: detail }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-4 block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.15em] text-slate-500", children: "Approval password" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          type: "password",
          value: password,
          onChange: handlePasswordChange,
          autoComplete: "current-password",
          className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      )
    ] }),
    approvalGate?.totp_enabled === true && /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-3 block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.15em] text-slate-500", children: "Authenticator code" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          type: "text",
          inputMode: "numeric",
          pattern: "[0-9]*",
          value: totpCode,
          onChange: handleTotpChange,
          className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex justify-end gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: onCancel, children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleConfirm, disabled: confirmDisabled, children: confirmLabel })
    ] })
  ] }) });
}
function useResolvedApprovalGate(initialGate) {
  const [resolvedApprovalGate, setResolvedApprovalGate] = reactExports.useState(initialGate);
  reactExports.useEffect(() => {
    setResolvedApprovalGate(initialGate);
  }, [initialGate]);
  const resolveApprovalGate = reactExports.useCallback(async () => {
    if (resolvedApprovalGate !== null) {
      return resolvedApprovalGate;
    }
    try {
      const payload = await fetchSettings();
      const gate = payload.settings.approval_gate ?? null;
      setResolvedApprovalGate(gate);
      return gate;
    } catch {
      return null;
    }
  }, [resolvedApprovalGate]);
  return { resolvedApprovalGate, resolveApprovalGate };
}
export {
  ApprovalProofModal as A,
  useResolvedApprovalGate as u
};
