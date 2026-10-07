import { r as reactExports, j as jsxRuntimeExports, as as ApprovalProofFieldInputs, A as ActionButton, at as isApprovalProofSubmitDisabled, au as buildApprovalProofCredentials } from "../guard-dashboard.js";
function BusinessPolicyRecoveryPanel(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const [busy, setBusy] = reactExports.useState(false);
  const [message, setMessage] = reactExports.useState(null);
  const [recovered, setRecovered] = reactExports.useState(false);
  let buttonLabel = "Approve and recover policy";
  if (busy) buttonLabel = "Recovering policy…";
  const showProof = !recovered && !props.installed && props.policy != null;
  async function recover() {
    if (busy || recovered || props.installed || props.policy == null) return;
    const proof = buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }, true);
    setPassword("");
    setTotp("");
    setBusy(true);
    setMessage(null);
    try {
      await props.recoverPolicy({ requestId: props.requestId, candidateDigest: props.candidateDigest, ...proof });
      setRecovered(true);
      setMessage("Policy installation recovered. No app action was sent or replayed.");
      props.onRecovered();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The saved policy could not be recovered. Refresh before retrying.");
    } finally {
      setBusy(false);
    }
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-4 border-t border-slate-200 pt-5", "aria-labelledby": "business-policy-recovery-title", "aria-busy": busy, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "business-policy-recovery-title", className: "text-lg font-semibold text-brand-dark", children: "Recover interrupted policy installation" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-prose text-sm leading-6 text-brand-dark/75", children: "Freshly approve this request’s saved policy to finish its installation. Guard checks that it matches the saved policy and does not replace newer protection. This does not resume an app task or resolve the original request." }),
    props.policy ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { open: true, className: "space-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-sm font-semibold text-brand-dark", children: "Saved policy rules" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: "Author metadata is hidden. The digest identifies the original saved policy." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono text-xs text-brand-dark", "aria-label": "Saved policy digest", children: props.candidateDigest }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("pre", { className: "max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-50 p-3 text-xs text-brand-dark", children: JSON.stringify(props.policy, null, 2) })
    ] }) : null,
    props.installed ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-brand-dark", children: "This policy is already installed. The original request remains unchanged; you can decline it." }) : null,
    props.requestRecovered && !props.installed ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-brand-dark", children: "This request was imported through recovery and cannot be approved again. An interrupted installation can still be recovered with fresh proof." }) : null,
    showProof ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ApprovalProofFieldInputs,
        {
          approvalGate: props.approvalGate ?? null,
          approvalPassword: password,
          approvalTotpCode: totp,
          onApprovalPasswordChange: (event) => setPassword(event.target.value),
          onApprovalTotpCodeChange: (event) => setTotp(event.target.value),
          requireFreshTotp: true,
          requireGate: true
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: () => void recover(), disabled: busy || isApprovalProofSubmitDisabled(props.approvalGate, {
        approvalPassword: password,
        approvalTotpCode: totp
      }, busy, true, true), children: buttonLabel })
    ] }) : null,
    message ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", "aria-live": "polite", className: "text-sm leading-6 text-brand-dark", children: message }) : null
  ] });
}
export {
  BusinessPolicyRecoveryPanel
};
