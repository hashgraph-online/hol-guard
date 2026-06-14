import { au as GuardHarnessActionError, j as jsxRuntimeExports, r as reactExports, N as HiMiniKey, A as ActionButton, S as SectionLabel, Y as fetchSettings } from "../guard-dashboard.js";
const APPROVAL_GATE_REQUIRED_CODES = /* @__PURE__ */ new Set([
  "approval_gate_required",
  "approval_gate_password_required",
  "approval_gate_totp_required"
]);
const APPROVAL_GATE_NON_CREDENTIAL_CODES = /* @__PURE__ */ new Set([
  "approval_gate_locked",
  "approval_gate_invalid_password",
  "approval_gate_totp_invalid",
  "approval_gate_recovery_required",
  "approval_gate_weak_password"
]);
const APPROVAL_CREDENTIAL_PROMPT_MESSAGE = /approval(?:\s+gate)?\s+password is required|totp code is required/i;
const SUPPLY_CHAIN_CONNECT_ERROR_CODES = /* @__PURE__ */ new Set([
  "guard_cloud_connect_required",
  "guard_cloud_reconnect_required"
]);
const GUARD_FETCH_NETWORK_ERROR_MESSAGE = /failed to fetch|networkerror|load failed/i;
function isGuardHarnessActionError(error) {
  if (error instanceof GuardHarnessActionError) {
    return true;
  }
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const candidate = error;
  return candidate.name === "GuardHarnessActionError" && typeof candidate.status === "number";
}
function readHarnessActionErrorCode(error) {
  if (!isGuardHarnessActionError(error)) {
    return null;
  }
  const code = error.payload?.error;
  if (typeof code !== "string") {
    return null;
  }
  const trimmed = code.trim();
  return trimmed.length > 0 ? trimmed : null;
}
function readHarnessActionErrorMessage(error) {
  if (!isGuardHarnessActionError(error)) {
    if (error instanceof Error && error.message.trim()) {
      return error.message.trim();
    }
    return null;
  }
  const message = error.payload?.message ?? error.message;
  if (typeof message !== "string") {
    return null;
  }
  const trimmed = message.trim();
  return trimmed.length > 0 ? trimmed : null;
}
function isApprovalCredentialPromptCode(code) {
  if (code === null) {
    return false;
  }
  if (APPROVAL_GATE_REQUIRED_CODES.has(code)) {
    return true;
  }
  return APPROVAL_CREDENTIAL_PROMPT_MESSAGE.test(code);
}
function isSupplyChainSyncConnectError(error) {
  const code = readHarnessActionErrorCode(error);
  return code !== null && SUPPLY_CHAIN_CONNECT_ERROR_CODES.has(code);
}
function readHarnessActionUserMessage(error, fallback) {
  if (error instanceof Error && GUARD_FETCH_NETWORK_ERROR_MESSAGE.test(error.message)) {
    return "Guard lost connection while syncing supply-chain intel. Confirm the local daemon is still running, then try again.";
  }
  const structuredMessage = readHarnessActionErrorMessage(error);
  if (structuredMessage !== null) {
    return structuredMessage;
  }
  return fallback;
}
function isApprovalGateRequiredError(error) {
  const code = readHarnessActionErrorCode(error);
  if (code !== null && APPROVAL_GATE_NON_CREDENTIAL_CODES.has(code)) {
    return false;
  }
  if (isApprovalCredentialPromptCode(code)) {
    return true;
  }
  const message = readHarnessActionErrorMessage(error);
  if (message !== null && APPROVAL_CREDENTIAL_PROMPT_MESSAGE.test(message)) {
    return true;
  }
  return false;
}
function resolveApprovalGateSyncFailure(error, options) {
  const hasCredentials = options?.hasCredentials === true;
  if (!hasCredentials && isApprovalGateRequiredError(error)) {
    return { kind: "approval_required" };
  }
  return {
    kind: "failed",
    message: readHarnessActionUserMessage(error, "Sync failed.")
  };
}
function ApprovalProofFieldInputs(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "Approval password" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          ref: props.passwordRef,
          type: "password",
          autoComplete: "current-password",
          value: props.approvalPassword,
          onChange: props.onApprovalPasswordChange,
          className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      )
    ] }),
    props.approvalGate?.totp_enabled === true ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "Authenticator code" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          type: "text",
          inputMode: "numeric",
          pattern: "[0-9]*",
          autoComplete: "one-time-code",
          value: props.approvalTotpCode,
          onChange: props.onApprovalTotpCodeChange,
          className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      )
    ] }) : null
  ] });
}
function ApprovalProofInline(props) {
  const passwordRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    const timer = window.setTimeout(() => {
      passwordRef.current?.focus();
    }, 50);
    return () => window.clearTimeout(timer);
  }, []);
  const submitDisabled = props.submitBusy || props.approvalPassword.trim() === "" || props.approvalGate?.totp_enabled === true && props.approvalTotpCode.trim() === "";
  const handleKeyDown = reactExports.useCallback(
    (event) => {
      if (event.key === "Enter" && !submitDisabled) {
        event.preventDefault();
        props.onSubmit();
      }
    },
    [props.onSubmit, submitDisabled]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-5", onKeyDown: handleKeyDown, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] px-4 py-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-blue/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniKey, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: "Approval proof required" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-relaxed text-slate-600", children: "Enter your local approval password before Guard syncs supply-chain intel on this device." })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofFieldInputs,
      {
        approvalGate: props.approvalGate,
        approvalPassword: props.approvalPassword,
        approvalTotpCode: props.approvalTotpCode,
        passwordRef,
        onApprovalPasswordChange: props.onApprovalPasswordChange,
        onApprovalTotpCodeChange: props.onApprovalTotpCodeChange
      }
    ),
    props.error !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-attention", role: "alert", children: props.error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-center", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: props.onSubmit, disabled: submitDisabled, children: props.submitLabel }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: props.onBack, disabled: props.submitBusy, children: "Go back" })
    ] })
  ] });
}
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
function resolveManagerCoverageStatus(protection, manager) {
  if (protection === void 0) {
    return "unprotected";
  }
  if (protection.protected_managers.includes(manager)) {
    return "protected";
  }
  if (protection.installed_managers.includes(manager)) {
    if (protection.path_status === "restart_required") {
      return "restart_required";
    }
    return "path_repair";
  }
  return "unprotected";
}
function buildSupplyChainStats(snapshot) {
  const managedInstalls = snapshot.managed_installs ?? [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const supportedManagers = protection?.supported_managers ?? [];
  const protectedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "protected"
  ).length;
  const stagedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "restart_required"
  ).length;
  const repairRequiredManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "path_repair"
  ).length;
  const unprotectedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "unprotected"
  ).length;
  return {
    totalApps: managedInstalls.length,
    activeApps: managedInstalls.filter((install) => install.active).length,
    preventedInstalls: managedInstalls.filter((install) => !install.active).length,
    protectedManagers,
    stagedManagers,
    repairRequiredManagers,
    unprotectedManagers
  };
}
export {
  ApprovalProofInline as A,
  isSupplyChainSyncConnectError as a,
  resolveApprovalGateSyncFailure as b,
  isApprovalGateRequiredError as c,
  readHarnessActionUserMessage as d,
  ApprovalProofModal as e,
  buildSupplyChainStats as f,
  resolveManagerCoverageStatus as g,
  isGuardHarnessActionError as i,
  readHarnessActionErrorCode as r,
  useResolvedApprovalGate as u
};
