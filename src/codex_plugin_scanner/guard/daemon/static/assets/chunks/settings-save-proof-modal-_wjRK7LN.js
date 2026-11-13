import { r as reactExports, ae as useFocusTrap, j as jsxRuntimeExports, eE as HiMiniKey, S as SectionLabel, A as ActionButton } from "../guard-dashboard.js";
function resolveSettingsSaveProofKind(input) {
  if (input.draftGateEnabled && !input.savedGateEnabled) {
    return "setup-gate";
  }
  if (input.savedGateEnabled) {
    return "verify-save";
  }
  return null;
}
function requiresSettingsSaveProof(kind) {
  return kind !== null;
}
function resolveSettingsSaveProofModalCopy(input) {
  if (input.mode === "setup-gate") {
    return {
      title: "Set your approval password",
      detail: "Choose a password Guard will ask for before allow or trust changes stick.",
      confirmLabel: "Save settings"
    };
  }
  if (input.mode === "change-password") {
    return {
      title: "Change approval password",
      detail: "Confirm your approval proof, then choose a new password.",
      confirmLabel: "Update password"
    };
  }
  if (input.mode === "maintenance") {
    if (input.maintenanceAction === "clear-approvals") {
      return {
        title: "Clear saved approvals",
        detail: "Guard needs fresh proof before it removes saved allow decisions.",
        confirmLabel: "Clear approvals"
      };
    }
    if (input.maintenanceAction === "clear-queue") {
      return {
        title: "Clear review queue",
        detail: "Guard needs fresh proof before it removes pending review items.",
        confirmLabel: "Clear queue"
      };
    }
    if (input.maintenanceAction === "revoke-cooldown") {
      return {
        title: "Revoke cooldown",
        detail: "Confirm your identity before Guard ends the active cooldown.",
        confirmLabel: "Revoke cooldown"
      };
    }
    if (input.maintenanceAction === "disable-totp") {
      return {
        title: "Disconnect authenticator",
        detail: "Confirm a current app code to remove this second factor.",
        confirmLabel: "Disconnect"
      };
    }
    if (input.maintenanceAction === "import-settings") {
      return {
        title: "Import settings",
        detail: "Guard needs fresh proof before it replaces your local settings from a file.",
        confirmLabel: "Import settings"
      };
    }
    if (input.maintenanceAction === "reset-settings") {
      return {
        title: "Reset settings",
        detail: "Guard needs fresh proof before it restores every local setting to defaults.",
        confirmLabel: "Reset settings"
      };
    }
    return {
      title: "Confirm your identity",
      detail: "Guard needs fresh proof before this cleanup can continue.",
      confirmLabel: "Continue"
    };
  }
  if (input.gateSettingsChanged) {
    return {
      title: "Confirm before saving gate changes",
      detail: "Enter your approval proof so Guard can apply the gate updates you chose.",
      confirmLabel: "Save settings"
    };
  }
  return {
    title: "Confirm before saving",
    detail: "Enter your approval proof so Guard can save these settings.",
    confirmLabel: "Save settings"
  };
}
function isSettingsSaveProofSubmitDisabled(mode, credentials, totpRequired) {
  const current = credentials.currentPassword?.trim() ?? "";
  const next = credentials.newPassword?.trim() ?? "";
  const confirm = credentials.confirmPassword?.trim() ?? "";
  const totp = credentials.totpCode?.trim() ?? "";
  if (mode === "setup-gate") {
    return next.length === 0 || confirm.length === 0 || next !== confirm;
  }
  if (mode === "change-password") {
    if (next.length === 0 || confirm.length === 0 || next !== confirm) {
      return true;
    }
    return totpRequired ? totp.length === 0 : current.length === 0;
  }
  if (totpRequired) {
    return totp.length === 0;
  }
  return current.length === 0;
}
function SettingsSaveProofModal(props) {
  const dialogRef = reactExports.useRef(null);
  const passwordRef = reactExports.useRef(null);
  const totpRef = reactExports.useRef(null);
  const [currentPassword, setCurrentPassword] = reactExports.useState("");
  const [newPassword, setNewPassword] = reactExports.useState("");
  const [confirmPassword, setConfirmPassword] = reactExports.useState("");
  const [totpCode, setTotpCode] = reactExports.useState("");
  useFocusTrap(props.open, dialogRef);
  reactExports.useEffect(() => {
    if (!props.open) {
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setTotpCode("");
      return;
    }
    const timer = setTimeout(() => {
      if (props.gate?.totp_enabled === true && (props.mode === "verify-save" || props.mode === "change-password" || props.mode === "maintenance")) {
        totpRef.current?.focus();
      } else {
        passwordRef.current?.focus();
      }
    }, 50);
    return () => clearTimeout(timer);
  }, [props.gate?.totp_enabled, props.open, props.mode]);
  reactExports.useEffect(() => {
    if (props.open) {
      document.documentElement.dataset.guardModalOpen = String(
        Number(document.documentElement.dataset.guardModalOpen ?? 0) + 1
      );
      return () => {
        const count = Number(document.documentElement.dataset.guardModalOpen ?? 1) - 1;
        if (count <= 0) {
          delete document.documentElement.dataset.guardModalOpen;
        } else {
          document.documentElement.dataset.guardModalOpen = String(count);
        }
      };
    }
    return void 0;
  }, [props.open]);
  const totpRequired = props.gate?.totp_enabled === true && (props.mode === "verify-save" || props.mode === "change-password" || props.mode === "maintenance");
  const needsCurrentPassword = props.mode !== "setup-gate" && !totpRequired;
  const handleCurrentPasswordChange = reactExports.useCallback((event) => {
    setCurrentPassword(event.target.value);
  }, []);
  const handleNewPasswordChange = reactExports.useCallback((event) => {
    setNewPassword(event.target.value);
  }, []);
  const handleConfirmPasswordChange = reactExports.useCallback((event) => {
    setConfirmPassword(event.target.value);
  }, []);
  const handleTotpChange = reactExports.useCallback((event) => {
    setTotpCode(event.target.value);
  }, []);
  const handleBackdropClick = reactExports.useCallback(
    (event) => {
      if (event.target === event.currentTarget && !props.pending) {
        props.onCancel();
      }
    },
    [props.onCancel, props.pending]
  );
  const handleConfirm = reactExports.useCallback((event) => {
    event.preventDefault();
    if (props.pending || isSettingsSaveProofSubmitDisabled(
      props.mode,
      { currentPassword, newPassword, confirmPassword, totpCode },
      totpRequired
    )) {
      return;
    }
    props.onConfirm({
      ...currentPassword.trim().length > 0 ? { currentPassword } : {},
      ...newPassword.trim().length > 0 ? { newPassword } : {},
      ...confirmPassword.trim().length > 0 ? { confirmPassword } : {},
      ...totpCode.trim().length > 0 ? { totpCode } : {}
    });
  }, [confirmPassword, currentPassword, newPassword, props, totpCode, totpRequired]);
  const credentials = {
    currentPassword,
    newPassword,
    confirmPassword,
    totpCode
  };
  const confirmDisabled = isSettingsSaveProofSubmitDisabled(props.mode, credentials, totpRequired);
  if (!props.open) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm",
      onClick: handleBackdropClick,
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "settings-save-proof-title",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "form",
        {
          ref: dialogRef,
          className: "w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl",
          onSubmit: handleConfirm,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 items-center justify-center rounded-full bg-brand-blue/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniKey, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Approval required" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "settings-save-proof-title", className: "text-lg font-semibold tracking-tight text-brand-dark", children: props.title }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: props.detail })
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 space-y-3", children: [
              needsCurrentPassword ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "Approval password" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    ref: passwordRef,
                    type: "password",
                    autoComplete: "current-password",
                    value: currentPassword,
                    onChange: handleCurrentPasswordChange,
                    className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                  }
                )
              ] }) : null,
              props.mode === "setup-gate" || props.mode === "change-password" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: props.mode === "setup-gate" ? "Password" : "New password" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      ref: props.mode === "setup-gate" ? passwordRef : void 0,
                      type: "password",
                      autoComplete: "new-password",
                      value: newPassword,
                      onChange: handleNewPasswordChange,
                      className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                    }
                  )
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "Confirm password" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      type: "password",
                      autoComplete: "new-password",
                      value: confirmPassword,
                      onChange: handleConfirmPasswordChange,
                      className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                    }
                  )
                ] })
              ] }) : null,
              totpRequired ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "Authenticator code" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    type: "text",
                    inputMode: "numeric",
                    pattern: "[0-9]*",
                    maxLength: 6,
                    ref: totpRef,
                    autoComplete: "one-time-code",
                    value: totpCode,
                    onChange: handleTotpChange,
                    placeholder: "123456",
                    className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm tracking-[0.28em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                  }
                )
              ] }) : null
            ] }),
            props.error !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark", children: props.error }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex flex-col gap-2 sm:flex-row sm:justify-end", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  type: "button",
                  onClick: props.onCancel,
                  disabled: props.pending,
                  className: "rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50",
                  children: "Go back"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { type: "submit", disabled: props.pending || confirmDisabled, children: props.pending ? "Working…" : props.confirmLabel })
            ] })
          ]
        }
      )
    }
  );
}
export {
  SettingsSaveProofModal as S,
  requiresSettingsSaveProof as a,
  resolveSettingsSaveProofModalCopy as b,
  resolveSettingsSaveProofKind as r
};
