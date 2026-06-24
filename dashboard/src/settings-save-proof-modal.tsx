import { useCallback, useEffect, useRef, useState, type ChangeEvent } from "react";
import { HiMiniKey } from "react-icons/hi2";

import { ActionButton, SectionLabel } from "./approval-center-primitives";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { useFocusTrap } from "./use-focus-trap";

export type SettingsSaveProofMode =
  | "verify-save"
  | "setup-gate"
  | "change-password"
  | "maintenance";

export type SettingsSaveProofCredentials = {
  currentPassword?: string;
  newPassword?: string;
  confirmPassword?: string;
  totpCode?: string;
};

type SettingsSaveProofModalProps = {
  open: boolean;
  mode: SettingsSaveProofMode;
  gate: GuardApprovalGatePublicConfig | null;
  title: string;
  detail: string;
  confirmLabel: string;
  error: string | null;
  pending: boolean;
  onCancel: () => void;
  onConfirm: (credentials: SettingsSaveProofCredentials) => void;
};

export function resolveSettingsSaveProofKind(input: {
  savedGateEnabled: boolean;
  wasConfigured: boolean;
  draftGateEnabled: boolean;
  changingPassword: boolean;
}): SettingsSaveProofMode | null {
  if (input.changingPassword && input.wasConfigured) {
    return "change-password";
  }
  if (!input.wasConfigured && input.draftGateEnabled) {
    return "setup-gate";
  }
  if (input.wasConfigured && input.draftGateEnabled && !input.savedGateEnabled) {
    return "verify-save";
  }
  if (input.savedGateEnabled) {
    return "verify-save";
  }
  return null;
}

export function requiresSettingsSaveProof(kind: SettingsSaveProofMode | null): boolean {
  return kind !== null;
}

export function resolveSettingsSaveProofModalCopy(input: {
  mode: SettingsSaveProofMode;
  gateSettingsChanged: boolean;
  maintenanceAction?:
    | "clear-approvals"
    | "clear-queue"
    | "revoke-cooldown"
    | "disable-totp"
    | "import-settings"
    | "reset-settings";
}): { title: string; detail: string; confirmLabel: string } {
  if (input.mode === "setup-gate") {
    return {
      title: "Set your approval password",
      detail: "Choose a password Guard will ask for before allow or trust changes stick.",
      confirmLabel: "Save settings",
    };
  }
  if (input.mode === "change-password") {
    return {
      title: "Change approval password",
      detail: "Confirm your approval proof, then choose a new password.",
      confirmLabel: "Update password",
    };
  }
  if (input.mode === "maintenance") {
    if (input.maintenanceAction === "clear-approvals") {
      return {
        title: "Clear saved approvals",
        detail: "Guard needs fresh proof before it removes saved allow decisions.",
        confirmLabel: "Clear approvals",
      };
    }
    if (input.maintenanceAction === "clear-queue") {
      return {
        title: "Clear review queue",
        detail: "Guard needs fresh proof before it removes pending review items.",
        confirmLabel: "Clear queue",
      };
    }
    if (input.maintenanceAction === "revoke-cooldown") {
      return {
        title: "Revoke cooldown",
        detail: "Confirm your identity before Guard ends the active cooldown.",
        confirmLabel: "Revoke cooldown",
      };
    }
    if (input.maintenanceAction === "disable-totp") {
      return {
        title: "Disconnect authenticator",
        detail: "Confirm a current app code to remove this second factor.",
        confirmLabel: "Disconnect",
      };
    }
    if (input.maintenanceAction === "import-settings") {
      return {
        title: "Import settings",
        detail: "Guard needs fresh proof before it replaces your local settings from a file.",
        confirmLabel: "Import settings",
      };
    }
    if (input.maintenanceAction === "reset-settings") {
      return {
        title: "Reset settings",
        detail: "Guard needs fresh proof before it restores every local setting to defaults.",
        confirmLabel: "Reset settings",
      };
    }
    return {
      title: "Confirm your identity",
      detail: "Guard needs fresh proof before this cleanup can continue.",
      confirmLabel: "Continue",
    };
  }
  if (input.gateSettingsChanged) {
    return {
      title: "Confirm before saving gate changes",
      detail: "Enter your approval proof so Guard can apply the gate updates you chose.",
      confirmLabel: "Save settings",
    };
  }
  return {
    title: "Confirm before saving",
    detail: "Enter your approval proof so Guard can save these settings.",
    confirmLabel: "Save settings",
  };
}

export function isSettingsSaveProofSubmitDisabled(
  mode: SettingsSaveProofMode,
  credentials: SettingsSaveProofCredentials,
  totpRequired: boolean,
): boolean {
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
  if (current.length === 0) {
    return true;
  }
  return false;
}

export function SettingsSaveProofModal(props: SettingsSaveProofModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const totpRef = useRef<HTMLInputElement>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");

  useFocusTrap(props.open, dialogRef);

  useEffect(() => {
    if (!props.open) {
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setTotpCode("");
      return;
    }
    const timer = setTimeout(() => {
      if (
        props.gate?.totp_enabled === true
        && (props.mode === "verify-save" || props.mode === "change-password" || props.mode === "maintenance")
      ) {
        totpRef.current?.focus();
      } else {
        passwordRef.current?.focus();
      }
    }, 50);
    return () => clearTimeout(timer);
  }, [props.gate?.totp_enabled, props.open, props.mode]);

  useEffect(() => {
    if (props.open) {
      document.documentElement.dataset.guardModalOpen = String(
        Number(document.documentElement.dataset.guardModalOpen ?? 0) + 1,
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
    return undefined;
  }, [props.open]);

  const totpRequired = props.gate?.totp_enabled === true
    && (props.mode === "verify-save" || props.mode === "change-password" || props.mode === "maintenance");
  const needsCurrentPassword = props.mode !== "setup-gate" && !totpRequired;

  const handleCurrentPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setCurrentPassword(event.target.value);
  }, []);

  const handleNewPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setNewPassword(event.target.value);
  }, []);

  const handleConfirmPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setConfirmPassword(event.target.value);
  }, []);

  const handleTotpChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotpCode(event.target.value);
  }, []);

  const handleBackdropClick = useCallback(
    (event: React.MouseEvent<HTMLDivElement>) => {
      if (event.target === event.currentTarget && !props.pending) {
        props.onCancel();
      }
    },
    [props.onCancel, props.pending],
  );

  const handleConfirm = useCallback(() => {
    props.onConfirm({
      ...(currentPassword.trim().length > 0 ? { currentPassword } : {}),
      ...(newPassword.trim().length > 0 ? { newPassword } : {}),
      ...(confirmPassword.trim().length > 0 ? { confirmPassword } : {}),
      ...(totpCode.trim().length > 0 ? { totpCode } : {}),
    });
  }, [confirmPassword, currentPassword, newPassword, props, totpCode]);

  const credentials: SettingsSaveProofCredentials = {
    currentPassword,
    newPassword,
    confirmPassword,
    totpCode,
  };
  const confirmDisabled = isSettingsSaveProofSubmitDisabled(props.mode, credentials, totpRequired);

  if (!props.open) {
    return null;
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm"
      onClick={handleBackdropClick}
      role="dialog"
      aria-modal="true"
      aria-labelledby="settings-save-proof-title"
    >
      <div
        ref={dialogRef}
        className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl"
      >
        <div className="flex items-center gap-3">
          <span className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-brand-blue/10">
            <HiMiniKey className="h-5 w-5 text-brand-blue" aria-hidden="true" />
          </span>
          <div>
            <SectionLabel>Approval required</SectionLabel>
            <h2 id="settings-save-proof-title" className="text-lg font-semibold tracking-tight text-brand-dark">
              {props.title}
            </h2>
            <p className="text-sm text-brand-dark/70">{props.detail}</p>
          </div>
        </div>

        <div className="mt-5 space-y-3">
          {needsCurrentPassword ? (
            <label className="block">
              <span className="text-sm font-semibold text-brand-dark">Approval password</span>
              <input
                ref={passwordRef}
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={handleCurrentPasswordChange}
                className="mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              />
            </label>
          ) : null}
          {props.mode === "setup-gate" || props.mode === "change-password" ? (
            <>
              <label className="block">
                <span className="text-sm font-semibold text-brand-dark">
                  {props.mode === "setup-gate" ? "Password" : "New password"}
                </span>
                <input
                  ref={props.mode === "setup-gate" ? passwordRef : undefined}
                  type="password"
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={handleNewPasswordChange}
                  className="mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                />
              </label>
              <label className="block">
                <span className="text-sm font-semibold text-brand-dark">Confirm password</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={handleConfirmPasswordChange}
                  className="mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                />
              </label>
            </>
          ) : null}
          {totpRequired ? (
            <label className="block">
              <span className="text-sm font-semibold text-brand-dark">Authenticator code</span>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                ref={totpRef}
                autoComplete="one-time-code"
                value={totpCode}
                onChange={handleTotpChange}
                placeholder="123456"
                className="mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm tracking-[0.28em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              />
            </label>
          ) : null}
        </div>

        {props.error !== null ? (
          <p className="mt-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark">
            {props.error}
          </p>
        ) : null}

        <div className="mt-6 flex flex-col gap-2 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={props.onCancel}
            disabled={props.pending}
            className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
          >
            Go back
          </button>
          <ActionButton onClick={handleConfirm} disabled={props.pending || confirmDisabled}>
            {props.pending ? "Working…" : props.confirmLabel}
          </ActionButton>
        </div>
      </div>
    </div>
  );
}
