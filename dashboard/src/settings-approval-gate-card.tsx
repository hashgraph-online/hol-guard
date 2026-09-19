import { type ChangeEvent } from "react";
import { ActionButton, SectionLabel, Tag } from "./approval-center-primitives";
import { type GuardApprovalGateTotpEnrollment } from "./guard-api";
import { approvalGateCooldownLabel } from "./approval-gate-utils";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { ApprovalPasswordSection } from "./settings/approval-password-copy";
import { TotpSetupStep, hasApprovalGateSettingsChanged, effectiveApprovalGateCooldownSeconds } from "./settings-workspace-model";
import { SettingToggle } from "./settings-workspace-cards";
import { TotpSetupModal } from "./settings-totp-setup-modal";

export const cooldownOptions = [
  { value: "0", label: approvalGateCooldownLabel(0) },
  { value: "900", label: approvalGateCooldownLabel(900) },
  { value: "3600", label: approvalGateCooldownLabel(3600) },
];

export type ApprovalGateCardProps = {
  enabled: boolean;
  gateConfig: GuardApprovalGatePublicConfig | null;
  savedGateConfig: GuardApprovalGatePublicConfig | null;
  totpCode: string;
  totpDeviceLabel: string;
  strictAllDecisions: boolean;
  cooldownSeconds: number;
  totpEnrollment: GuardApprovalGateTotpEnrollment | null;
  totpSetupOpen: boolean;
  totpSetupStep: TotpSetupStep;
  totpActionPassword: string;
  totpActionPending: "enroll" | "verify" | "disable" | null;
  totpActionError: string | null;
  onToggle: (event: ChangeEvent<HTMLInputElement>) => void;
  onOpenPasswordChangeModal: (mode?: "change-password" | "setup-gate") => void;
  onTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTotpDeviceLabelChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTotpActionPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onOpenTotpSetup: () => void;
  onCloseTotpSetup: () => void;
  onStrictAllDecisionsChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onCooldownChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  onStartTotpEnrollment: () => void;
  onVerifyTotpEnrollment: () => void;
  onDisableTotp: () => void;
  onRevokeCooldown: () => void;
};

export function ApprovalGateCard(props: ApprovalGateCardProps) {
  const wasConfigured = props.savedGateConfig?.configured === true;
  const gateSettingsChanged = hasApprovalGateSettingsChanged(
    props.savedGateConfig,
    props.enabled,
    props.cooldownSeconds,
    props.strictAllDecisions,
  );
  const showGateDetails = props.enabled || gateSettingsChanged;
  const cooldownActive = props.gateConfig?.cooldown_active === true;
  const cooldownExpiresAt = props.gateConfig?.cooldown_expires_at ?? null;
  const totpEnabled = props.gateConfig?.totp_enabled === true;
  const totpPending = props.gateConfig?.totp_pending === true;
  const failClosed = props.gateConfig?.fail_closed === true;
  const effectiveCooldownSeconds = effectiveApprovalGateCooldownSeconds(props.cooldownSeconds, totpEnabled);
  const cooldownLabel = cooldownExpiresAt
    ? new Date(cooldownExpiresAt).toLocaleTimeString()
    : null;

  return (
    <div className="space-y-4 rounded-xl border border-slate-100 bg-slate-50/40 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <SettingToggle
            id="settings-approval-gate"
            label="Ask for proof on allow decisions"
            checked={props.enabled}
            onChange={props.onToggle}
          />
          <p className="mt-1 text-xs text-slate-500">
            Use a password before allow or trust changes stick. Turn on strict mode to require proof for block decisions too.
          </p>
        </div>
      </div>

      {failClosed && props.enabled && (
        <div className="rounded-lg border border-brand-purple/20 bg-brand-purple/[0.04] px-3 py-2">
          <p className="text-xs text-brand-purple">
            Guard needs your approval setup fixed before trust or policy changes can continue.
          </p>
        </div>
      )}

      {showGateDetails && (
        <div className="space-y-3">
          <ApprovalPasswordSection
            wasConfigured={wasConfigured}
            enabled={props.enabled}
            onOpenPasswordChangeModal={props.onOpenPasswordChangeModal}
          />

          <div className="rounded-xl border border-slate-100 bg-white p-4">
            <SectionLabel>Extra checks</SectionLabel>
            <div className="mt-3 space-y-3">
              <SettingToggle
                id="settings-approval-gate-strict"
                label="Also ask before block decisions"
                checked={props.strictAllDecisions}
                onChange={props.onStrictAllDecisionsChange}
              />
              <label className="block">
                <span className="text-xs font-medium text-slate-500">Cooldown after approval</span>
                <select
                  id="settings-approval-gate-cooldown"
                  value={String(effectiveCooldownSeconds)}
                  onChange={props.onCooldownChange}
                  disabled={totpEnabled}
                  aria-describedby={totpEnabled ? "settings-approval-gate-cooldown-help" : undefined}
                  className="mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-500"
                >
                  {cooldownOptions.map((opt) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
                {totpEnabled ? (
                  <span id="settings-approval-gate-cooldown-help" className="mt-1 block text-xs leading-5 text-slate-500">
                    Authenticator approvals do not use the password cooldown. Your saved password cooldown applies when Authenticator is off.
                  </span>
                ) : null}
              </label>
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-brand-blue/15 bg-white">
            <div className="flex items-center justify-between gap-2">
              <div className="px-4 py-3">
                <SectionLabel>Authenticator app</SectionLabel>
                <p className="mt-1 max-w-xl text-xs leading-5 text-slate-500">
                  Add a six-digit code from Google Authenticator, 1Password, Authy, or iCloud Passwords for high-risk approvals.
                </p>
              </div>
              <div className="px-4">
                <Tag tone={totpEnabled ? "green" : totpPending ? "blue" : "slate"}>
                  {totpEnabled ? "Enabled" : totpPending ? "Pending verification" : "Not connected"}
                </Tag>
              </div>
            </div>
            <div className="border-t border-slate-100 bg-slate-50/50 px-4 py-3">
              {!totpEnabled && !totpPending && (
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="max-w-xl space-y-1">
                    <p className="text-sm font-medium text-brand-dark">Add a second factor for high-risk approvals.</p>
                    <p className="text-xs text-slate-500">
                      Setup opens a guided flow for password confirmation, then QR scan.
                    </p>
                  </div>
                  <ActionButton
                    onClick={props.onOpenTotpSetup}
                    disabled={props.totpActionPending !== null}
                    variant="outline"
                  >
                    Set up authenticator
                  </ActionButton>
                </div>
              )}
              {totpPending && (
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="max-w-xl space-y-1">
                    <p className="text-sm font-medium text-brand-dark">Finish connecting your authenticator app.</p>
                    <p className="text-xs text-slate-500">
                      Open setup to scan the QR code and enter a live six-digit code.
                    </p>
                  </div>
                  <ActionButton
                    onClick={props.onOpenTotpSetup}
                    disabled={props.totpActionPending !== null}
                    variant="outline"
                  >
                    Continue setup
                  </ActionButton>
                </div>
              )}
              {totpEnabled && (
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="max-w-xl text-xs text-slate-500">
                    Disconnecting removes the app code requirement from future high-risk approvals.
                  </p>
                  <ActionButton
                    onClick={props.onDisableTotp}
                    disabled={props.totpActionPending !== null}
                    variant="outline"
                  >
                    {props.totpActionPending === "disable" ? "Disconnecting..." : "Disconnect authenticator"}
                  </ActionButton>
                </div>
              )}
              {props.totpActionError !== null && !props.totpSetupOpen && (
                <p className="mt-2 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark">
                  {props.totpActionError}
                </p>
              )}
            </div>
            {props.totpSetupOpen && (
              <TotpSetupModal
                step={props.totpSetupStep}
                enrollment={props.totpEnrollment}
                deviceLabel={props.totpDeviceLabel}
                actionPassword={props.totpActionPassword}
                totpCode={props.totpCode}
                pending={props.totpActionPending}
                error={props.totpActionError}
                onActionPasswordChange={props.onTotpActionPasswordChange}
                onDeviceLabelChange={props.onTotpDeviceLabelChange}
                onTotpCodeChange={props.onTotpCodeChange}
                onConfirmPassword={props.onStartTotpEnrollment}
                onVerify={props.onVerifyTotpEnrollment}
                onClose={props.onCloseTotpSetup}
              />
            )}
          </div>

          {cooldownActive && cooldownLabel !== null && (
            <div className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] p-4">
              <SectionLabel>Active cooldown</SectionLabel>
              <p className="mt-1 text-xs text-brand-dark">Cooldown active until {cooldownLabel}</p>
              <div className="mt-3">
                <ActionButton onClick={props.onRevokeCooldown} variant="outline">
                  Revoke cooldown
                </ActionButton>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
