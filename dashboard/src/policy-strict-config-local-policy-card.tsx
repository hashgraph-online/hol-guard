import type { ReactNode } from "react";
import {
  HiMiniArrowPath,
  HiMiniBolt,
  HiMiniCodeBracket,
  HiMiniCommandLine,
  HiMiniDocumentText,
  HiMiniGlobeAlt,
  HiMiniInformationCircle,
} from "react-icons/hi2";
import { SectionLabel } from "./approval-center-primitives";
import type { GuardSettings } from "./guard-types";
import {
  StrictConfigActionSegmented,
  type StrictConfigSettingKey,
} from "./policy-strict-config-segmented";
import { POLICY_PANEL_CARD_CLASS } from "./policy-strict-config-surfaces";
import { resolveStrictFileWriteAction } from "./policy-strict-config-utils";

function PolicyInfoBanner({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-xl border border-slate-200/80 bg-slate-50 px-3 py-2.5 text-xs leading-relaxed text-slate-600">
      <HiMiniInformationCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

type PolicyLocalStrictPolicyCardProps = {
  settings: GuardSettings;
  controlsDisabled: boolean;
  saveError: string | null;
  savingKey: string | null;
  onResetDefaults: () => void;
  onSettingChange: (key: StrictConfigSettingKey, value: string) => void;
};

export function PolicyLocalStrictPolicyCard({
  settings,
  controlsDisabled,
  saveError,
  savingKey,
  onResetDefaults,
  onSettingChange,
}: PolicyLocalStrictPolicyCardProps) {
  const fileWriteAction = resolveStrictFileWriteAction(settings);

  return (
    <div className={`${POLICY_PANEL_CARD_CLASS} p-4`}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <SectionLabel>Local strict policy</SectionLabel>
        <button
          type="button"
          onClick={onResetDefaults}
          disabled={controlsDisabled}
          className="inline-flex shrink-0 items-center gap-1.5 text-sm font-medium text-brand-blue hover:underline disabled:opacity-50"
        >
          <HiMiniArrowPath className="h-4 w-4" aria-hidden="true" />
          Reset to defaults
        </button>
      </div>
      <div className="mt-3 divide-y divide-slate-100">
        <StrictConfigActionSegmented
          label="Default action"
          help="For any action not explicitly allowed."
          icon={HiMiniBolt}
          value={settings.default_action}
          settingKey="default_action"
          onSettingChange={onSettingChange}
          disabled={controlsDisabled}
        />
        <StrictConfigActionSegmented
          label="Changed tool hash action"
          help="When a tool or script hash is new."
          icon={HiMiniCodeBracket}
          value={settings.changed_hash_action}
          settingKey="changed_hash_action"
          onSettingChange={onSettingChange}
          disabled={controlsDisabled}
        />
        <StrictConfigActionSegmented
          label="New network domain action"
          help="When a process tries to contact a new domain."
          icon={HiMiniGlobeAlt}
          value={settings.new_network_domain_action}
          settingKey="new_network_domain_action"
          onSettingChange={onSettingChange}
          disabled={controlsDisabled}
        />
        <StrictConfigActionSegmented
          label="Subprocess action"
          help="When a process tries to launch another program."
          icon={HiMiniCommandLine}
          value={settings.subprocess_action}
          settingKey="subprocess_action"
          onSettingChange={onSettingChange}
          disabled={controlsDisabled}
        />
        <StrictConfigActionSegmented
          label="File write action"
          help="When a process writes to disk."
          icon={HiMiniDocumentText}
          value={fileWriteAction}
          settingKey="destructive_shell"
          onSettingChange={onSettingChange}
          disabled={controlsDisabled}
        />
      </div>
      <div className="mt-4">
        <PolicyInfoBanner>These settings apply only when no local or Cloud rules cover the action.</PolicyInfoBanner>
      </div>
      {saveError ? <p className="mt-3 text-sm text-red-600">{saveError}</p> : null}
      {savingKey ? <p className="mt-3 text-sm text-slate-500">Saving {savingKey.replace(/_/g, " ")}…</p> : null}
    </div>
  );
}
