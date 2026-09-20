import { type ChangeEvent } from "react";
import { HiMiniBellAlert } from "react-icons/hi2";
import { ActionButton, Tag } from "./approval-center-primitives";
import { PROTECTION_POSTURE_COPY, type ProtectionPosture } from "./protection-posture-copy";
import type { GuardNotificationSetupResult, GuardRuntimeSnapshot, GuardSettings } from "./guard-types";
import { isFineTuningEditable, actionOptions } from "./settings-workspace-model";

export function SettingsActionMessage(props: { message: string | null; kind: "success" | "error" }) {
  if (props.message === null) {
    return null;
  }
  return (
    <div
      className={`rounded-xl border px-4 py-3 text-sm font-medium ${
        props.kind === "error"
          ? "border-brand-attention/20 bg-brand-attention/[0.04] text-brand-dark"
          : "border-brand-blue/15 bg-brand-blue/[0.04] text-brand-dark"
      }`}
      role={props.kind === "error" ? "alert" : "status"}
    >
      {props.message}
    </div>
  );
}

export function DiagnosticsPerfCard(props: { snapshot: GuardRuntimeSnapshot }) {
  const threadCount = props.snapshot.thread_count;
  const daemonPort = props.snapshot.runtime_state?.daemon_port ?? null;
  const startedAt = props.snapshot.runtime_state?.started_at ?? null;
  return (
    <div className="rounded-lg bg-slate-50/80 px-3 py-2">
      <p className="text-xs font-semibold text-brand-dark">Background service</p>
      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
        {threadCount !== undefined && <span>{threadCount} worker threads</span>}
        {daemonPort !== null && <span>Local port {daemonPort}</span>}
        {startedAt !== null && <span>Running since {new Date(startedAt).toLocaleTimeString()}</span>}
      </div>
    </div>
  );
}

export function NotificationSetupCard(props: {
  result: GuardNotificationSetupResult | null;
  settingUp: boolean;
  onSetup: () => void;
}) {
  return (
    <div className="rounded-xl border border-brand-blue/15 bg-gradient-to-br from-white to-brand-blue/[0.03] p-5">
      <div className="flex gap-4">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
          <HiMiniBellAlert className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1 space-y-4">
          <div>
            <p className="text-sm font-semibold text-brand-dark">Desktop alerts</p>
            <p className="mt-1 max-w-2xl text-sm leading-relaxed text-slate-500">
              When Guard pauses something, a banner helps you respond without hunting for this tab.
            </p>
          </div>
          <ol className="grid gap-2 text-xs text-slate-600 sm:grid-cols-3">
            <li className="rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100">1. Open notification settings.</li>
            <li className="rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100">2. Allow alerts for Guard.</li>
            <li className="rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100">3. Turn on banners and sound.</li>
          </ol>
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4">
            <div className="flex flex-wrap gap-2">
              {props.result ? (
                <>
                  <Tag tone={props.result.supported ? "blue" : "slate"}>
                    {props.result.supported ? "Supported on this Mac" : "Not supported here"}
                  </Tag>
                  <Tag tone={props.result.preview_sent ? "blue" : "slate"}>
                    {props.result.preview_sent ? "Test alert sent" : "No test alert yet"}
                  </Tag>
                  <Tag tone={props.result.settings_opened ? "blue" : "slate"}>
                    {props.result.settings_opened ? "Settings opened" : "Settings not opened"}
                  </Tag>
                </>
              ) : (
                <Tag tone="slate">Not set up yet</Tag>
              )}
            </div>
            <button
              type="button"
              onClick={props.onSetup}
              disabled={props.settingUp}
              className="inline-flex min-h-9 shrink-0 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-semibold text-brand-dark transition-colors hover:border-brand-blue/30 hover:bg-slate-50 disabled:pointer-events-none disabled:opacity-50"
            >
              {props.settingUp ? "Opening…" : "Set up alerts"}
            </button>
          </div>
          {props.result?.guidance ? (
            <p className="text-xs leading-relaxed text-slate-500">{props.result.guidance}</p>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function SettingSelect(props: {
  label: string;
  value: string;
  options: Array<{ value: string; label: string }>;
  onChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  disabled?: boolean;
}) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-slate-500">{props.label}</span>
      <select
        value={props.value}
        onChange={props.onChange}
        disabled={props.disabled}
        className="mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {props.options.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}

export function SettingNumber(props: {
  label: string;
  value: number;
  min: number;
  max: number;
  suffix: string;
  onChange: (event: ChangeEvent<HTMLInputElement>) => void;
}) {
  const inputId = `setting-${props.label.toLowerCase().replaceAll(" ", "-")}`;
  return (
    <label htmlFor={inputId} className="space-y-2">
      <span className="block text-sm font-medium text-brand-dark">{props.label}</span>
      <span className="flex min-h-11 items-center rounded-lg border border-slate-200 bg-white focus-within:border-brand-blue focus-within:ring-1 focus-within:ring-brand-blue/20">
        <input
          id={inputId}
          type="number"
          min={props.min}
          max={props.max}
          value={props.value}
          onChange={props.onChange}
          className="min-w-0 flex-1 bg-transparent px-3 py-2 text-sm text-brand-dark focus:outline-none"
        />
        <span className="border-l border-slate-100 px-3 text-xs text-slate-500">{props.suffix}</span>
      </span>
    </label>
  );
}

export function SettingToggle(props: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (event: ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <label htmlFor={props.id} className="flex min-h-10 cursor-pointer items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 transition-colors hover:bg-slate-100/60">
      <span className="text-sm text-brand-dark">{props.label}</span>
      <input id={props.id} name={props.id} type="checkbox" checked={props.checked} onChange={props.onChange} className="h-4 w-4 accent-brand-blue" />
    </label>
  );
}

export function FineTuningPresetBanner(props: {
  securityLevel: GuardSettings["security_level"];
  posture: ProtectionPosture;
  onSwitchToCustom: () => void;
}) {
  if (isFineTuningEditable(props.securityLevel)) return null;
  const postureLabel = PROTECTION_POSTURE_COPY[props.posture].label;

  return (
    <div
      className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-4 sm:flex sm:items-center sm:justify-between sm:gap-4"
      role="region"
      aria-label="Advanced rules"
    >
      <div className="min-w-0">
        <p className="text-sm font-medium text-brand-dark">
          These rules follow {postureLabel}
        </p>
        <p className="mt-1 text-sm text-slate-500">
          Switch to Custom to change how Guard handles each action type on this machine.
        </p>
      </div>
      <div className="mt-3 w-full shrink-0 sm:mt-0 sm:w-auto">
        <ActionButton onClick={props.onSwitchToCustom}>Use Custom fine-tuning</ActionButton>
      </div>
    </div>
  );
}

export type RiskControlRowProps = {
  risk: { key: string; label: string; description: string; consequence?: { example: string; impact: string } | undefined };
  value: string;
  disabled: boolean;
  onChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  showConsequence?: boolean;
};

export function RiskControlRow({ risk, value, disabled, onChange, showConsequence }: RiskControlRowProps) {
  return (
    <div className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-start">
      <div>
        <p className="text-sm font-medium text-brand-dark">{risk.label}</p>
        <p className="text-xs text-slate-500">{risk.description}</p>
        {showConsequence && risk.consequence && (
          <p className="mt-1 text-xs text-slate-400">
            <span className="font-medium">Example:</span> {risk.consequence.example}
          </p>
        )}
        {showConsequence && risk.consequence && (
          <p className="mt-0.5 text-xs text-slate-400">{risk.consequence.impact}</p>
        )}
      </div>
      <SettingSelect label="Guard should" value={value} options={actionOptions} onChange={onChange} disabled={disabled} />
    </div>
  );
}
