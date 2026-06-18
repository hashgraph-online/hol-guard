import { useCallback, type ComponentType } from "react";
import type { GuardSettings } from "./guard-types";
import { STRICT_CONFIG_ACTION_OPTIONS } from "./policy-strict-config-utils";

const PRIMARY_STRICT_ACTIONS = [
  { value: "allow", label: "Allow" },
  { value: "warn", label: "Warn" },
  { value: "review", label: "Review" },
  { value: "block", label: "Block" },
] as const;

const PRIMARY_STRICT_ACTION_VALUES = new Set<string>(PRIMARY_STRICT_ACTIONS.map((item) => item.value));

type StrictConfigActionSegmentedProps = {
  label: string;
  value: string;
  settingKey: "default_action" | "changed_hash_action" | "new_network_domain_action" | "subprocess_action" | "destructive_shell";
  onSettingChange: (key: StrictConfigActionSegmentedProps["settingKey"], value: string) => void;
  disabled?: boolean;
  help?: string;
  icon?: ComponentType<{ className?: string }>;
};

export function StrictConfigActionSegmented({
  label,
  value,
  settingKey,
  onSettingChange,
  disabled = false,
  help,
  icon: Icon,
}: StrictConfigActionSegmentedProps) {
  const handleSelect = useCallback(
    (nextValue: string) => {
      onSettingChange(settingKey, nextValue);
    },
    [onSettingChange, settingKey],
  );

  const showAdvanced = !PRIMARY_STRICT_ACTION_VALUES.has(value);

  return (
    <div className="grid gap-3 py-4 first:pt-0 last:pb-0 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center lg:gap-4">
      <div className="flex min-w-0 items-start gap-3">
        {Icon ? (
          <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-500">
            <Icon className="h-4 w-4" aria-hidden="true" />
          </span>
        ) : null}
        <div className="min-w-0">
          <p className="text-sm font-medium text-brand-dark">{label}</p>
          {help ? <p className="mt-0.5 text-xs leading-relaxed text-slate-500">{help}</p> : null}
        </div>
      </div>
      <div className="w-full max-w-[17.5rem] lg:justify-self-end">
        <div
          className="flex w-full flex-wrap gap-0.5 rounded-xl border border-slate-200 bg-slate-100/80 p-0.5"
          role="group"
          aria-label={label}
        >
          {PRIMARY_STRICT_ACTIONS.map((option) => {
            const selected = value === option.value;
            return (
              <button
                key={option.value}
                type="button"
                disabled={disabled}
                aria-pressed={selected}
                onClick={() => handleSelect(option.value)}
                className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
                  selected
                    ? "bg-brand-blue text-white shadow-sm"
                    : "text-slate-600 hover:bg-white/70 hover:text-brand-dark disabled:opacity-50"
                }`}
              >
                {option.label}
              </button>
            );
          })}
        </div>
        {showAdvanced ? (
          <label className="mt-2 block space-y-1">
            <span className="text-xs font-medium text-slate-500">Advanced fallback</span>
            <select
              value={value}
              disabled={disabled}
              onChange={(event) => handleSelect(event.target.value)}
              className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark disabled:cursor-not-allowed disabled:bg-slate-50"
            >
              {STRICT_CONFIG_ACTION_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
        ) : null}
      </div>
    </div>
  );
}

export type StrictConfigSettingKey = StrictConfigActionSegmentedProps["settingKey"];

export function resolveStrictConfigPatch(
  settings: GuardSettings,
  key: StrictConfigSettingKey,
  value: string,
): Partial<GuardSettings> {
  if (key === "destructive_shell") {
    return {
      risk_actions: {
        ...settings.risk_actions,
        destructive_shell: value,
      },
    };
  }
  return { [key]: value };
}

export function applyStrictConfigPatch(
  settings: GuardSettings,
  key: StrictConfigSettingKey,
  value: string,
): GuardSettings {
  if (key === "destructive_shell") {
    return {
      ...settings,
      risk_actions: {
        ...settings.risk_actions,
        destructive_shell: value,
      },
    };
  }
  return {
    ...settings,
    [key]: value,
  };
}
