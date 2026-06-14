import { useCallback } from "react";
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
};

export function StrictConfigActionSegmented({
  label,
  value,
  settingKey,
  onSettingChange,
  disabled = false,
  help,
}: StrictConfigActionSegmentedProps) {
  const handleSelect = useCallback(
    (nextValue: string) => {
      onSettingChange(settingKey, nextValue);
    },
    [onSettingChange, settingKey],
  );

  const showAdvanced = !PRIMARY_STRICT_ACTION_VALUES.has(value);

  return (
    <div className="space-y-2">
      <div>
        <p className="text-sm font-medium text-brand-dark">{label}</p>
        {help ? <p className="mt-0.5 text-xs text-slate-500">{help}</p> : null}
      </div>
      <div
        className="inline-flex flex-wrap gap-1 rounded-xl border border-slate-200 bg-slate-50/80 p-1"
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
              className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                selected
                  ? "bg-white text-brand-dark shadow-sm ring-1 ring-slate-200"
                  : "text-slate-600 hover:bg-white/70 hover:text-brand-dark disabled:opacity-50"
              }`}
            >
              {option.label}
            </button>
          );
        })}
      </div>
      {showAdvanced ? (
        <label className="block space-y-1">
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
