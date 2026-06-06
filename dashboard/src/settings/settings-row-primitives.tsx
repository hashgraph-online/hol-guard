import { useCallback, useId, type ChangeEvent, type ReactNode } from "react";

export interface SettingsFormSectionProps {
  title: string;
  description?: string;
  children: ReactNode;
}

export function SettingsFormSection({ title, description, children }: SettingsFormSectionProps) {
  return (
    <section className="guard-settings-section space-y-4">
      <div>
        <h3 className="guard-settings-section-title">{title}</h3>
        {description ? (
          <p className="guard-settings-body mt-1 text-slate-500">{description}</p>
        ) : null}
      </div>
      <div className="divide-y divide-slate-100 rounded-xl border border-slate-100 bg-white px-4">
        {children}
      </div>
    </section>
  );
}

export interface SettingsToggleRowProps {
  label: string;
  description?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}

export function SettingsToggleRow({
  label,
  description,
  checked,
  onChange,
  disabled = false,
}: SettingsToggleRowProps) {
  const labelId = useId();
  const descriptionId = useId();

  const handleToggle = useCallback(() => {
    if (!disabled) {
      onChange(!checked);
    }
  }, [checked, disabled, onChange]);

  return (
    <div className="flex items-center justify-between gap-4 py-3">
      <div className="min-w-0 flex-1">
        <p id={labelId} className="guard-settings-body font-medium text-brand-dark">
          {label}
        </p>
        {description ? (
          <p id={descriptionId} className="guard-settings-caption mt-0.5 text-slate-500">
            {description}
          </p>
        ) : null}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-labelledby={labelId}
        aria-describedby={description ? descriptionId : undefined}
        disabled={disabled}
        onClick={handleToggle}
        className={`relative h-7 w-12 shrink-0 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/60 ${
          checked ? "bg-brand-blue" : "bg-slate-200"
        } ${disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`}
      >
        <span
          className={`absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white shadow-sm transition-transform ${
            checked ? "translate-x-5" : "translate-x-0"
          }`}
        />
      </button>
    </div>
  );
}

export interface SettingsSelectRowProps {
  label: string;
  description?: string;
  value: string;
  options: Array<{ value: string; label: string }>;
  onChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  disabled?: boolean;
}

export function SettingsSelectRow({
  label,
  description,
  value,
  options,
  onChange,
  disabled = false,
}: SettingsSelectRowProps) {
  const selectId = useId();

  return (
    <div className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center">
      <div>
        <label htmlFor={selectId} className="guard-settings-body font-medium text-brand-dark">
          {label}
        </label>
        {description ? (
          <p className="guard-settings-caption mt-0.5 text-slate-500">{description}</p>
        ) : null}
      </div>
      <select
        id={selectId}
        value={value}
        onChange={onChange}
        disabled={disabled}
        className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}
