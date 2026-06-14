import type { ReactNode } from "react";
import { scopeLabel } from "./approval-center-utils";
import type { GuardCloudExceptionRequestCreateInput } from "./guard-api";
import { resolveCloudExceptionBlastRadius } from "./policy-cloud-exceptions-utils";

export const REQUEST_STEPS = ["Source", "Scope", "Guardrails", "Submit"] as const;

export type RequestStep = (typeof REQUEST_STEPS)[number];

type RequestStepperProps = {
  activeStep: RequestStep;
};

export function RequestStepper({ activeStep }: RequestStepperProps) {
  const activeIndex = REQUEST_STEPS.indexOf(activeStep);

  return (
    <ol className="flex flex-wrap gap-2" aria-label="Request steps">
      {REQUEST_STEPS.map((step, index) => {
        const complete = index < activeIndex;
        const active = index === activeIndex;
        return (
          <li
            key={step}
            className={`flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${
              active
                ? "border-brand-blue bg-brand-blue/10 text-brand-blue"
                : complete
                  ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                  : "border-slate-200 bg-slate-50 text-slate-500"
            }`}
            aria-current={active ? "step" : undefined}
          >
            <span
              className={`inline-flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-semibold ${
                active
                  ? "bg-brand-blue text-white"
                  : complete
                    ? "bg-emerald-600 text-white"
                    : "bg-slate-200 text-slate-600"
              }`}
            >
              {index + 1}
            </span>
            {step}
          </li>
        );
      })}
    </ol>
  );
}

const SCOPE_CARD_TONES: Record<
  ReturnType<typeof resolveCloudExceptionBlastRadius>["tone"],
  string
> = {
  narrow: "border-emerald-200 bg-emerald-50/70 hover:border-emerald-300",
  medium: "border-amber-200 bg-amber-50/60 hover:border-amber-300",
  wide: "border-rose-200 bg-rose-50/50 hover:border-rose-300",
};

type ScopeCardOption = {
  value: GuardCloudExceptionRequestCreateInput["scope"];
  label: string;
  description: string;
};

type ScopeCardGridProps = {
  options: ScopeCardOption[];
  value: GuardCloudExceptionRequestCreateInput["scope"];
  onChange: (value: GuardCloudExceptionRequestCreateInput["scope"]) => void;
};

export function ScopeCardGrid({ options, value, onChange }: ScopeCardGridProps) {
  return (
    <div className="grid gap-2 sm:grid-cols-2" role="radiogroup" aria-label="Exception scope">
      {options.map((option) => {
        const blast = resolveCloudExceptionBlastRadius(option.value);
        const selected = value === option.value;
        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={selected}
            onClick={() => onChange(option.value)}
            className={`rounded-xl border p-3 text-left transition ${
              selected
                ? `${SCOPE_CARD_TONES[blast.tone]} ring-2 ring-brand-blue/30`
                : `${SCOPE_CARD_TONES[blast.tone]} opacity-90`
            }`}
          >
            <p className="text-sm font-semibold text-brand-dark">{option.label}</p>
            <p className="mt-1 text-xs text-slate-600">{option.description}</p>
            <p className="mt-2 text-[11px] font-medium uppercase tracking-wide text-slate-500">
              Blast radius · {blast.label}
            </p>
          </button>
        );
      })}
    </div>
  );
}

type SafetyPreviewProps = {
  scope: GuardCloudExceptionRequestCreateInput["scope"];
  harness: string;
  artifactId: string;
  publisher: string;
  workingDirectory: string;
  reason: string;
  expiresLabel: string;
};

export function SafetyPreview({
  scope,
  harness,
  artifactId,
  publisher,
  workingDirectory,
  reason,
  expiresLabel,
}: SafetyPreviewProps) {
  const blast = resolveCloudExceptionBlastRadius(scope);
  const scopeTarget =
    scope === "artifact"
      ? artifactId || "Selected artifact"
      : scope === "publisher"
        ? publisher || "Publisher"
        : scope === "harness"
          ? harness
          : scope === "workspace"
            ? workingDirectory || "Project folder"
            : "Global";

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Safety preview</p>
      <dl className="mt-3 space-y-3 text-sm">
        <div>
          <dt className="text-xs text-slate-500">Scope</dt>
          <dd className="font-medium text-brand-dark">{scopeLabel(scope, "policy")}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500">Target</dt>
          <dd className="break-all font-medium text-brand-dark">{scopeTarget}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500">Blast radius</dt>
          <dd className="text-brand-dark">{blast.label}</dd>
          <dd className="text-xs text-slate-600">{blast.detail}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500">Expires</dt>
          <dd className="text-brand-dark">{expiresLabel}</dd>
        </div>
        {reason.trim() ? (
          <div>
            <dt className="text-xs text-slate-500">Reason</dt>
            <dd className="text-brand-dark">{reason.trim()}</dd>
          </div>
        ) : null}
      </dl>
      <p className="mt-4 text-xs leading-relaxed text-slate-500">
        Guard Cloud must approve this request before it syncs as a signed bundle entry on this device.
      </p>
    </div>
  );
}

type RequestModalShellProps = {
  title: string;
  stepper: ReactNode;
  children: ReactNode;
  footer: ReactNode;
  onCancel: () => void;
};

export function RequestModalShell({ title, stepper, children, footer, onCancel }: RequestModalShellProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-900/45 p-4 sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cloud-exception-request-title"
    >
      <div className="w-full max-w-6xl rounded-2xl border border-slate-200 bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-100 px-5 py-4">
          <div className="min-w-0 space-y-3">
            <h2 id="cloud-exception-request-title" className="text-lg font-semibold text-brand-dark">
              {title}
            </h2>
            {stepper}
          </div>
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg px-2 py-1 text-sm font-medium text-slate-500 hover:bg-slate-100 hover:text-brand-dark"
          >
            Close
          </button>
        </div>
        <div className="px-5 py-5">{children}</div>
        <div className="border-t border-slate-100 px-5 py-4">{footer}</div>
      </div>
    </div>
  );
}
