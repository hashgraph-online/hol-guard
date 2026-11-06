import type { ReactNode } from "react";
import {
  HiMiniBeaker,
  HiMiniCheck,
  HiMiniClipboardDocument,
  HiMiniCodeBracket,
  HiMiniDocumentText,
  HiMiniFolder,
  HiMiniInformationCircle,
  HiMiniLockClosed,
  HiMiniShieldCheck,
  HiMiniUsers,
} from "react-icons/hi2";
import { harnessDisplayName, scopeLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardCloudExceptionRequestCreateInput } from "./guard-api";
import type { GuardReceipt } from "./guard-types";
import type { WizardStep } from "./policy-cloud-exception-request-draft";
import { WIZARD_STEPS } from "./policy-cloud-exception-request-draft";
import { resolveRequestScopeBlastRadius } from "./policy-cloud-exceptions-utils";

export const REQUEST_STEPS = [...WIZARD_STEPS, "Submitted"] as const;

export type RequestStep = (typeof REQUEST_STEPS)[number];

export type RequestScopeValue = GuardCloudExceptionRequestCreateInput["scope"] | "team-policy";

type RequestStepperProps = {
  activeStep: WizardStep | "Submitted";
};

export function RequestStepper({ activeStep }: RequestStepperProps) {
  const visibleSteps = WIZARD_STEPS;
  const activeIndex =
    activeStep === "Submitted" ? visibleSteps.length : visibleSteps.indexOf(activeStep as WizardStep);

  return (
    <ol className="flex flex-wrap gap-2" aria-label="Request steps">
      {visibleSteps.map((step, index) => {
        const complete = activeStep === "Submitted" || index < activeIndex;
        const active = activeStep !== "Submitted" && index === activeIndex;
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
              {complete ? <HiMiniCheck className="h-3 w-3" aria-hidden="true" /> : index + 1}
            </span>
            {step}
          </li>
        );
      })}
    </ol>
  );
}

type RequestSummaryRailProps = {
  activeStep: WizardStep | "Submitted";
  sourceComplete: boolean;
  scopeComplete: boolean;
  guardrailsComplete: boolean;
};

const RAIL_STEPS: Array<{ key: WizardStep; label: string }> = [
  { key: "Source", label: "Source" },
  { key: "Scope", label: "Scope" },
  { key: "Guardrails", label: "Guardrails" },
  { key: "Review", label: "Review" },
];

function resolveRailStatus(
  step: WizardStep,
  activeStep: WizardStep | "Submitted",
  flags: { sourceComplete: boolean; scopeComplete: boolean; guardrailsComplete: boolean },
): string {
  if (activeStep === "Submitted") {
    return "Complete";
  }
  const activeIndex = WIZARD_STEPS.indexOf(activeStep as WizardStep);
  const stepIndex = WIZARD_STEPS.indexOf(step);
  if (stepIndex < activeIndex) {
    return "Complete";
  }
  if (stepIndex > activeIndex) {
    if (step === "Scope" && !flags.sourceComplete) {
      return "Not chosen";
    }
    if (step === "Guardrails" && !flags.scopeComplete) {
      return "Not set";
    }
    if (step === "Review") {
      return "Pending";
    }
    return step === "Scope" ? "Not chosen" : "Not set";
  }
  if (step === "Source") {
    return flags.sourceComplete ? "Selected" : "Not chosen";
  }
  if (step === "Scope") {
    return flags.scopeComplete ? "Selected" : "Not chosen";
  }
  if (step === "Guardrails") {
    return flags.guardrailsComplete ? "Set" : "Not set";
  }
  return "Pending";
}

export function RequestSummaryRail({
  activeStep,
  sourceComplete,
  scopeComplete,
  guardrailsComplete,
}: RequestSummaryRailProps) {
  const flags = { sourceComplete, scopeComplete, guardrailsComplete };

  return (
    <aside className="rounded-xl border border-slate-200 bg-slate-50/60 p-4" aria-label="Request progress">
      <ol className="space-y-3">
        {RAIL_STEPS.map((step, index) => {
          const status = resolveRailStatus(step.key, activeStep, flags);
          const active = activeStep === step.key;
          const complete =
            activeStep === "Submitted" ||
            WIZARD_STEPS.indexOf(activeStep as WizardStep) > index ||
            (step.key === "Source" && sourceComplete && activeStep !== "Source");
          return (
            <li
              key={step.key}
              className={`flex items-start justify-between gap-2 rounded-lg px-2 py-1.5 text-sm ${
                active ? "bg-brand-blue/8" : ""
              }`}
            >
              <div className="flex items-center gap-2">
                <span
                  className={`inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${
                    complete
                      ? "bg-emerald-600 text-white"
                      : active
                        ? "bg-brand-blue text-white"
                        : "bg-slate-200 text-slate-600"
                  }`}
                >
                  {complete ? <HiMiniCheck className="h-3 w-3" aria-hidden="true" /> : index + 1}
                </span>
                <span className="font-medium text-brand-dark">{step.label}</span>
              </div>
              <span className="text-xs text-slate-500">{status}</span>
            </li>
          );
        })}
      </ol>
      {activeStep !== "Submitted" ? (
        <div className="mt-4 border-t border-slate-200 pt-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">What&apos;s next?</p>
          <p className="mt-2 text-xs leading-relaxed text-slate-600">
            {activeStep === "Source"
              ? "Choose scope, add guardrails, then submit to Guard Cloud."
              : activeStep === "Scope"
                ? "Set guardrails like reason and expiry, then send the request to Guard Cloud."
                : activeStep === "Guardrails"
                  ? "Review the exact request before submitting to Guard Cloud."
                  : "Submit when the summary looks correct."}
          </p>
        </div>
      ) : null}
    </aside>
  );
}

const SCOPE_CARD_TONES: Record<
  ReturnType<typeof resolveRequestScopeBlastRadius>["tone"],
  string
> = {
  narrow: "border-emerald-200 bg-emerald-50/70 hover:border-emerald-300",
  medium: "border-amber-200 bg-amber-50/60 hover:border-amber-300",
  wide: "border-rose-200 bg-rose-50/50 hover:border-rose-300",
};

const SCOPE_ICONS: Record<RequestScopeValue, typeof HiMiniCodeBracket> = {
  artifact: HiMiniCodeBracket,
  publisher: HiMiniFolder,
  workspace: HiMiniFolder,
  harness: HiMiniBeaker,
  "team-policy": HiMiniUsers,
};

type ScopeCardOption = {
  value: RequestScopeValue;
  label: string;
  description: string;
  disabled?: boolean;
  disabledReason?: string;
};

type ScopeCardGridProps = {
  options: ScopeCardOption[];
  value: RequestScopeValue;
  onChange: (value: RequestScopeValue) => void;
};

export function ScopeCardGrid({ options, value, onChange }: ScopeCardGridProps) {
  return (
    <div className="space-y-2" role="radiogroup" aria-label="Exception scope">
      {options.map((option) => {
        const blast = resolveRequestScopeBlastRadius(option.value);
        const selected = value === option.value;
        const Icon = SCOPE_ICONS[option.value];
        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={selected}
            disabled={option.disabled}
            onClick={() => onChange(option.value)}
            className={`w-full rounded-xl border p-4 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${
              selected
                ? `${SCOPE_CARD_TONES[blast.tone]} ring-2 ring-brand-blue/30`
                : `${SCOPE_CARD_TONES[blast.tone]} opacity-95`
            }`}
          >
            <div className="flex items-start gap-3">
              <span
                className={`mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${
                  selected ? "border-brand-blue bg-brand-blue" : "border-slate-300 bg-white"
                }`}
                aria-hidden="true"
              >
                {selected ? <span className="h-1.5 w-1.5 rounded-full bg-white" /> : null}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <Icon className="h-4 w-4 text-slate-500" aria-hidden="true" />
                  <p className="text-sm font-semibold text-brand-dark">{option.label}</p>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-600">{option.description}</p>
                <p className="mt-2 text-[11px] font-medium uppercase tracking-wide text-slate-500">
                  Blast radius · {blast.label}
                </p>
                {option.disabled && option.disabledReason ? (
                  <p className="mt-2 flex items-center gap-1 text-[11px] text-slate-500">
                    <HiMiniLockClosed className="h-3 w-3" aria-hidden="true" />
                    {option.disabledReason}
                  </p>
                ) : null}
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}

type SafetyPreviewProps = {
  scope: RequestScopeValue;
  harness: string;
  artifactId: string;
  publisher: string;
  workingDirectory: string;
  reason: string;
  expiresLabel: string;
  compact?: boolean;
};

const SAFETY_ITEMS = [
  {
    icon: HiMiniShieldCheck,
    title: "Cloud approval required",
    detail: "Your request will be reviewed and approved in Guard Cloud.",
  },
  {
    icon: HiMiniLockClosed,
    title: "MFA may be required",
    detail: "Broad scopes may require step-up authentication.",
  },
  {
    icon: HiMiniDocumentText,
    title: "Signed bundle enforcement",
    detail: "This exception is enforced only after it appears in a signed policy bundle.",
  },
  {
    icon: HiMiniCheck,
    title: "Local daemon ack required",
    detail: "Your machine will acknowledge the updated bundle before enforcement.",
  },
] as const;

function resolveSafetyScopeTarget(
  scope: RequestScopeValue,
  artifactId: string,
  publisher: string,
  harness: string,
  workingDirectory: string,
): string {
  if (scope === "artifact") {
    return artifactId || "Selected artifact";
  }
  if (scope === "publisher") {
    return publisher || "Publisher";
  }
  if (scope === "harness") {
    return harness;
  }
  if (scope === "workspace") {
    return workingDirectory || "Project folder";
  }
  return "Team policy";
}

function resolveResultActionLabel(scope: RequestScopeValue): string {
  if (scope === "artifact") {
    return "this exact action";
  }
  if (scope === "workspace") {
    return "matching actions in this project";
  }
  const scopeForLabel = scope === "team-policy" ? "global" : scope;
  return scopeLabel(scopeForLabel, "policy");
}

export function SafetyPreview({
  scope,
  harness,
  artifactId,
  publisher,
  workingDirectory,
  reason,
  expiresLabel,
  compact = false,
}: SafetyPreviewProps) {
  const blast = resolveRequestScopeBlastRadius(scope);
  const scopeTarget = resolveSafetyScopeTarget(scope, artifactId, publisher, harness, workingDirectory);
  const actionLabel = resolveResultActionLabel(scope);
  const showHarness = (scope === "artifact" || scope === "harness") && harness.trim();

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Safety &amp; enforcement</p>
      {!compact ? (
        <div className="mt-3">
          <p className="text-xs text-slate-500">Blast radius</p>
          <p className="mt-1 text-sm font-semibold text-brand-dark">{blast.label}</p>
          <p className="text-xs text-slate-600">{scopeTarget}</p>
        </div>
      ) : null}
      <ul className={`space-y-3 ${compact ? "mt-3" : "mt-4"}`}>
        {SAFETY_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <li key={item.title} className="flex gap-2.5">
              <Icon className="mt-0.5 h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
              <div>
                <p className="text-sm font-medium text-brand-dark">{item.title}</p>
                <p className="text-xs leading-relaxed text-slate-600">{item.detail}</p>
              </div>
            </li>
          );
        })}
      </ul>
      <div className="mt-4 rounded-lg border border-slate-200 bg-white p-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Preview</p>
        <p className="mt-2 text-xs leading-relaxed text-brand-dark">
          If approved, Guard will allow {actionLabel}
          {showHarness ? ` for ${harnessDisplayName(harness)}` : ""} until {expiresLabel}.
        </p>
      </div>
      {!compact && reason.trim() ? (
        <p className="mt-4 text-xs leading-relaxed text-slate-500">
          Reason: {reason.trim().slice(0, 120)}
          {reason.trim().length > 120 ? "…" : ""}
        </p>
      ) : null}
    </div>
  );
}

type SourceReceiptSummaryProps = {
  receipt: GuardReceipt;
  compact?: boolean;
};

export function SourceReceiptSummary({ receipt, compact = false }: SourceReceiptSummaryProps) {
  const evidenceHref = `/evidence?search=${encodeURIComponent(receipt.receipt_id)}`;
  const artifactLabel = receipt.artifact_name ?? receipt.artifact_id;

  const handleCopyArtifact = () => {
    if (!receipt.artifact_id || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(receipt.artifact_id);
  };

  return (
    <div className={`rounded-xl border border-slate-200 bg-slate-50/80 ${compact ? "p-3" : "p-4"}`}>
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        {compact ? "Source" : "Selected source preview"}
      </p>
      <div className="mt-3 flex items-start gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-200/80 text-slate-600">
          <HiMiniCodeBracket className="h-4 w-4" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-brand-dark">{artifactLabel}</p>
          <p className="mt-1 text-xs text-slate-600">
            {harnessDisplayName(receipt.harness)}
            {receipt.timestamp ? ` · ${receipt.timestamp}` : ""}
          </p>
        </div>
      </div>
      {!compact ? (
        <div className="mt-4 space-y-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Artifact ID</p>
            <div className="mt-1 flex items-center gap-1.5">
              <p className="truncate font-mono text-xs text-brand-dark">{receipt.artifact_id}</p>
              <button
                type="button"
                onClick={handleCopyArtifact}
                className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark"
                aria-label="Copy artifact ID"
              >
                <HiMiniClipboardDocument className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          </div>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Evidence receipt</p>
            <a
              href={guardAwareHref(evidenceHref)}
              className="mt-1 inline-flex items-center gap-1 break-all text-xs font-medium text-brand-blue hover:underline"
            >
              <HiMiniDocumentText className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              {receipt.receipt_id}
            </a>
          </div>
        </div>
      ) : null}
    </div>
  );
}

type ResultPreviewProps = {
  scope: RequestScopeValue;
  harness: string;
  expiresLabel: string;
  actionLabel?: string;
  scopeLabelText?: string;
};

export function ResultPreview({
  scope,
  harness,
  expiresLabel,
  actionLabel,
  scopeLabelText,
}: ResultPreviewProps) {
  const showHarness = (scope === "artifact" || scope === "harness") && harness.trim();
  const resolvedAction = actionLabel ?? resolveResultActionLabel(scope);
  const resolvedScope = scopeLabelText ?? scopeLabel(scope === "team-policy" ? "global" : scope, "policy");

  return (
    <div className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] p-4">
      <div className="flex gap-2">
        <HiMiniInformationCircle className="mt-0.5 h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
        <p className="text-sm leading-relaxed text-brand-dark">
          If approved in Guard Cloud, Guard will allow <strong>{resolvedAction}</strong>
          {showHarness ? (
            <>
              {" "}
              for <strong>{harnessDisplayName(harness)}</strong>
            </>
          ) : null}{" "}
          in <strong>{resolvedScope}</strong> until <strong>{expiresLabel}</strong>.
        </p>
      </div>
    </div>
  );
}

type RequestModalShellProps = {
  title: string;
  subtitle?: string;
  stepper?: ReactNode;
  children: ReactNode;
  footer: ReactNode;
  summaryRail?: ReactNode;
  onCancel: () => void;
  onCloseRef?: (close: () => void) => void;
  preventClose?: boolean;
};

export function RequestModalShell({
  title,
  subtitle,
  stepper,
  children,
  footer,
  summaryRail,
  onCancel,
  preventClose = false,
}: RequestModalShellProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-900/45 p-3 sm:items-center sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cloud-exception-request-title"
    >
      <div className="my-auto w-full max-w-5xl rounded-2xl border border-slate-200 bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-100 px-4 py-4 sm:px-5">
          <div className="min-w-0 space-y-2">
            <h2 id="cloud-exception-request-title" className="text-lg font-semibold text-brand-dark">
              {title}
            </h2>
            {subtitle ? <p className="text-sm text-slate-600">{subtitle}</p> : null}
            {stepper}
          </div>
          <button
            type="button"
            onClick={onCancel}
            disabled={preventClose}
            className="rounded-lg px-2 py-1 text-sm font-medium text-slate-500 hover:bg-slate-100 hover:text-brand-dark disabled:cursor-not-allowed disabled:opacity-50"
            aria-label="Close"
          >
            Close
          </button>
        </div>
        <div className="px-4 py-4 sm:px-5 sm:py-5">
          <div className={summaryRail ? "grid gap-4 lg:grid-cols-[minmax(0,1fr)_240px] lg:items-start" : ""}>
            <div className="min-w-0">{children}</div>
            {summaryRail ? <div className="min-w-0 lg:sticky lg:top-0">{summaryRail}</div> : null}
          </div>
        </div>
        <div className="border-t border-slate-100 px-4 py-4 sm:px-5">{footer}</div>
      </div>
    </div>
  );
}
