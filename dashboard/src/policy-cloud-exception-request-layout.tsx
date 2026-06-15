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
import { resolveRequestScopeBlastRadius } from "./policy-cloud-exceptions-utils";

export const REQUEST_STEPS = ["Source", "Scope", "Guardrails", "Submit"] as const;

export type RequestStep = (typeof REQUEST_STEPS)[number];

export type RequestScopeValue = GuardCloudExceptionRequestCreateInput["scope"] | "team-policy";

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
              {complete ? <HiMiniCheck className="h-3 w-3" aria-hidden="true" /> : index + 1}
            </span>
            {step}
          </li>
        );
      })}
    </ol>
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
};

type ScopeCardGridProps = {
  options: ScopeCardOption[];
  value: RequestScopeValue;
  onChange: (value: RequestScopeValue) => void;
};

export function ScopeCardGrid({ options, value, onChange }: ScopeCardGridProps) {
  return (
    <div className="-mx-1 flex gap-2 overflow-x-auto px-1 pb-1" role="radiogroup" aria-label="Exception scope">
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
            className={`min-w-[148px] shrink-0 rounded-xl border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${
              selected
                ? `${SCOPE_CARD_TONES[blast.tone]} ring-2 ring-brand-blue/30`
                : `${SCOPE_CARD_TONES[blast.tone]} opacity-95`
            }`}
          >
            <div className="flex items-center gap-2">
              <Icon className="h-4 w-4 text-slate-500" aria-hidden="true" />
              <p className="text-sm font-semibold text-brand-dark">{option.label}</p>
            </div>
            <p className="mt-1 text-xs leading-relaxed text-slate-600">{option.description}</p>
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
  scope: RequestScopeValue;
  harness: string;
  artifactId: string;
  publisher: string;
  workingDirectory: string;
  reason: string;
  expiresLabel: string;
};

const SAFETY_ITEMS = [
  {
    icon: HiMiniInformationCircle,
    title: "Requires Cloud approval",
    detail: "Your request will be reviewed and approved in Guard Cloud.",
  },
  {
    icon: HiMiniLockClosed,
    title: "Requires MFA for this scope",
    detail: "Broad scopes require step-up authentication.",
  },
  {
    icon: HiMiniShieldCheck,
    title: "Signed bundle enforcement",
    detail: "Local daemon will enforce only after receiving signed bundle ack.",
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
}: SafetyPreviewProps) {
  const blast = resolveRequestScopeBlastRadius(scope);
  const scopeTarget = resolveSafetyScopeTarget(scope, artifactId, publisher, harness, workingDirectory);

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Safety preview</p>
      <div className="mt-3">
        <p className="text-xs text-slate-500">Blast radius</p>
        <p className="mt-1 text-sm font-semibold text-brand-dark">{blast.label}</p>
        <p className="text-xs text-slate-600">{scopeTarget}</p>
      </div>
      <ul className="mt-4 space-y-3">
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
      {reason.trim() ? (
        <p className="mt-4 text-xs leading-relaxed text-slate-500">
          Reason: {reason.trim().slice(0, 120)}
          {reason.trim().length > 120 ? "…" : ""}
        </p>
      ) : null}
      <p className="mt-3 text-xs text-slate-500">Expires {expiresLabel}</p>
    </div>
  );
}

type SourceReceiptSummaryProps = {
  receipt: GuardReceipt;
};

export function SourceReceiptSummary({ receipt }: SourceReceiptSummaryProps) {
  const evidenceHref = `/evidence?search=${encodeURIComponent(receipt.receipt_id)}`;
  const artifactLabel = receipt.artifact_name ?? receipt.artifact_id;

  const handleCopyArtifact = () => {
    if (!receipt.artifact_id || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(receipt.artifact_id);
  };

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Source: approval record</p>
      <div className="mt-3 flex items-start gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-200/80 text-slate-600">
          <HiMiniCodeBracket className="h-4 w-4" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-brand-dark">{artifactLabel}</p>
          <p className="mt-1 text-xs text-slate-600">
            {harnessDisplayName(receipt.harness)} · Reviewed recently
          </p>
        </div>
      </div>
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
            className="mt-1 inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline"
          >
            <HiMiniDocumentText className="h-3.5 w-3.5" aria-hidden="true" />
            {receipt.receipt_id}
          </a>
        </div>
      </div>
    </div>
  );
}

type ResultPreviewProps = {
  scope: RequestScopeValue;
  harness: string;
  expiresLabel: string;
};

export function ResultPreview({ scope, harness, expiresLabel }: ResultPreviewProps) {
  const showHarness = (scope === "artifact" || scope === "harness") && harness.trim();
  const actionLabel = resolveResultActionLabel(scope);

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Result preview</p>
      <p className="mt-3 text-sm leading-relaxed text-brand-dark">
        If approved in Guard Cloud, Guard will allow {actionLabel}
        {showHarness ? ` for ${harnessDisplayName(harness)}` : ""} until {expiresLabel}.
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
