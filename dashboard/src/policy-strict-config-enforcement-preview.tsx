import { HiMiniArrowTopRightOnSquare } from "react-icons/hi2";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import {
  POLICY_PANEL_CARD_CLASS,
  STRICT_CONFIG_EVALUATION_STEPS,
} from "./policy-strict-config-surfaces";
import { STRICT_POLICY_EVALUATION_ORDER } from "./policy-strict-config-utils";

type PolicyEnforcementPreviewCardProps = {
  cloudControlsUrl: string | null;
};

export function PolicyEnforcementPreviewCard({ cloudControlsUrl }: PolicyEnforcementPreviewCardProps) {
  return (
    <div className={`${POLICY_PANEL_CARD_CLASS} p-4`}>
      <SectionLabel>How Guard decides</SectionLabel>
      <p className="mt-1.5 text-sm leading-relaxed text-slate-600">
        Evaluation order when Guard decides what to do next.
      </p>

      <div className="mt-4">
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
          {STRICT_CONFIG_EVALUATION_STEPS.map((step, index) => {
            const Icon = step.icon;
            return (
              <div key={step.label} className={`relative flex min-w-0 flex-col rounded-xl border p-3 ${step.surfaceClass}`}>
                <span className="absolute right-3 top-3 text-[10px] font-semibold tabular-nums text-slate-400" aria-hidden="true">
                  {index + 1}
                </span>
                <span className={`flex h-8 w-8 items-center justify-center rounded-lg bg-white/80 ${step.iconClass}`}>
                  <Icon className="h-4 w-4" aria-hidden="true" />
                </span>
                <p className="mt-2 text-sm font-semibold text-brand-dark">{step.label}</p>
                <p className="mt-1 text-xs leading-relaxed text-slate-600">{step.description}</p>
              </div>
            );
          })}
        </div>
      </div>

      <div className="mt-4 flex flex-col gap-3 border-t border-slate-100 pt-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="max-w-xl text-xs leading-relaxed text-slate-500">
          Evaluation order: {STRICT_POLICY_EVALUATION_ORDER.join(" → ")}. Team-wide exceptions are managed in Guard
          Cloud.
        </p>
        {cloudControlsUrl ? (
          <div className="shrink-0">
            <ActionButton href={cloudControlsUrl} variant="secondary">
              Open Guard Cloud
              <HiMiniArrowTopRightOnSquare className="ml-1.5 h-4 w-4" aria-hidden="true" />
            </ActionButton>
          </div>
        ) : null}
      </div>
    </div>
  );
}
