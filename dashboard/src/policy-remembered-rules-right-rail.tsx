import {
  HiMiniArrowPath,
  HiMiniCloudArrowUp,
  HiMiniFolder,
  HiMiniGlobeAlt,
  HiMiniShieldCheck,
  HiMiniUsers,
} from "react-icons/hi2";
import { ActionButton, SectionLabel, Tag } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { resolveCloudPolicyControlsUrl, resolveSecurityModeCopy } from "./policy-workspace-helpers";

const REVIEW_SCOPE_LADDER = [
  {
    label: "Once",
    detail: "One time only.",
    icon: HiMiniArrowPath,
  },
  {
    label: "This cwd",
    detail: "Reuse in this working directory.",
    icon: HiMiniFolder,
  },
  {
    label: "This project",
    detail: "Reuse across this project.",
    icon: HiMiniFolder,
  },
  {
    label: "This harness",
    detail: "Reuse across this tool harness.",
    icon: HiMiniGlobeAlt,
  },
  {
    label: "Team policy",
    detail: "Organization-wide policy.",
    icon: HiMiniUsers,
  },
] as const;

type PolicyRememberedRulesRightRailProps = {
  snapshot: GuardRuntimeSnapshot;
  onOpenCloudExceptions: () => void;
};

export function PolicyRememberedRulesRightRail({
  snapshot,
  onOpenCloudExceptions,
}: PolicyRememberedRulesRightRailProps) {
  const modeCopy = resolveSecurityModeCopy(snapshot.security_level);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);

  return (
    <aside className="space-y-4 lg:sticky lg:top-4">
      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
        <SectionLabel>Active mode</SectionLabel>
        <div className="mt-3 flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
            <HiMiniShieldCheck className="h-5 w-5" aria-hidden="true" />
          </span>
          <div>
            <p className="text-sm font-semibold text-brand-dark">{modeCopy.label}</p>
            <p className="mt-1 text-sm leading-relaxed text-slate-600">{modeCopy.description}</p>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
        <p className="font-medium text-brand-dark">Approvals are still fast</p>
        <p className="mt-1 text-xs leading-relaxed text-slate-500">
          When you approve in Inbox, you pick how broadly Guard should remember the decision.
        </p>
        <ul className="mt-3 space-y-2.5">
          {REVIEW_SCOPE_LADDER.map((step) => {
            const Icon = step.icon;
            return (
              <li key={step.label} className="flex gap-2.5">
                <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500">
                  <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                </span>
                <div>
                  <p className="text-sm font-medium text-brand-dark">{step.label}</p>
                  <p className="text-xs leading-relaxed text-slate-500">{step.detail}</p>
                </div>
              </li>
            );
          })}
        </ul>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-sm">
        <p className="font-medium text-brand-dark">Cloud exceptions</p>
        <p className="mt-2 text-sm leading-relaxed text-slate-600">
          Governed risk acceptances override team policy when approved in Guard Cloud. They sync as signed bundle
          entries on this device.
        </p>
        <button
          type="button"
          onClick={onOpenCloudExceptions}
          className="mt-3 text-sm font-medium text-brand-blue hover:underline"
        >
          Open Cloud exceptions tab
        </button>
        {cloudControlsUrl ? (
          <div className="mt-3">
            <ActionButton href={cloudControlsUrl} variant="secondary">
              <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Open Guard Cloud
            </ActionButton>
          </div>
        ) : null}
      </div>

      <p className="text-xs leading-relaxed text-slate-500">
        Local remembered rules are for your machine only. Cloud exceptions and team policy sync from Guard Cloud.
      </p>
    </aside>
  );
}
