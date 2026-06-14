import { HiMiniShieldCheck } from "react-icons/hi2";
import { SectionLabel, Tag } from "./approval-center-primitives";
import { scopeLabel } from "./approval-center-utils";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { resolveCloudPolicyControlsUrl, resolveSecurityModeCopy } from "./policy-workspace-helpers";

const REVIEW_SCOPE_LADDER = [
  { scope: "artifact", detail: "Guard remembers only the next matching retry." },
  { scope: "workspace", detail: "Guard remembers the same action in this project folder." },
  { scope: "publisher", detail: "Guard remembers actions from the same source in this app." },
  { scope: "harness", detail: "Guard remembers the action across this app." },
  { scope: "global", detail: "Guard remembers the action on every project on this device." },
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
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-sm font-semibold text-brand-dark">{modeCopy.label}</p>
              <Tag tone={modeCopy.tone}>{modeCopy.tone === "attention" ? "Protect" : "Active"}</Tag>
            </div>
            <p className="mt-1 text-sm leading-relaxed text-slate-600">{modeCopy.description}</p>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-slate-50/80 p-4 text-sm text-slate-600">
        <p className="font-medium text-brand-dark">Approvals are still fast</p>
        <p className="mt-1 text-xs leading-relaxed text-slate-500">
          When you approve in Inbox, you pick how broadly Guard should remember the decision.
        </p>
        <ol className="mt-3 space-y-2.5">
          {REVIEW_SCOPE_LADDER.map((step) => (
            <li key={step.scope} className="flex gap-2.5">
              <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full bg-brand-blue/70" aria-hidden="true" />
              <div>
                <p className="text-sm font-medium text-brand-dark">{scopeLabel(step.scope, "policy")}</p>
                <p className="text-xs leading-relaxed text-slate-500">{step.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-sm">
        <p className="font-medium text-brand-dark">Cloud exceptions</p>
        <p className="mt-2 text-sm leading-relaxed text-slate-600">
          Governed risk acceptances override team policy when approved in Guard Cloud. They sync as signed
          bundle entries on this device.
        </p>
        <button
          type="button"
          onClick={onOpenCloudExceptions}
          className="mt-3 text-sm font-medium text-brand-blue hover:underline"
        >
          Open Cloud exceptions tab
        </button>
        {cloudControlsUrl ? (
          <a
            href={cloudControlsUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-2 block text-sm font-medium text-brand-blue hover:underline"
          >
            Open Guard Cloud
          </a>
        ) : null}
      </div>
    </aside>
  );
}
