import { type MouseEvent } from "react";
import { HiMiniCloudArrowUp } from "react-icons/hi2";
import { guardAwareHref } from "./guard-api";
import { ActionButton } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { PolicyActiveModeCard } from "./policy-active-mode-card";
import { PolicyGuardCloudBundleCard } from "./policy-guard-cloud-bundle-card";
import { resolveCloudPolicyControlsUrl } from "./policy-workspace-helpers";

const SCOPE_LADDER = [
  ["Once", "One time only."],
  ["This cwd", "Reuse in this working directory."],
  ["This project", "Reuse across this project."],
  ["This harness", "Reuse across this tool harness."],
  ["Team policy", "Organization-wide policy."],
] as const;

/**
 * Everything explanatory about this page, in one disclosure at the
 * bottom — nothing in here is needed to use the list above it.
 */
export function PolicyRulesAbout(props: {
  snapshot: GuardRuntimeSnapshot;
  decisionOrder: readonly string[];
  onOpenCloudExceptions: () => void;
  onNavigate?: (pathname: string) => void;
}) {
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(props.snapshot);
  // Keep the page's own navigation, and the guard token with it, instead of
  // a bare anchor that reloads without one.
  const openExtensions = (event: MouseEvent<HTMLAnchorElement>) => {
    if (!props.onNavigate) return;
    event.preventDefault();
    props.onNavigate("/extensions");
  };
  return (
    <details className="rounded-2xl border border-slate-200 bg-white shadow-sm">
      <summary className="cursor-pointer list-none px-4 py-3 text-sm font-medium text-brand-dark marker:hidden [&::-webkit-details-marker]:hidden">
        About these rules
        <span className="mt-0.5 block text-xs font-normal text-slate-500">
          How Guard decides, what the scopes mean, and the sync and protection state on this device.
        </span>
      </summary>
      <div className="space-y-5 border-t border-slate-100 p-4 sm:p-5">
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <h3 className="text-sm font-semibold text-brand-dark">How Guard decides</h3>
            <ol className="mt-2 space-y-1.5 text-sm leading-relaxed text-slate-600">
              {props.decisionOrder.map((step, index) => (
                <li key={step}><strong className="text-brand-dark">{index + 1}.</strong> {step}</li>
              ))}
            </ol>
            <a href={guardAwareHref("/extensions")} onClick={openExtensions} className="mt-2 inline-flex text-sm font-semibold text-brand-blue hover:underline">Open Extensions</a>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-brand-dark">What the scopes mean</h3>
            <ul className="mt-2 space-y-1.5 text-sm leading-relaxed text-slate-600">
              {SCOPE_LADDER.map(([label, detail]) => (
                <li key={label}><span className="font-medium text-brand-dark">{label}</span> — {detail}</li>
              ))}
            </ul>
          </div>
        </div>

        <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4">
          <p className="text-sm font-medium text-brand-dark">Cloud exceptions</p>
          <p className="mt-1 text-sm leading-relaxed text-slate-600">
            Bounded exceptions apply to contextual Cloud rules. They never weaken a managed-restrictive Extension
            block, and sync as signed bundle entries on this device. Local remembered rules are for your machine
            only; cloud exceptions and team policy sync from Guard Cloud.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" onClick={props.onOpenCloudExceptions} className="text-sm font-medium text-brand-blue hover:underline">
              Open Cloud exceptions tab
            </button>
            {cloudControlsUrl ? (
              <ActionButton href={cloudControlsUrl} variant="secondary">
                <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
                Open Guard Cloud
              </ActionButton>
            ) : null}
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1.55fr)_minmax(10rem,1fr)] lg:items-start">
          <PolicyGuardCloudBundleCard snapshot={props.snapshot} />
          <PolicyActiveModeCard snapshot={props.snapshot} />
        </div>
      </div>
    </details>
  );
}
