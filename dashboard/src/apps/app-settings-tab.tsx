import { useState, useRef, useCallback, memo } from "react";
import {
  HiMiniExclamationTriangle,
  HiMiniCloud,
} from "react-icons/hi2";
import {
  EmptyState,
  SectionLabel,
  Tag,
} from "../approval-center-primitives";
import { harnessDisplayName } from "../approval-center-utils";
import { useFocusTrap } from "../use-focus-trap";
import type { GuardPolicyDecision } from "../guard-types";
import type { AppStatus } from "./app-types";

type AppSettingsTabProps = {
  harness: string;
  status: AppStatus;
  harnessPolicies: GuardPolicyDecision[];
  onClearAppPolicies?: (harness: string) => Promise<void>;
  policyError: string | null;
  onRetry: () => void;
};

export const AppSettingsTab = memo(function AppSettingsTab(props: AppSettingsTabProps) {
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [clearing, setClearing] = useState(false);
  const confirmRef = useRef<HTMLDivElement>(null);
  useFocusTrap(showClearConfirm, confirmRef);

  const handleClear = useCallback(async () => {
    if (!props.onClearAppPolicies) return;
    setClearing(true);
    await props.onClearAppPolicies(props.harness);
    setClearing(false);
    setShowClearConfirm(false);
  }, [props.onClearAppPolicies, props.harness]);

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,0.8fr)]">
      <div className="space-y-6">
        {props.policyError && (
          <div className="guard-fade-in rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
              <div className="flex-1">
                <p className="text-sm font-medium text-brand-dark">Unable to load decisions</p>
                <p className="mt-1 text-sm text-muted-foreground">{props.policyError}</p>
                <button
                  onClick={props.onRetry}
                  className="mt-3 inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
                >
                  Retry
                </button>
              </div>
            </div>
          </div>
        )}
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <div className="flex items-center justify-between gap-3">
            <SectionLabel>Remembered decisions</SectionLabel>
            {props.harnessPolicies.length > 0 && props.onClearAppPolicies && (
              <button
                onClick={() => setShowClearConfirm(true)}
                className="text-xs font-medium text-slate-500 hover:text-brand-dark transition-colors"
              >
                Clear all
              </button>
            )}
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            Guard remembers these choices for {harnessDisplayName(props.harness)}. Remove any to be asked again.
          </p>
          {props.harnessPolicies.length === 0 ? (
            <div className="mt-4">
              <EmptyState
                title="No remembered decisions"
                body="Guard will remember choices here after you allow or stop actions for this app."
                tone="teach"
              />
            </div>
          ) : (
            <div className={`mt-4 space-y-2 ${clearing ? "guard-fade-out" : ""}`}>
              {props.harnessPolicies.map((policy) => (
                <div
                  key={`${policy.scope}-${policy.artifact_id ?? policy.workspace ?? "global"}`}
                  className="flex items-center justify-between rounded-lg border border-slate-200/70 px-4 py-3 transition-all duration-200 hover:border-brand-blue/30 hover:shadow-sm"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-brand-dark">
                      {policy.scope === "global"
                        ? "Every app"
                        : policy.scope === "harness"
                        ? "This app"
                        : policy.scope === "artifact" && policy.artifact_id
                        ? policy.artifact_id
                        : policy.scope}
                    </p>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {policy.action} · {policy.reason || "No reason given"}
                    </p>
                  </div>
                  <Tag tone={policy.action === "allow" ? "green" : policy.action === "block" ? "blue" : "blue"}>
                    {policy.action}
                  </Tag>
                </div>
              ))}
            </div>
          )}
        </div>

        {showClearConfirm && (
          <div ref={confirmRef} className="guard-fade-in rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
              <div>
                <h3 className="text-sm font-semibold text-brand-dark">
                  Clear all remembered decisions for {harnessDisplayName(props.harness)}?
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  This will remove {props.harnessPolicies.length} remembered decision{props.harnessPolicies.length !== 1 ? "s" : ""}. Guard will ask again next time matching actions run.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    onClick={handleClear}
                    disabled={clearing}
                    className="inline-flex min-h-9 items-center rounded-lg bg-brand-attention px-3 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-50"
                  >
                    {clearing ? "Clearing…" : "Clear decisions"}
                  </button>
                  <button
                    onClick={() => setShowClearConfirm(false)}
                    className="inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
                  >
                    Keep decisions
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {props.harnessPolicies.length > 0 && !showClearConfirm && (
          <div className="rounded-xl border border-brand-purple/10 bg-brand-purple/[0.03] p-4 sm:p-5">
            <div className="flex items-start gap-3">
              <HiMiniCloud className="mt-0.5 h-5 w-5 shrink-0 text-brand-purple" aria-hidden="true" />
              <div>
                <p className="text-sm font-semibold text-brand-dark">Team policy sync</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  Cloud keeps your team's rules consistent across all devices.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="space-y-6">
        {props.status === "needs_setup" && (
          <div className="rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
              <div>
                <SectionLabel>Setup needed</SectionLabel>
                <p className="mt-2 text-sm text-muted-foreground">
                  This app is detected but not active. Run Guard with this app once to complete setup.
                </p>
                <div className="mt-4 rounded-xl bg-white/60 p-4">
                  <p className="font-mono text-xs text-brand-dark">{`npx @hol/guard install ${props.harness}`}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
});
