import { useCallback, useState } from "react";
import { HiMiniSparkles, HiMiniXMark, HiMiniBolt } from "react-icons/hi2";
import { SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import {
  safeLocalStorage,
  STREAK_MILESTONE_MESSAGES,
  resolveNewAppDiscoveries,
} from "./home-dashboard-model";
import type { GuardManagedInstall, GuardReceipt, GuardPolicyDecision } from "./guard-types";

const MILESTONE_STREAKS = [7, 14, 30];

export function StreakMilestoneBanner({ streak }: { streak: number }) {
  const milestone = MILESTONE_STREAKS.includes(streak) ? streak : null;
  const storageKey = milestone ? `guard-streak-milestone-dismissed-${milestone}` : "";
  const [dismissed, setDismissed] = useState(() => {
    if (!storageKey) return true;
    return safeLocalStorage.getItem(storageKey) === "1";
  });

  const handleDismiss = useCallback(() => {
    setDismissed(true);
    if (storageKey) safeLocalStorage.setItem(storageKey, "1");
  }, [storageKey]);

  if (!milestone || dismissed) return null;

  const messages: Record<number, string> = STREAK_MILESTONE_MESSAGES;

  return (
    <div className="guard-fade-in relative overflow-hidden rounded-2xl border border-brand-purple/20 bg-brand-purple/[0.04] p-5 shadow-sm sm:p-6">
      <div className="absolute -right-6 -top-6 h-24 w-24 rounded-full bg-brand-purple/10" />
      <div className="relative flex items-start gap-3">
        <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-purple/10">
          <HiMiniSparkles className="h-5 w-5 text-brand-purple" aria-hidden="true" />
        </span>
        <div className="flex-1">
          <SectionLabel>{streak} day coverage</SectionLabel>
          <p className="mt-2 text-sm text-muted-foreground">{messages[milestone]}</p>
        </div>
        <button
          onClick={handleDismiss}
          className="shrink-0 rounded-full p-1.5 text-muted-foreground transition-colors hover:bg-white/70 hover:text-brand-dark"
          aria-label="Dismiss streak celebration"
        >
          <HiMiniXMark className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}

export function NewAppDiscoveryBanner(props: {
  managedInstalls: GuardManagedInstall[];
  observedHarnesses: string[];
  receipts: GuardReceipt[];
  policies: GuardPolicyDecision[];
  onOpenAppDetail: (harness: string) => void;
}) {
  const discovered = resolveNewAppDiscoveries(props.managedInstalls, props.observedHarnesses);

  return (
    <>
      {discovered.map((harness) => (
        <NewAppBanner
          key={harness}
          harness={harness}
          onOpenAppDetail={props.onOpenAppDetail}
        />
      ))}
    </>
  );
}

function NewAppBanner(props: {
  harness: string;
  onOpenAppDetail: (harness: string) => void;
}) {
  const storageKey = `guard-new-app-dismissed-${props.harness}`;
  const [dismissed, setDismissed] = useState(() => {
    return safeLocalStorage.getItem(storageKey) === "1";
  });

  const handleDismiss = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    setDismissed(true);
    safeLocalStorage.setItem(storageKey, "1");
  }, [storageKey]);

  const handleOpen = useCallback(() => {
    props.onOpenAppDetail(props.harness);
  }, [props.onOpenAppDetail, props.harness]);

  if (dismissed) return null;

  return (
    <div className="guard-fade-in flex w-full items-center gap-3 rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-3 text-left transition-colors hover:bg-brand-blue/[0.08]">
      <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10">
        <HiMiniBolt className="h-4 w-4 text-brand-blue" aria-hidden="true" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-brand-dark">
          Guard discovered {harnessDisplayName(props.harness)}
        </p>
        <p className="text-xs text-slate-500">
          Guard saw this app but it is not set up yet. Open to connect it.
        </p>
      </div>
      <button
        type="button"
        onClick={handleOpen}
        className="inline-flex min-h-11 items-center justify-center rounded-lg px-3 text-sm font-semibold text-brand-blue transition-colors hover:bg-white/70"
      >
        Open
      </button>
      <button
        type="button"
        onClick={handleDismiss}
        className="shrink-0 rounded-full p-1.5 text-slate-400 transition-colors hover:bg-white/70 hover:text-brand-dark"
        aria-label={`Dismiss ${harnessDisplayName(props.harness)} discovery`}
      >
        <HiMiniXMark className="h-4 w-4" aria-hidden="true" />
      </button>
    </div>
  );
}
