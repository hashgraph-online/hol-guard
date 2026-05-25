import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type ReactNode } from "react";
import {
  HiMiniCheckCircle,
  HiMiniMinusCircle,
  HiMiniChevronRight,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniShieldCheck,
  HiMiniSparkles,
  HiMiniExclamationTriangle,
  HiMiniXMark,
  HiMiniBolt,
  HiMiniQuestionMarkCircle,
  HiMiniCloud,
} from "react-icons/hi2";
import {
  ActionButton,
  Badge,
  EmptyState,
  SectionLabel,
  GuardHero,
  ProofStrip,
} from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime, formatNumber, isDisplayableHarness } from "./approval-center-utils";
import { useFocusTrap } from "./use-focus-trap";
import { DeviceProofCard, resolveCloudIntelCopy } from "./runtime-overview";
import type {
  GuardApprovalGatePublicConfig,
  GuardApprovalRequest,
  GuardManagedInstall,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
} from "./guard-types";

export const safeLocalStorage = {
  getItem(key: string): string | null {
    try {
      return typeof window !== "undefined" ? window.localStorage.getItem(key) : null;
    } catch {
      return null;
    }
  },
  setItem(key: string, value: string): void {
    try {
      if (typeof window !== "undefined") {
        window.localStorage.setItem(key, value);
      }
    } catch {
      return;
    }
  },
};

export const STREAK_MILESTONE_MESSAGES: Record<number, string> = {
  7: "One week of Guard activity on this machine.",
  14: "Two weeks of consistent Guard coverage.",
  30: "A full month of daily Guard coverage.",
};

export function resolveCloudUpsellVisible(
  pendingCount: number,
  cloudState: GuardRuntimeSnapshot["cloud_state"]
): boolean {
  if (pendingCount > 0) return false;
  return cloudState === "local_only";
}

export function buildEmptyStateCopy(): { title: string; body: string; installHint: string } {
  return {
    title: "No apps connected",
    body: "Connect an AI app so Guard can start protecting it. Guard works with Codex, Claude Code, Cursor, Hermes, and more.",
    installHint: "hol-guard apps connect <app>",
  };
}

export function buildDaemonErrorCopy(): { title: string; body: string; primaryCta: string; secondaryCta: string } {
  return {
    title: "Guard is not responding",
    body: "The local Guard service is not reachable. Go to Settings to repair the connection and restore protection.",
    primaryCta: "Go to Settings",
    secondaryCta: "Open review queue",
  };
}

export function redactHomeArtifactLabel(value: string | null): string {
  if (value === null || value.trim().length === 0) {
    return "a local action";
  }
  const trimmed = value.trim();
  if (
    trimmed.includes("/") ||
    trimmed.includes("\\") ||
    trimmed.includes("~") ||
    trimmed.includes(":") ||
    trimmed.length > 48
  ) {
    return "a local action";
  }
  return trimmed;
}

export function buildRecentProtectionCopy(receipt: GuardReceipt): string {
  const decisionLabel = receipt.policy_decision === "block" ? "blocked" : "allowed";
  return `${harnessDisplayName(receipt.harness)} ${decisionLabel} ${redactHomeArtifactLabel(receipt.artifact_name)}`;
}

type HomeRequestState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardApprovalRequest[] };

type HomeRuntimeState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; snapshot: GuardRuntimeSnapshot };

type HomePolicyState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardPolicyDecision[] };

export function HomeWorkspace(props: {
  requests: HomeRequestState;
  runtime: HomeRuntimeState;
  policies: HomePolicyState;
  onOpenInbox: () => void;
  onOpenFleet: () => void;
  onOpenEvidence: () => void;
  onOpenSettings: () => void;
  onClearPolicies: (scope: { harness?: string; all?: boolean }) => void;
  onOpenAppDetail: (harness: string) => void;
  clearConfirm: { harness?: string; all?: boolean } | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onConfirmClear: (credentials?: { approval_password?: string; approval_totp_code?: string }) => Promise<void>;
  onCancelClear: () => void;
  onOpenHelp?: () => void;
}) {
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [clearPassword, setClearPassword] = useState("");
  const [clearTotpCode, setClearTotpCode] = useState("");
  const [clearError, setClearError] = useState<string | null>(null);
  const [clearSubmitting, setClearSubmitting] = useState(false);
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    };
  }, []);

  const showToast = useCallback((message: string) => {
    setToastMessage(message);
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    toastTimerRef.current = setTimeout(() => setToastMessage(null), 3000);
  }, []);

  const handleClearPolicies = useCallback((scope: { harness?: string; all?: boolean }) => {
    props.onClearPolicies(scope);
  }, [props.onClearPolicies]);

  const handleClearPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setClearPassword(event.target.value);
    setClearError(null);
  }, []);

  const handleClearTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setClearTotpCode(event.target.value);
    setClearError(null);
  }, []);

  const handleConfirmClearWithToast = useCallback(async () => {
    const confirm = props.clearConfirm;
    setClearSubmitting(true);
    setClearError(null);
    try {
      await props.onConfirmClear({
        ...(clearPassword ? { approval_password: clearPassword } : {}),
        ...(clearTotpCode ? { approval_totp_code: clearTotpCode } : {}),
      });
      setClearPassword("");
      setClearTotpCode("");
      if (confirm?.harness) {
        showToast(`Cleared for ${harnessDisplayName(confirm.harness)}`);
      } else if (confirm?.all) {
        showToast("Cleared all decisions");
      }
    } catch (error) {
      setClearError(error instanceof Error ? error.message : "Unable to clear remembered decisions.");
    } finally {
      setClearSubmitting(false);
    }
  }, [clearPassword, clearTotpCode, props.clearConfirm, props.onConfirmClear, showToast]);

  const snapshot = props.runtime.kind === "ready" ? props.runtime.snapshot : null;
  const queuedCount = props.requests.kind === "ready" ? props.requests.items.length : 0;
  const policyItems = props.policies.kind === "ready" ? props.policies.items : [];
  const managedInstalls = (snapshot?.managed_installs ?? []).filter((item: GuardManagedInstall) => isDisplayableHarness(item.harness));
  const activeInstalls = managedInstalls.filter((item: GuardManagedInstall) => item.active);
  const observedHarnesses = snapshot
    ? Array.from(
        new Set([
          ...snapshot.items.map((item: GuardApprovalRequest) => item.harness),
          ...snapshot.latest_receipts.map((receipt: GuardReceipt) => receipt.harness),
          ...policyItems.map((policy: GuardPolicyDecision) => policy.harness),
        ].filter(isDisplayableHarness))
      ).sort()
    : [];
  const clearHarnesses = activeInstalls.length > 0 ? activeInstalls.map((i: GuardManagedInstall) => i.harness) : observedHarnesses;
  const watchedAppsCount = activeInstalls.length > 0 ? activeInstalls.length : observedHarnesses.length;

  const state = useMemo(
    () =>
      deriveHomeState({
        hasActiveInstalls: activeInstalls.length > 0,
        hasObservedHarnesses: observedHarnesses.length > 0,
        queuedCount,
        watchedAppsCount,
      }),
    [activeInstalls.length, observedHarnesses.length, queuedCount, watchedAppsCount]
  );

  const dailyStory = useMemo(
    () => (snapshot ? buildDailyStory(snapshot.latest_receipts, queuedCount) : null),
    [snapshot, queuedCount]
  );
  const streak = useMemo(() => (snapshot ? computeStreak(snapshot.latest_receipts) : 0), [snapshot]);
  const cloudUpsellVisible = useMemo(
    () => (snapshot ? resolveCloudUpsellVisible(queuedCount, snapshot.cloud_state) : false),
    [snapshot, queuedCount]
  );

  const ctaAction =
    state.ctaTarget === "inbox"
      ? props.onOpenInbox
      : state.ctaTarget === "fleet"
      ? props.onOpenFleet
      : props.onOpenEvidence;

  if (props.runtime.kind === "loading" || props.requests.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-36 w-full" />
        <div className="guard-skeleton h-16 w-full" />
      </div>
    );
  }

  if (props.runtime.kind === "error") {
    const errorCopy = buildDaemonErrorCopy();
    return (
      <EmptyState
        title={errorCopy.title}
        body={errorCopy.body}
        action={
          <div className="flex flex-col gap-2 sm:flex-row">
            <ActionButton onClick={props.onOpenSettings}>{errorCopy.primaryCta}</ActionButton>
            <ActionButton variant="outline" onClick={props.onOpenInbox}>{errorCopy.secondaryCta}</ActionButton>
          </div>
        }
        tone="teach"
      />
    );
  }

  if (!snapshot) return null;

  return (
    <div className="space-y-6">
      {toastMessage && (
        <div className="guard-fade-in fixed bottom-6 right-6 z-50 flex items-center gap-3 rounded-xl border border-brand-green/25 bg-brand-green-bg/90 px-4 py-3 shadow-lg backdrop-blur">
          <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
          <p className="text-sm font-medium text-brand-green-text">{toastMessage}</p>
        </div>
      )}

      <GuardHero
        status={state.heroStatus}
        headline={state.headline}
        subheadline={state.subheadline}
        cta={
          <ActionButton onClick={ctaAction} data-primary="true">
            {state.ctaLabel}
          </ActionButton>
        }
      />

      <ProofStrip
        items={[
          { label: "Pending", value: formatNumber(queuedCount), tone: queuedCount > 0 ? "blue" : "slate" },
          { label: "Apps", value: formatNumber(watchedAppsCount), tone: watchedAppsCount > 0 ? "green" : "slate" },
          { label: "History", value: formatNumber(snapshot?.receipt_count ?? 0), tone: "purple" },
        ]}
      />

      <StreakMilestoneBanner streak={streak} />

      <NewAppDiscoveryBanner
        managedInstalls={managedInstalls}
        observedHarnesses={observedHarnesses}
        receipts={snapshot.latest_receipts}
        policies={policyItems}
        onOpenAppDetail={props.onOpenAppDetail}
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]">
        <section className="space-y-6">
          <AppsAtAGlance
            managedInstalls={managedInstalls}
            observedHarnesses={observedHarnesses}
            queuedItems={props.requests.kind === "ready" ? props.requests.items : []}
            onOpenAppDetail={props.onOpenAppDetail}
          />

          {dailyStory && (
            <CollapsibleCard
              id="daily-brief"
              icon={<HiMiniShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-brand-green" aria-hidden="true" />}
              label={dailyStory.title}
              defaultOpen={true}
            >
              <p className="text-sm text-muted-foreground">{dailyStory.body}</p>
              {dailyStory.stats && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {dailyStory.stats.map((s) => (
                    <span
                      key={s.label}
                      className="rounded-full bg-white/70 px-3 py-1 text-xs font-medium text-brand-dark"
                    >
                      {s.value} {s.label}
                    </span>
                  ))}
                </div>
              )}
            </CollapsibleCard>
          )}
        </section>

        <section className="space-y-6">
          <DeviceProofCard device={snapshot.device} proofStatus={snapshot.proof_status} />

          <CloudStatusCard
            snapshot={snapshot}
            showUpsell={cloudUpsellVisible}
            onOpenSettings={props.onOpenSettings}
          />

          <KeyboardHelpCard onOpenHelp={props.onOpenHelp} />

          {snapshot.latest_receipts.length > 0 && (
            <RecentProtectionSection receipts={snapshot.latest_receipts} />
          )}

          {policyItems.length > 0 && (
            <div className="rounded-xl border border-slate-100 p-4">
              <SectionLabel>Reset remembered decisions</SectionLabel>
              <p className="mt-1 text-sm text-slate-500">
                Clear remembered decisions when you want Guard to ask again next time. This does not remove your history.
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {clearHarnesses.slice(0, 4).map((harness: string) => (
                  <ClearHarnessButton
                    key={harness}
                    harness={harness}
                    onClearPolicies={handleClearPolicies}
                  />
                ))}
              </div>
            </div>
          )}
        </section>
      </div>

      {props.clearConfirm && (
        <ClearConfirmDialog
          clearConfirm={props.clearConfirm}
          approvalGate={props.approvalGate}
          clearPassword={clearPassword}
          clearTotpCode={clearTotpCode}
          clearError={clearError}
          clearSubmitting={clearSubmitting}
          onClearPasswordChange={handleClearPasswordChange}
          onClearTotpCodeChange={handleClearTotpCodeChange}
          onCancelClear={props.onCancelClear}
          onConfirmClear={handleConfirmClearWithToast}
        />
      )}
    </div>
  );
}

function ClearConfirmDialog(props: {
  clearConfirm: { harness?: string; all?: boolean };
  approvalGate: GuardApprovalGatePublicConfig | null;
  clearPassword: string;
  clearTotpCode: string;
  clearError: string | null;
  clearSubmitting: boolean;
  onClearPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onClearTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onCancelClear: () => void;
  onConfirmClear: () => Promise<void>;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, dialogRef);
  const needsProof = props.approvalGate?.enabled === true && props.approvalGate.configured === true;

  return (
    <div className="guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Confirm clear decisions">
      <div ref={dialogRef} className="guard-fade-in w-full max-w-md rounded-2xl border border-brand-attention/20 bg-white p-6 shadow-2xl">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
              <div>
                <h3 className="text-lg font-semibold tracking-tight text-brand-dark">
                  Clear remembered decisions?
                </h3>
                <p className="mt-2 text-sm text-muted-foreground">
                  This will remove {props.clearConfirm.all ? "all saved approvals" : `decisions for ${props.clearConfirm.harness ?? "this app"}`}. Guard will ask again next time matching actions run.
                </p>
                {needsProof && (
                  <div className="mt-4 grid gap-3">
                    <label className="block">
                      <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Approval password</span>
                      <input
                        type="password"
                        autoComplete="current-password"
                        value={props.clearPassword}
                        onChange={props.onClearPasswordChange}
                        className="mt-1 min-h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                      />
                    </label>
                    {props.approvalGate?.totp_enabled === true && (
                      <label className="block">
                        <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Authenticator code</span>
                        <input
                          type="text"
                          inputMode="numeric"
                          pattern="[0-9]*"
                          maxLength={6}
                          value={props.clearTotpCode}
                          onChange={props.onClearTotpCodeChange}
                          placeholder="123456"
                          className="mt-1 min-h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm tracking-[0.28em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                        />
                      </label>
                    )}
                  </div>
                )}
                {props.clearError !== null && (
                  <p className="mt-3 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-sm text-brand-dark">
                    {props.clearError}
                  </p>
                )}
              </div>
            </div>
            <div className="mt-5 flex flex-col gap-2 sm:flex-row sm:justify-end">
              <button
                type="button"
                onClick={props.onCancelClear}
                className="inline-flex min-h-11 items-center justify-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
              >
                Keep decisions
              </button>
              <button
                type="button"
                onClick={props.onConfirmClear}
                disabled={props.clearSubmitting}
                className="inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-60"
              >
                {props.clearSubmitting ? "Clearing..." : "Clear decisions"}
              </button>
            </div>
          </div>
        </div>
  );
}

export function deriveHomeState(input: {
  hasActiveInstalls: boolean;
  hasObservedHarnesses: boolean;
  queuedCount: number;
  watchedAppsCount: number;
}): {
  heroStatus: "clear" | "needs_review" | "setup_gap";
  headline: string;
  subheadline: string;
  ctaLabel: string;
  ctaTarget: "inbox" | "fleet" | "evidence";
} {
  const { hasActiveInstalls, hasObservedHarnesses, queuedCount, watchedAppsCount } = input;

  if (queuedCount > 0) {
    return {
      heroStatus: "needs_review",
      headline: queuedCount === 1 ? "1 action needs review" : `${queuedCount} actions need review`,
      subheadline: "Guard stopped something. Review and decide whether to allow or block it.",
      ctaLabel: "Review now",
      ctaTarget: "inbox",
    };
  }

  if (!hasActiveInstalls && !hasObservedHarnesses) {
    return {
      heroStatus: "setup_gap",
      headline: "Guard is ready",
      subheadline: "Connect your first AI app so Guard can start protecting it.",
      ctaLabel: "Open Protect",
      ctaTarget: "fleet",
    };
  }

  if (!hasActiveInstalls && hasObservedHarnesses) {
    return {
      heroStatus: "setup_gap",
      headline: "Finish setup",
      subheadline: "Guard detected apps but they need setup to be fully protected.",
      ctaLabel: "Open Protect",
      ctaTarget: "fleet",
    };
  }

  return {
    heroStatus: "clear",
    headline: "All clear",
    subheadline: `Guard is watching your AI work. ${watchedAppsCount} app${watchedAppsCount !== 1 ? "s" : ""} protected. Nothing needs you right now.`,
    ctaLabel: "View history",
    ctaTarget: "evidence",
  };
}

export function buildDailyStory(
  receipts: GuardReceipt[],
  queuedCount: number
): { title: string; body: string; stats?: { label: string; value: number }[] } | null {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayReceipts = receipts.filter((r) => new Date(r.timestamp) >= today);
  const allowedToday = todayReceipts.filter((r) => r.policy_decision === "allow").length;
  const blockedToday = todayReceipts.filter((r) => r.policy_decision === "block").length;

  if (queuedCount > 0) {
    const actionText = queuedCount === 1 ? "1 action is" : `${queuedCount} actions are`;
    const pronoun = queuedCount === 1 ? "it" : "them";
    return {
      title: "Needs your attention",
      body: `${actionText} waiting for review. Guard paused ${pronoun} to keep you safe.`,
      stats: [{ label: "pending review", value: queuedCount }],
    };
  }

  if (allowedToday + blockedToday > 0) {
    return {
      title: "Today so far",
      body: `Guard allowed ${allowedToday} action${allowedToday !== 1 ? "s" : ""} and blocked ${blockedToday}.`,
      stats: [
        { label: "allowed", value: allowedToday },
        { label: "blocked", value: blockedToday },
      ],
    };
  }

  if (receipts.length > 0) {
    const last = receipts[0];
    return {
      title: "All quiet",
      body: `No new activity today. Last decision was ${formatRelativeTime(last.timestamp)}.`,
    };
  }

  return null;
}

export function computeStreak(receipts: GuardReceipt[]): number {
  if (receipts.length === 0) return 0;
  const sortedByTime = [...receipts].sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp));
  const mostRecent = new Date(sortedByTime[0].timestamp);
  const now = new Date();
  const diffHours = (now.getTime() - mostRecent.getTime()) / (1000 * 60 * 60);
  if (diffHours > 48) return 0;

  const dates = new Set(receipts.map((r) => new Date(r.timestamp).toDateString()));
  const sortedDates = Array.from(dates).sort((a, b) => +new Date(b) - +new Date(a));
  let streak = 0;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  let checkDate = new Date(today);
  for (const dateStr of sortedDates) {
    const d = new Date(dateStr);
    d.setHours(0, 0, 0, 0);
    if (d.getTime() === checkDate.getTime()) {
      streak++;
      checkDate.setDate(checkDate.getDate() - 1);
    } else if (d.getTime() < checkDate.getTime()) {
      break;
    }
  }
  return streak;
}

function AppsAtAGlance(props: {
  managedInstalls: GuardManagedInstall[];
  observedHarnesses: string[];
  queuedItems: GuardApprovalRequest[];
  onOpenAppDetail: (harness: string) => void;
}) {
  const pendingByHarness = useMemo(() => {
    const map = new Map<string, number>();
    for (const item of props.queuedItems) {
      map.set(item.harness, (map.get(item.harness) ?? 0) + 1);
    }
    return map;
  }, [props.queuedItems]);

  const sortedHarnesses = useMemo(() => {
    const all = Array.from(
      new Set([
        ...props.managedInstalls.map((i) => i.harness),
        ...props.observedHarnesses,
      ])
    );
    return all.sort((a, b) => {
      const aInstall = props.managedInstalls.find((i) => i.harness === a);
      const bInstall = props.managedInstalls.find((i) => i.harness === b);
      const aPending = pendingByHarness.get(a) ?? 0;
      const bPending = pendingByHarness.get(b) ?? 0;
      const aScore = (aInstall?.active ? 3 : aInstall !== undefined ? 2 : props.observedHarnesses.includes(a) ? 1 : 0) + (aPending > 0 ? 4 : 0);
      const bScore = (bInstall?.active ? 3 : bInstall !== undefined ? 2 : props.observedHarnesses.includes(b) ? 1 : 0) + (bPending > 0 ? 4 : 0);
      return bScore - aScore;
    });
  }, [props.managedInstalls, props.observedHarnesses, pendingByHarness]);

  if (sortedHarnesses.length === 0) {
    const emptyCopy = buildEmptyStateCopy();
    return (
      <EmptyState
        title={emptyCopy.title}
        body={emptyCopy.body}
        tone="teach"
      />
    );
  }

  return (
    <div>
      <div className="mb-3">
        <SectionLabel>Apps at a glance</SectionLabel>
        <p className="mt-1 text-sm text-slate-500">
          Guard is watching these apps on this machine.
        </p>
      </div>
      <div className="divide-y divide-slate-100 border-t border-slate-100" role="list" aria-label="Apps at a glance">
        {sortedHarnesses.map((harness, index) => {
          const install = props.managedInstalls.find((i) => i.harness === harness);
          const isObserved = props.observedHarnesses.includes(harness);
          const pending = pendingByHarness.get(harness) ?? 0;
          return (
            <AppGlanceRow
              key={harness}
              harness={harness}
              install={install}
              isObserved={isObserved}
              pending={pending}
              onOpenAppDetail={props.onOpenAppDetail}
            />
          );
        })}
      </div>
    </div>
  );
}

function AppGlanceRow(props: {
  harness: string;
  install: GuardManagedInstall | undefined;
  isObserved: boolean;
  pending: number;
  onOpenAppDetail: (harness: string) => void;
}) {
  const handleOpen = useCallback(() => {
    props.onOpenAppDetail(props.harness);
  }, [props.onOpenAppDetail, props.harness]);

  return (
    <div role="listitem">
      <button
        type="button"
        data-app-item
        onClick={handleOpen}
        className="flex w-full items-center justify-between gap-3 py-2.5 text-left transition-colors hover:bg-slate-50/60 focus:bg-brand-blue/[0.04] focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
      >
        <div className="flex min-w-0 items-center gap-2.5">
          <AppStatusIcon install={props.install} isObserved={props.isObserved} />
          <p className="truncate text-sm font-medium text-brand-dark">
            {harnessDisplayName(props.harness)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {props.pending > 0 && (
            <Badge tone="info">{props.pending} pending</Badge>
          )}
          <AppStatusBadge install={props.install} isObserved={props.isObserved} />
          <HiMiniChevronRight className="h-4 w-4 shrink-0 text-slate-300" aria-hidden="true" />
        </div>
      </button>
    </div>
  );
}

function AppStatusIcon(props: { install: GuardManagedInstall | undefined; isObserved: boolean }) {
  if (props.install?.active === true) {
    return <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />;
  }
  if (props.install !== undefined && !props.install.active) {
    return <HiMiniMinusCircle className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />;
  }
  if (props.isObserved) {
    return <HiMiniMinusCircle className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />;
  }
  return <HiMiniMinusCircle className="h-4 w-4 shrink-0 text-slate-300" aria-hidden="true" />;
}

function AppStatusBadge(props: { install: GuardManagedInstall | undefined; isObserved: boolean }) {
  if (props.install?.active === true) {
    return <Badge tone="success">Active</Badge>;
  }
  if (props.install !== undefined && !props.install.active) {
    return <Badge tone="attention">Needs setup</Badge>;
  }
  if (props.isObserved) {
    return <Badge tone="attention">Needs setup</Badge>;
  }
  return <Badge tone="attention">Needs setup</Badge>;
}

function ClearHarnessButton(props: {
  harness: string;
  onClearPolicies: (scope: { harness?: string; all?: boolean }) => void;
}) {
  const handleClick = useCallback(() => {
    void props.onClearPolicies({ harness: props.harness });
  }, [props.onClearPolicies, props.harness]);

  return (
    <ActionButton variant="outline" onClick={handleClick}>
      Clear {props.harness}
    </ActionButton>
  );
}

function CloudStatusCard(props: {
  snapshot: GuardRuntimeSnapshot;
  showUpsell: boolean;
  onOpenSettings: () => void;
}) {
  const copy = resolveCloudIntelCopy(props.snapshot.cloud_state);
  return (
    <section className="rounded-2xl border border-brand-blue/15 bg-brand-blue/[0.04] p-5 shadow-sm sm:p-6">
      <div className="flex items-start gap-3">
        <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-white/80 text-brand-blue">
          <HiMiniCloud className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <SectionLabel>Cloud sync</SectionLabel>
          <p className="mt-2 text-sm font-medium text-brand-dark">{copy.label}</p>
          <p className="mt-1 text-sm text-muted-foreground">{copy.detail}</p>
          {props.showUpsell && (
            <div className="mt-4">
              <ActionButton variant="outline" onClick={props.onOpenSettings}>
                Open sync settings
              </ActionButton>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function KeyboardHelpCard(props: { onOpenHelp?: () => void }) {
  if (!props.onOpenHelp) {
    return null;
  }
  return (
    <section className="rounded-2xl border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
      <div className="flex items-start gap-3">
        <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-100 text-brand-dark">
          <HiMiniQuestionMarkCircle className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <SectionLabel>Shortcuts</SectionLabel>
          <p className="mt-2 text-sm text-muted-foreground">
            Press ? for help or / to jump to pending review. Every Home action also works with Tab and Enter.
          </p>
          <div className="mt-4">
            <ActionButton variant="ghost" onClick={props.onOpenHelp}>
              Show shortcuts
            </ActionButton>
          </div>
        </div>
      </div>
    </section>
  );
}



type RecentReceiptRowProps = {
  receipt: GuardReceipt;
};

function RecentReceiptRow(props: RecentReceiptRowProps) {
  const { receipt } = props;
  const copy = buildRecentProtectionCopy(receipt);
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-200/70 px-4 py-3 last:border-b-0">
      <div className="min-w-0">
        <p className="text-sm text-brand-dark">
          {copy}
        </p>
      </div>
      <span className="shrink-0 text-[11px] text-muted-foreground">
        {formatRelativeTime(receipt.timestamp)}
      </span>
    </div>
  );
}

type RecentProtectionSectionProps = {
  receipts: GuardReceipt[];
};

function RecentProtectionSection(props: RecentProtectionSectionProps) {
  const recent = props.receipts.slice(0, 3);
  return (
    <section className="rounded-2xl border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
      <SectionLabel>Recent protection</SectionLabel>
      <p className="mt-2 text-sm text-muted-foreground">
        What Guard stopped or allowed recently.
      </p>
      <div className="mt-4 overflow-hidden rounded-xl border border-slate-200/70">
        {recent.map((receipt) => (
          <RecentReceiptRow key={receipt.receipt_id} receipt={receipt} />
        ))}
      </div>
    </section>
  );
}

const MILESTONE_STREAKS = [7, 14, 30];

function StreakMilestoneBanner({ streak }: { streak: number }) {
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

function NewAppDiscoveryBanner(props: {
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

export function resolveNewAppDiscoveries(
  managedInstalls: GuardManagedInstall[],
  observedHarnesses: string[]
): string[] {
  const activeHarnesses = new Set(managedInstalls.filter((i) => isDisplayableHarness(i.harness)).map((i) => i.harness));
  return observedHarnesses.filter((h) => isDisplayableHarness(h) && !activeHarnesses.has(h));
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

function CollapsibleCard(props: {
  id: string;
  icon: ReactNode;
  label: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const storageKey = `guard-collapsed-${props.id}`;
  const [isOpen, setIsOpen] = useState(() => {
    const saved = safeLocalStorage.getItem(storageKey);
    return saved === null ? (props.defaultOpen ?? true) : saved === "1";
  });

  const toggle = useCallback(() => {
    setIsOpen((prev) => {
      const next = !prev;
      safeLocalStorage.setItem(storageKey, next ? "1" : "0");
      return next;
    });
  }, [storageKey]);

  const borderClass =
    props.id === "daily-brief"
      ? "border-brand-green/15 bg-brand-green/[0.04]"
      : "border-brand-purple/15 bg-brand-purple/[0.04]";

  return (
    <div className={`rounded-2xl border ${borderClass} p-5 shadow-sm sm:p-6`}>
      <button
        onClick={toggle}
        className="flex w-full items-center gap-3 text-left"
        aria-expanded={isOpen}
        aria-controls={`collapsible-content-${props.id}`}
      >
        {props.icon}
        <div className="flex-1">
          <SectionLabel>{props.label}</SectionLabel>
        </div>
        {isOpen ? (
          <HiMiniChevronUp className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        ) : (
          <HiMiniChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        )}
      </button>
      {isOpen && (
        <div id={`collapsible-content-${props.id}`} className="mt-3 guard-fade-in">
          {props.children}
        </div>
      )}
    </div>
  );
}
