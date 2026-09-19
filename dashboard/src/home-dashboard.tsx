import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import { HiMiniCheckCircle, HiMiniShieldCheck } from "react-icons/hi2";
import { ActionButton, EmptyState, SectionLabel, GuardHero } from "./approval-center-primitives";
import { harnessDisplayName, formatNumber } from "./approval-center-utils";
import { DeviceProofCard, OperatorHealthCard } from "./runtime-overview";
import { HomeProtectionModule } from "./home-protection-module";
import { EvidenceInsightsHomePreview } from "./evidence/evidence-insights-home-preview";
import { EvidenceInsightsShareModal } from "./evidence/evidence-insights-share-modal";
import { useReceiptAnalytics } from "./evidence/use-receipt-analytics";
import { HomeCommandActivityCard } from "./command-activity/command-activity-home-card";
import {
  protectionHealthFor,
  unavailableProtectionHealth,
  useProtectionPresentationState,
} from "./protection-health";
import { WatchProtectionBanner } from "./watch-protection-banner";
import { updateSettings } from "./guard-api";
import { isConnectableAppHarness } from "./apps/harness-setup-target";
import { buildHomeRuntimeErrorCopy } from "./home-runtime-error";
import type {
  GuardApprovalGatePublicConfig,
  GuardApprovalRequest,
  GuardManagedInstall,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
} from "./guard-types";
import {
  resolveHomeQueuedCount,
  deriveHomeState,
  buildDailyStory,
  computeStreak,
  resolveCloudUpsellVisible,
} from "./home-dashboard-model";
import { ClearConfirmDialog } from "./home-clear-confirm-dialog";
import { AppsAtAGlance } from "./home-apps-at-a-glance";
import {
  ClearHarnessButton,
  CloudStatusCard,
  KeyboardHelpCard,
  RecentProtectionSection,
  CollapsibleCard,
} from "./home-dashboard-cards";
import { StreakMilestoneBanner, NewAppDiscoveryBanner } from "./home-dashboard-banners";

export { safeLocalStorage, STREAK_MILESTONE_MESSAGES, resolveCloudUpsellVisible, buildEmptyStateCopy, redactHomeArtifactLabel, buildRecentProtectionCopy, resolveHomeQueuedCount, deriveHomeState, buildDailyStory, computeStreak, resolveNewAppDiscoveries } from "./home-dashboard-model";
export { buildDaemonErrorCopy, buildHomeRuntimeErrorCopy } from "./home-runtime-error";

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
  onOpenTodayEvidence: () => void;
  onOpenInsights?: () => void;
  onOpenCommands: () => void;
  onOpenSettings: () => void;
  onRefreshRuntime?: () => Promise<void> | void;
  onReconnectSession?: () => Promise<void> | void;
  onOpenSupplyChain?: () => void;
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
  const [shareOpen, setShareOpen] = useState(false);
  const handleShareOpen = useCallback(() => {
    setShareOpen(true);
  }, []);
  const handleShareClose = useCallback(() => {
    setShareOpen(false);
  }, []);
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const analyticsEnabled = props.runtime.kind === "ready" && (props.runtime.snapshot?.receipt_count ?? 0) > 0;
  const analyticsState = useReceiptAnalytics(analyticsEnabled);

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

  const handleTurnProtectionOn = useCallback(() => {
    void updateSettings({ protection_posture: "protected" })
      .then(async () => {
        await props.onRefreshRuntime?.();
        props.onOpenSettings();
      })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : "Unable to turn protection on.";
        showToast(message);
        props.onOpenSettings();
      });
  }, [props.onOpenSettings, props.onRefreshRuntime, showToast]);

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
  const queuedCount = resolveHomeQueuedCount({
    pendingCount: snapshot?.pending_count ?? null,
    requestCount: props.requests.kind === "ready" ? props.requests.items.length : null,
  });
  const policyItems = props.policies.kind === "ready" ? props.policies.items : [];
  const managedInstalls = (snapshot?.managed_installs ?? []).filter((item: GuardManagedInstall) => isConnectableAppHarness(item.harness));
  const activeInstalls = managedInstalls.filter((item: GuardManagedInstall) => item.active);
  const observedHarnesses = snapshot
    ? Array.from(
        new Set([
          ...snapshot.items.map((item: GuardApprovalRequest) => item.harness),
          ...snapshot.latest_receipts.map((receipt: GuardReceipt) => receipt.harness),
          ...policyItems.map((policy: GuardPolicyDecision) => policy.harness),
        ].filter(isConnectableAppHarness))
      ).sort()
    : [];
  const clearHarnesses = activeInstalls.length > 0 ? activeInstalls.map((i: GuardManagedInstall) => i.harness) : observedHarnesses;
  const watchedAppsCount = activeInstalls.length > 0 ? activeInstalls.length : observedHarnesses.length;
  const protectionState = useProtectionPresentationState(
    snapshot ? protectionHealthFor(snapshot) : unavailableProtectionHealth(),
  );

  const state = useMemo(
    () =>
      deriveHomeState({
        hasActiveInstalls: activeInstalls.length > 0,
        hasObservedHarnesses: observedHarnesses.length > 0,
        queuedCount,
        watchedAppsCount,
        protectionState,
      }),
    [activeInstalls.length, observedHarnesses.length, protectionState, queuedCount, watchedAppsCount]
  );

  const dailyStory = useMemo(
    () => (snapshot ? buildDailyStory(snapshot.latest_receipts, queuedCount) : null),
    [snapshot, queuedCount]
  );
  const streak = useMemo(() => {
    if (analyticsState.kind === "ready") {
      return analyticsState.data.active_day_streak;
    }
    return snapshot ? computeStreak(snapshot.latest_receipts) : 0;
  }, [analyticsState, snapshot]);
  const cloudUpsellVisible = useMemo(
    () => (snapshot ? resolveCloudUpsellVisible(queuedCount, snapshot.cloud_state) : false),
    [snapshot, queuedCount]
  );

  const ctaAction =
    state.ctaTarget === "inbox"
      ? props.onOpenInbox
      : state.ctaTarget === "protect"
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
    const errorCopy = buildHomeRuntimeErrorCopy(props.runtime.message);
    const handlePrimary = () => {
      if (errorCopy.kind === "session") {
        void props.onReconnectSession?.();
        return;
      }
      void props.onRefreshRuntime?.();
    };
    const handleSecondary = errorCopy.kind === "session" ? props.onOpenInbox : props.onOpenSettings;
    return (
      <EmptyState
        title={errorCopy.title}
        body={errorCopy.body}
        action={
          <div className="flex flex-col gap-2 sm:flex-row">
            <ActionButton onClick={handlePrimary}>{errorCopy.primaryCta}</ActionButton>
            <ActionButton variant="outline" onClick={handleSecondary}>{errorCopy.secondaryCta}</ActionButton>
          </div>
        }
        tone="teach"
      />
    );
  }

  if (!snapshot) return null;

  return (
    <div className="space-y-6">
      {snapshot.protection_posture === "watch" ? (
        <WatchProtectionBanner onTurnProtectionOn={handleTurnProtectionOn} />
      ) : null}
      {shareOpen && analyticsState.kind === "ready" ? (
        <EvidenceInsightsShareModal
          analytics={analyticsState.data}
          runtime={snapshot}
          onClose={handleShareClose}
        />
      ) : null}
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

      {snapshot.operator_health ? <OperatorHealthCard health={snapshot.operator_health} /> : null}

      <EvidenceInsightsHomePreview
        overviewStats={[
          { label: "Pending", value: formatNumber(queuedCount), tone: queuedCount > 0 ? "blue" : "slate" },
          { label: "Apps", value: formatNumber(watchedAppsCount), tone: watchedAppsCount > 0 ? "green" : "slate" },
          { label: "Recorded", value: formatNumber(snapshot.receipt_count ?? 0), tone: "slate" },
        ]}
        analytics={analyticsState.kind === "ready" ? analyticsState.data : null}
        analyticsLoading={analyticsState.kind === "loading" && analyticsEnabled}
        runtime={snapshot}
        onOpenInsights={props.onOpenInsights}
        onShare={handleShareOpen}
      />

      <HomeCommandActivityCard onOpen={props.onOpenCommands} />

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

          <HomeProtectionModule
            snapshot={snapshot}
            managedInstalls={managedInstalls}
            onOpenFleet={props.onOpenFleet}
            onOpenSupplyChain={props.onOpenSupplyChain}
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
              <ActionButton className="mt-4" variant="secondary" onClick={props.onOpenTodayEvidence}>
                Review today&apos;s activity
              </ActionButton>
            </CollapsibleCard>
          )}
        </section>

        <section className="space-y-6">
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

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <DeviceProofCard device={snapshot.device} proofStatus={snapshot.proof_status} />

        <CloudStatusCard
          snapshot={snapshot}
          showUpsell={cloudUpsellVisible}
          onOpenSettings={props.onOpenSettings}
        />

        <KeyboardHelpCard onOpenHelp={props.onOpenHelp} />
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
