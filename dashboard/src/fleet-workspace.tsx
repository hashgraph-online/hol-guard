import { useCallback, useState } from "react";
import {
  HiMiniCheckCircle,
  HiMiniExclamationCircle,
  HiMiniWrenchScrewdriver,
  HiMiniXCircle,
  HiMiniChevronRight,
  HiMiniClipboard,
  HiMiniClipboardDocumentCheck,
  HiMiniEye,
} from "react-icons/hi2";
import {
  ActionButton,
  EmptyState,
  SectionLabel,
  Tag,
  GuardHero,
  ProofStrip,
} from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import {
  SUPPORTED_APPS_BRIEF,
  resolveAppInstallStatus,
  APP_STATUS_LABELS,
} from "./apps/app-catalog";
import { isConnectableAppHarness } from "./apps/harness-setup-target";
import { protectionHealthFor } from "./protection-health";
import type { GuardInventoryItem, GuardPolicyDecision, GuardProtectionState, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

type FleetWorkspaceProps = {
  runtime: GuardRuntimeSnapshot;
  policies: GuardPolicyDecision[];
  inventory:
    | { kind: "idle" }
    | { kind: "loading" }
    | { kind: "error"; message: string }
    | { kind: "ready"; items: GuardInventoryItem[] };
  onConnectHarness?: (harness: string) => void;
  onTestHarness?: (harness: string) => void;
  onRepairHarness?: (harness: string) => void;
  onOpenAppDetail?: (harness: string) => void;
};

type FleetHeroUrls = {
  fleet_url: string;
  dashboard_url: string;
  connect_url: string;
};

export type FleetHeroCopy = {
  status: "clear" | "setup_gap" | "partial" | "degraded";
  headline: string;
  subheadline: string;
  primaryCtaLabel: string;
  primaryCtaHref: string;
  secondaryCtaLabel: string;
  secondaryCtaHref: string;
};

const SUPPORTED_APPS_COPY = SUPPORTED_APPS_BRIEF;

export function resolveFleetHeroCopy(
  cloudState: "local_only" | "paired_waiting" | "paired_active",
  activeInstallCount: number,
  protectionState: GuardProtectionState,
  urls: FleetHeroUrls
): FleetHeroCopy {
  const hasApps = activeInstallCount > 0;
  if (hasApps && protectionState !== "protected") {
    return {
      status: protectionState,
      headline: protectionState === "partial" ? "Apps are partially protected" : "App protection is degraded",
      subheadline:
        protectionState === "partial"
          ? "Core protection passes, but complete decision-stream evidence is not available."
          : "One or more required protection checks failed or remain unproven.",
      primaryCtaLabel: "Review app health",
      primaryCtaHref: urls.dashboard_url,
      secondaryCtaLabel: cloudState === "local_only" ? "Connect this machine" : "Open Cloud Devices",
      secondaryCtaHref: cloudState === "local_only" ? urls.connect_url : urls.fleet_url,
    };
  }
  if (cloudState === "local_only") {
    return {
      status: hasApps ? "clear" : "setup_gap",
      headline: hasApps ? "Your apps are covered" : "Connect an app to start",
      subheadline: hasApps
        ? "Guard is protecting your local AI apps."
        : SUPPORTED_APPS_COPY,
      primaryCtaLabel: "Connect this machine",
      primaryCtaHref: urls.connect_url,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url,
    };
  }
  if (cloudState === "paired_waiting") {
    return {
      status: hasApps ? "clear" : "setup_gap",
      headline: hasApps ? "Apps covered, first proof pending" : "Connect an app to start",
      subheadline: hasApps
        ? "Guard is running. First cloud proof is on its way."
        : SUPPORTED_APPS_COPY,
      primaryCtaLabel: "Open Cloud Devices",
      primaryCtaHref: urls.fleet_url,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url,
    };
  }
  return {
    status: hasApps ? "clear" : "setup_gap",
    headline: hasApps ? "Your apps are covered" : "Connect an app to start",
    subheadline: hasApps
      ? "Confirm that Guard is running and protecting your local AI apps."
      : SUPPORTED_APPS_COPY,
    primaryCtaLabel: "Open Cloud Devices",
    primaryCtaHref: urls.fleet_url,
    secondaryCtaLabel: "Open Home",
    secondaryCtaHref: urls.dashboard_url,
  };
}

function collectHarnesses(snapshot: GuardRuntimeSnapshot): string[] {
  const harnesses = new Set<string>();
  for (const item of snapshot.items) {
    if (isConnectableAppHarness(item.harness)) harnesses.add(item.harness);
  }
  for (const receipt of snapshot.latest_receipts) {
    if (isConnectableAppHarness(receipt.harness)) harnesses.add(receipt.harness);
  }
  return Array.from(harnesses).sort((a, b) => a.localeCompare(b));
}

function renderReceiptContext(receipt: GuardReceipt): string {
  return `${harnessDisplayName(receipt.harness)} · ${receipt.policy_decision.replace(/-/g, " ")}`;
}

type AppStatus = "protected" | "partial" | "found_unprotected" | "needs_repair" | "not_found";

function resolveAppStatus(
  install: { active?: boolean } | undefined,
  protectionState: GuardProtectionState,
  hasInventory: boolean,
  hasReceipts: boolean
): AppStatus {
  if (install !== undefined) {
    if (install.active && protectionState === "protected") return "protected";
    if (install.active && protectionState === "partial") return "partial";
    return "needs_repair";
  }
  if (!hasInventory && !hasReceipts) return "not_found";
  return "found_unprotected";
}

function toInstallStatus(status: AppStatus): ReturnType<typeof resolveAppInstallStatus> {
  if (status === "protected") return "active";
  if (status === "partial") return "partial";
  if (status === "needs_repair") return "partial";
  if (status === "found_unprotected") return "observed";
  return "not_installed";
}

function StatusIcon({ status }: { status: AppStatus }) {
  if (status === "protected") return <HiMiniCheckCircle className="h-4 w-4 text-emerald-500" aria-hidden="true" />;
  if (status === "found_unprotected") return <HiMiniEye className="h-4 w-4 text-slate-400" aria-hidden="true" />;
  if (status === "needs_repair") return <HiMiniWrenchScrewdriver className="h-4 w-4 text-brand-purple" aria-hidden="true" />;
  if (status === "not_found") return <HiMiniXCircle className="h-4 w-4 text-slate-300" aria-hidden="true" />;
  return <HiMiniExclamationCircle className="h-4 w-4 text-brand-attention" aria-hidden="true" />;
}

function StatusBadge({ status }: { status: AppStatus }) {
  if (status === "partial") return <span className="text-xs font-medium text-brand-blue">Partially protected</span>;
  if (status === "needs_repair") return <span className="text-xs font-medium text-brand-attention">Degraded</span>;
  const installStatus = toInstallStatus(status);
  const label = APP_STATUS_LABELS[installStatus];
  if (installStatus === "active") return <span className="text-xs font-medium text-emerald-600">{label}</span>;
  if (installStatus === "partial") return <span className="text-xs font-medium text-brand-purple">{label}</span>;
  if (installStatus === "observed") return <span className="text-xs font-medium text-slate-500">{label}</span>;
  return <span className="text-xs text-slate-400">{label}</span>;
}

type AppRowProps = {
  harness: string;
  status: AppStatus;
  inventoryCount: number;
  policyCount: number;
  onOpenAppDetail?: (harness: string) => void;
};

function AppRow({ harness, status, inventoryCount, policyCount, onOpenAppDetail }: AppRowProps) {
  const isClickable = onOpenAppDetail !== undefined;

  const handleClick = useCallback(() => {
    onOpenAppDetail?.(harness);
  }, [onOpenAppDetail, harness]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        onOpenAppDetail?.(harness);
      }
    },
    [onOpenAppDetail, harness]
  );

  return (
    <div
      className={`flex items-center justify-between gap-3 py-3 transition-colors ${
        isClickable ? "cursor-pointer hover:bg-slate-50/60" : ""
      }`}
      onClick={isClickable ? handleClick : undefined}
      role={isClickable ? "button" : undefined}
      tabIndex={isClickable ? 0 : undefined}
      onKeyDown={isClickable ? handleKeyDown : undefined}
    >
      <div className="flex min-w-0 items-center gap-3">
        <StatusIcon status={status} />
        <div className="min-w-0">
          <p className="text-sm font-medium text-brand-dark">{harnessDisplayName(harness)}</p>
          <p className="text-xs text-slate-400">
            {inventoryCount} actions · {policyCount} decisions
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <StatusBadge status={status} />
        {isClickable && <HiMiniChevronRight className="h-4 w-4 text-slate-300" aria-hidden="true" />}
      </div>
    </div>
  );
}

export function FleetWorkspace(props: FleetWorkspaceProps) {
  const harnesses = collectHarnesses(props.runtime);
  const managedInstalls = (props.runtime.managed_installs ?? []).filter((i) => isConnectableAppHarness(i.harness));
  const activeInstalls = managedInstalls.filter((i) => i.active);
  const inventory = props.inventory.kind === "ready" ? props.inventory.items.filter((i) => isConnectableAppHarness(i.harness)) : [];
  const visibleHarnesses = Array.from(
    new Set([
      ...managedInstalls.map((i) => i.harness),
      ...harnesses,
      ...inventory.map((i) => i.harness),
      ...props.policies.map((p) => p.harness),
    ].filter(isConnectableAppHarness))
  ).sort((a, b) => a.localeCompare(b));
  const runtimeState = props.runtime.runtime_state;
  const protectionHealth = protectionHealthFor(props.runtime);
  const receiptHarnesses = new Set(props.runtime.latest_receipts.map((r) => r.harness).filter(isConnectableAppHarness));

  const heroCopy = resolveFleetHeroCopy(
    props.runtime.cloud_state,
    activeInstalls.length,
    protectionHealth.state,
    {
      fleet_url: props.runtime.fleet_url,
      dashboard_url: props.runtime.dashboard_url,
      connect_url: props.runtime.connect_url,
    }
  );

  return (
    <div className="space-y-8">
      <GuardHero
        status={heroCopy.status}
        headline={heroCopy.headline}
        subheadline={heroCopy.subheadline}
        cta={<ActionButton href={heroCopy.primaryCtaHref}>{heroCopy.primaryCtaLabel}</ActionButton>}
        secondaryCta={
          <ActionButton href={heroCopy.secondaryCtaHref} variant="outline">
            {heroCopy.secondaryCtaLabel}
          </ActionButton>
        }
      />

      <ProofStrip
        items={[
          { label: "Needs review", value: `${props.runtime.pending_count}`, tone: props.runtime.pending_count > 0 ? "blue" : "slate" },
          { label: "History", value: `${props.runtime.receipt_count}`, tone: "purple" },
          { label: "Watched apps", value: `${activeInstalls.length > 0 ? activeInstalls.length : visibleHarnesses.length}`, tone: protectionHealth.state === "protected" ? "green" : "slate" },
          { label: "Runtime", value: runtimeState ? "active" : "offline", tone: runtimeState ? "green" : "slate" },
        ]}
      />

      <div className="grid gap-8 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,0.8fr)]">
        <section>
          <div className="mb-4">
            <SectionLabel>App coverage</SectionLabel>
            <p className="mt-1 text-sm text-slate-500">Which apps Guard is watching on this machine.</p>
          </div>

          {visibleHarnesses.length > 0 ? (
            <div className="divide-y divide-slate-100 border-t border-slate-100">
              {visibleHarnesses.map((harness) => {
                const install = managedInstalls.find((i) => i.harness === harness);
                const harnessInventory = inventory.filter((i) => i.harness === harness && i.present);
                const harnessPolicies = props.policies.filter((p) => p.harness === harness);
                const hasReceipts = receiptHarnesses.has(harness);
                const appProtection = protectionHealthFor(props.runtime, harness);
                const status = resolveAppStatus(install, appProtection.state, harnessInventory.length > 0, hasReceipts);
                return (
                  <AppRow
                    key={harness}
                    harness={harness}
                    status={status}
                    inventoryCount={harnessInventory.length}
                    policyCount={harnessPolicies.length}
                    onOpenAppDetail={props.onOpenAppDetail}
                  />
                );
              })}
            </div>
          ) : (
            <EmptyState
              title="No watched apps yet"
              body="Run HOL Guard once with Codex, Claude Code, OpenCode, Copilot, Cursor, Gemini, Hermes, or another supported app and this machine will show coverage here."
              tone="teach"
            />
          )}

          {props.inventory.kind === "error" ? (
            <p className="mt-3 text-xs text-slate-500">{props.inventory.message}</p>
          ) : null}
        </section>

        <section>
          <div className="mb-4">
            <SectionLabel>Recent choices</SectionLabel>
            <p className="mt-1 text-sm text-slate-500">What Guard decided recently.</p>
          </div>
          {props.runtime.latest_receipts.length > 0 ? (
            <div className="space-y-0 divide-y divide-slate-100 border-t border-slate-100">
              {props.runtime.latest_receipts.slice(0, 6).map((receipt) => (
                <div key={receipt.receipt_id} className="py-2.5">
                  <p className="truncate text-sm font-medium text-brand-dark">
                    {receipt.artifact_name ?? receipt.artifact_id}
                  </p>
                  <p className="text-xs text-slate-400">{renderReceiptContext(receipt)}</p>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No choices yet"
              body="Allow or block an action once and HOL Guard will start building local history for this machine."
            />
          )}
        </section>
      </div>

      {activeInstalls.length === 0 && (
        <SetupGuide
          hasReceipts={props.runtime.latest_receipts.length > 0}
          hasInventory={inventory.length > 0}
        />
      )}
    </div>
  );
}

function SetupGuide(props: { hasReceipts: boolean; hasInventory: boolean }) {
  const steps = [
    {
      id: "install",
      label: "Install Guard hook",
      description: "Run `hol-guard install` in your project to set up the approval hook.",
      command: "hol-guard install",
      done: props.hasInventory,
    },
    {
      id: "run",
      label: "Run your AI app",
      description: "Start Codex, Claude Code, or another supported app. Guard will intercept risky actions.",
      done: props.hasReceipts,
    },
    {
      id: "verify",
      label: "Verify in dashboard",
      description: "Check this dashboard to review app health and see receipts appear in History.",
      done: props.hasReceipts && props.hasInventory,
    },
  ];

  const completedCount = steps.filter((s) => s.done).length;

  return (
    <div className="rounded-2xl border border-brand-blue/15 bg-brand-blue/[0.03] p-5 sm:p-6">
      <div className="flex items-center justify-between">
        <div>
          <SectionLabel>Setup guide</SectionLabel>
          <p className="mt-1 text-sm text-slate-500">
            {completedCount === steps.length
              ? "Guard is set up and running!"
              : `${completedCount} of ${steps.length} steps completed`}
          </p>
        </div>
        {completedCount === steps.length && (
          <HiMiniCheckCircle className="h-6 w-6 text-brand-green" aria-hidden="true" />
        )}
      </div>
      <div className="mt-4 space-y-3">
        {steps.map((step, index) => (
          <SetupStep
            key={step.id}
            stepNumber={index + 1}
            label={step.label}
            description={step.description}
            command={step.command}
            done={step.done}
          />
        ))}
      </div>
    </div>
  );
}

function SetupStep(props: {
  stepNumber: number;
  label: string;
  description: string;
  command?: string;
  done: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    if (!props.command) return;
    void navigator.clipboard.writeText(props.command).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [props.command]);

  return (
    <div className={`flex items-start gap-3 rounded-xl border p-3 ${props.done ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-white"}`}>
      <span className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${props.done ? "bg-brand-green text-white" : "bg-slate-100 text-slate-500"}`}>
        {props.done ? <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" /> : props.stepNumber}
      </span>
      <div className="min-w-0 flex-1">
        <p className={`text-sm font-medium ${props.done ? "text-brand-green-text" : "text-brand-dark"}`}>
          {props.label}
        </p>
        <p className="text-xs text-slate-500">{props.description}</p>
        {props.command && (
          <button
            onClick={handleCopy}
            className="mt-1.5 inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-slate-50 px-2 py-1 text-xs font-mono text-brand-dark transition-colors hover:bg-slate-100"
          >
            {copied ? (
              <HiMiniClipboardDocumentCheck className="h-3 w-3 text-brand-green" aria-hidden="true" />
            ) : (
              <HiMiniClipboard className="h-3 w-3" aria-hidden="true" />
            )}
            {props.command}
          </button>
        )}
      </div>
    </div>
  );
}
