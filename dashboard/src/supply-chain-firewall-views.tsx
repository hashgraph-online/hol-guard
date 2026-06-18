import { useCallback } from "react";
import {
  HiMiniShieldCheck,
  HiMiniArrowTopRightOnSquare,
  HiMiniCheckCircle,
  HiMiniXCircle,
  HiMiniExclamationTriangle,
  HiMiniArrowPath,
} from "react-icons/hi2";
import { ActionButton, Tag } from "./approval-center-primitives";
import type {
  PackageManagerProtection,
  PackageFirewallStatusResponse,
  PackageFirewallActionResponse,
  PackageFirewallEntitlement,
} from "./guard-types";
import { formatRelativeTime } from "./approval-center-utils";
import { parsePackageFirewallActionResult } from "./supply-chain-firewall-action-result";
import type { PackageFirewallNextAction } from "./supply-chain-firewall-next-action";
import { resolvePackageManagerProtectionCopy } from "./runtime-overview";

type UpgradeCtaProps = {
  entitlement: PackageFirewallEntitlement;
};

export function UpgradeCta({ entitlement }: UpgradeCtaProps) {
  const reconnectRequired = entitlement.reason === "guard_cloud_reconnect_required";
  const upgradeUrl = reconnectRequired
    ? "https://hol.org/guard/connect"
    : entitlement.upgrade_url ?? "https://hol.org/guard/pricing";
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-brand-blue/20 bg-gradient-to-br from-brand-blue/[0.04] to-brand-dark/[0.02] px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-start gap-2.5">
        <HiMiniShieldCheck
          className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue"
          aria-hidden="true"
        />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-brand-dark">
            {reconnectRequired ? "Reconnect to restore active protection" : "Upgrade to enable active protection"}
          </p>
          <p className="mt-0.5 text-xs leading-relaxed text-slate-500">
            {entitlement.upgrade_cta ??
              entitlement.reason ??
              "Package firewall actions require a Guard Cloud subscription."}
          </p>
        </div>
      </div>
      <ActionButton href={upgradeUrl} variant="primary">
        {reconnectRequired ? "Reconnect" : "Upgrade"}
        <HiMiniArrowTopRightOnSquare className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
      </ActionButton>
    </div>
  );
}

type ConnectFlowCardProps = {
  compact?: boolean;
  minimal?: boolean;
  connectError: string | null;
  connectStarting: boolean;
  connectFlow: NonNullable<PackageFirewallStatusResponse["connect_flow"]>;
  detail?: string;
  headline?: string;
  localRecoveryHint?: string | null;
  mode: "connect" | "repair";
  onStartConnect: () => void;
  purpose?: "package_firewall" | "insights_share" | "audit";
};

type NavigatorWithUserAgentData = Navigator & {
  userAgentData?: {
    platform?: string;
  };
};

type ConnectStepProps = {
  body: string;
  current: boolean;
  done: boolean;
  emphasis?: "default" | "prominent";
  index: number;
  title: string;
};

function humanizeConnectError(error: string): { detail: string; title: string } {
  const trimmed = error.trim();
  if (/HTTP Error 500|internal server error/i.test(trimmed)) {
    return {
      title: "Cloud sign-in is temporarily unavailable",
      detail: "Guard could not finish the repair flow. Wait a moment, then try connect again.",
    };
  }
  if (/HTTP Error 401|unauthorized/i.test(trimmed)) {
    return {
      title: "Guard Cloud authorization expired",
      detail: "Run connect again to refresh signed access on this machine.",
    };
  }
  if (/failed to fetch|networkerror|load failed/i.test(trimmed)) {
    return {
      title: "Guard lost contact with the local daemon",
      detail: "Confirm the local daemon is still running, then try connect again.",
    };
  }
  return {
    title: "Guard could not start local connect",
    detail: "Guard could not connect right now. Check that the local daemon is running, then try again.",
  };
}

function ConnectStep({
  body,
  current,
  done,
  emphasis = "default",
  index,
  title,
}: ConnectStepProps) {
  const prominent = emphasis === "prominent";
  let toneClass: string;
  if (done) {
    toneClass = "border-brand-green/25 bg-brand-green/[0.05]";
  } else if (current && prominent) {
    toneClass = "border-brand-blue/30 bg-gradient-to-br from-brand-blue/[0.08] to-white shadow-sm";
  } else if (current) {
    toneClass = "border-brand-blue/25 bg-brand-blue/[0.05]";
  } else {
    toneClass = "border-slate-200/90 bg-white/90";
  }
  let badgeClass: string;
  if (done) {
    badgeClass = "bg-brand-green/12 text-brand-green";
  } else if (current) {
    badgeClass = "bg-brand-blue/12 text-brand-blue";
  } else {
    badgeClass = "bg-slate-100 text-slate-500";
  }
  const titleClass = prominent
    ? "text-base font-semibold tracking-[-0.02em] text-brand-dark"
    : "text-sm font-semibold text-brand-dark";
  const bodyClass = prominent
    ? "mt-1.5 text-sm leading-relaxed text-slate-600"
    : "mt-1 text-sm leading-relaxed text-slate-500";
  return (
    <div className={`rounded-2xl border px-4 py-3.5 ${toneClass}`}>
      <div className="flex items-start gap-3">
        <span
          className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-semibold ${badgeClass}`}
        >
          {done ? <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" /> : index}
        </span>
        <div className="min-w-0">
          <p className={titleClass}>{title}</p>
          <p className={bodyClass}>{body}</p>
        </div>
      </div>
    </div>
  );
}

function ConnectProgressRail({
  steps,
}: {
  steps: Array<{ body: string; current: boolean; done: boolean; title: string }>;
}) {
  const activeIndex = steps.findIndex((step) => step.current);
  const focusIndex = activeIndex >= 0 ? activeIndex : steps.findIndex((step) => !step.done);
  return (
    <div className="space-y-2.5" role="list" aria-label="Connect progress">
      {steps.map((step, index) => (
        <div key={`${index}-${step.title}`} role="listitem">
          <ConnectStep
            index={index + 1}
            title={step.title}
            body={step.body}
            current={step.current}
            done={step.done}
            emphasis={index === focusIndex ? "prominent" : "default"}
          />
        </div>
      ))}
    </div>
  );
}

function ConnectErrorBanner({ connectError }: { connectError: string }) {
  const copy = humanizeConnectError(connectError);
  return (
    <div
      className="rounded-2xl border border-brand-attention/30 bg-brand-attention/[0.06] px-4 py-3.5"
      role="alert"
    >
      <div className="flex items-start gap-3">
        <HiMiniExclamationTriangle
          className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention"
          aria-hidden="true"
        />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-brand-dark">{copy.title}</p>
          <p className="mt-1 text-sm leading-relaxed text-slate-600">{copy.detail}</p>
        </div>
      </div>
    </div>
  );
}

function resolveConnectUnlockCopy(purpose: "package_firewall" | "insights_share" | "audit"): {
  body: string;
  title: string;
} {
  if (purpose === "insights_share") {
    return {
      title: "Unlock public sharing",
      body: "Guard verifies Cloud authorization before it publishes a public share link from this machine.",
    };
  }
  if (purpose === "audit") {
    return {
      title: "Run workspace audit",
      body: "After sign-in finishes, Guard scans workspace packages and lists flagged findings in Audit findings.",
    };
  }
  return {
    title: "Unlock firewall actions",
    body: "Guard verifies package-firewall access before it changes package-manager routing.",
  };
}

function resolveConnectSteps(
  connectFlow: NonNullable<PackageFirewallStatusResponse["connect_flow"]>,
  purpose: "package_firewall" | "insights_share" | "audit" = "package_firewall",
): Array<{ body: string; current: boolean; done: boolean; title: string }> {
  const running = connectFlow.state === "running" || connectFlow.state === "starting";
  const failed = connectFlow.state === "failed";
  const browserOpened = connectFlow.browser_opened === true;
  const unlockCopy = resolveConnectUnlockCopy(purpose);
  return [
    {
      title: "Start local connect",
      body: failed
        ? "Guard started the local connect flow, but it needs another attempt."
        : "The local daemon opens a secure HOL Guard Cloud sign-in flow for this machine.",
      done: running || failed,
      current: !running && !failed,
    },
    {
      title: "Approve in browser",
      body: browserOpened
        ? "Finish sign-in in the browser window Guard opened."
        : "If your browser did not open automatically, use the manual sign-in link below.",
      done: false,
      current: running,
    },
    {
      title: unlockCopy.title,
      body: unlockCopy.body,
      done: false,
      current: false,
    },
  ];
}

function resolveMinimalHelperText(input: {
  failed: boolean;
  mode: "connect" | "repair";
  purpose: "package_firewall" | "insights_share" | "audit";
  running: boolean;
}): string {
  if (input.running) {
    if (input.purpose === "audit") {
      return "Finish sign-in in your browser. Guard will run the workspace audit as soon as Cloud access is ready.";
    }
    if (input.purpose === "insights_share") {
      return "Finish sign-in in your browser to publish a public share link.";
    }
    return "Finish sign-in in your browser. Guard will unlock package firewall actions as soon as Cloud access is ready.";
  }
  if (input.failed) {
    return "Connect did not finish. Try again or open sign-in manually.";
  }
  if (input.mode === "repair") {
    if (input.purpose === "audit") {
      return "Reconnect Guard Cloud to restore workspace audit access on this machine.";
    }
    return "Reconnect Guard Cloud to restore public sharing from this machine.";
  }
  if (input.purpose === "audit") {
    return "One quick sign-in unlocks workspace package audits on this machine.";
  }
  return "One quick sign-in unlocks public sharing from this machine.";
}

function resolveConnectPrimaryLabel(input: {
  actionLabel: string;
  failed: boolean;
  running: boolean;
}): string {
  if (input.running) {
    return "Waiting for browser approval";
  }
  if (input.failed) {
    return "Try connect again";
  }
  return input.actionLabel;
}

function isMacClient(): boolean {
  if (typeof navigator === "undefined") {
    return false;
  }
  const navigatorWithUserAgentData = navigator as NavigatorWithUserAgentData;
  const platformHint =
    navigatorWithUserAgentData.userAgentData?.platform ?? navigator.userAgent ?? navigator.platform;
  return platformHint.toLowerCase().includes("mac");
}

export function ConnectFlowCard({
  compact = false,
  minimal = false,
  connectError,
  connectStarting,
  connectFlow,
  detail,
  headline,
  localRecoveryHint,
  mode,
  onStartConnect,
  purpose = "package_firewall",
}: ConnectFlowCardProps) {
  const running = connectFlow.state === "running" || connectFlow.state === "starting";
  const failed = connectFlow.state === "failed";
  const manualHref = connectFlow.authorize_url ?? (failed ? connectFlow.connect_url : null);
  const primaryBusy = connectStarting || running;
  const primaryLabel = resolveConnectPrimaryLabel({
    actionLabel: connectFlow.action_label,
    failed,
    running,
  });
  const steps = resolveConnectSteps(connectFlow, purpose);
  const statusTone = running ? "blue" : mode === "repair" ? "attention" : "blue";
  const statusLabel = running ? "Waiting for approval" : mode === "repair" ? "Repair required" : "Connection required";
  const showManualLink = manualHref !== null;
  const titleCopy = headline ?? connectFlow.title;
  const detailCopy = detail ?? connectFlow.detail;
  if (minimal) {
    const helperText = resolveMinimalHelperText({ failed, mode, purpose, running });
    return (
      <div className="space-y-4 px-5 py-5">
        <div className="flex flex-wrap items-center gap-2">
          <Tag tone={statusTone}>{statusLabel}</Tag>
        </div>
        <p className="text-sm leading-relaxed text-slate-600">{helperText}</p>
        {connectError !== null ? (
          <ConnectErrorBanner connectError={connectError} />
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <ActionButton variant="primary" onClick={onStartConnect} disabled={primaryBusy}>
            {primaryBusy ? (
              <HiMiniArrowPath className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <HiMiniShieldCheck className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            )}
            {primaryLabel}
          </ActionButton>
          {showManualLink ? (
            <ActionButton href={manualHref} variant="outline">
              Open sign-in
              <HiMiniArrowTopRightOnSquare className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
            </ActionButton>
          ) : null}
        </div>
      </div>
    );
  }
  if (compact) {
    return (
      <div className="space-y-5">
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-brand-blue">
              HOL Guard Cloud
            </p>
            <Tag tone={statusTone}>{statusLabel}</Tag>
          </div>
          <div className="space-y-2">
            <p className="text-lg font-semibold tracking-[-0.02em] text-brand-dark">{titleCopy}</p>
            <p className="max-w-2xl text-sm leading-relaxed text-slate-600">{detailCopy}</p>
          </div>
        </div>

        <ConnectProgressRail steps={steps} />

        {connectError !== null ? <ConnectErrorBanner connectError={connectError} /> : null}

        <div className="flex flex-wrap items-center gap-2.5">
          <ActionButton variant="primary" onClick={onStartConnect} disabled={primaryBusy}>
            {primaryBusy ? (
              <HiMiniArrowPath className="mr-1.5 h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <HiMiniShieldCheck className="mr-1.5 h-4 w-4" aria-hidden="true" />
            )}
            {primaryLabel}
          </ActionButton>
          {showManualLink ? (
            <ActionButton href={manualHref} variant="outline">
              Open sign-in page
              <HiMiniArrowTopRightOnSquare className="ml-1.5 h-4 w-4" aria-hidden="true" />
            </ActionButton>
          ) : null}
        </div>

        {localRecoveryHint != null ? (
          <details className="rounded-2xl border border-slate-200 bg-slate-50/70 px-4 py-3">
            <summary className="cursor-pointer list-none text-sm font-medium text-brand-dark">
              What still works locally
            </summary>
            <p className="mt-2 text-sm leading-relaxed text-slate-600">{localRecoveryHint}</p>
          </details>
        ) : null}

        <p className="text-sm leading-relaxed text-slate-500">
          Guard changes routing only after this machine receives signed cloud access.
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-4">
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_260px] lg:items-start">
          <div className="space-y-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-brand-blue">
                HOL Guard Cloud
              </p>
              <Tag tone={statusTone}>{statusLabel}</Tag>
            </div>
            <div className="space-y-1">
              <p className="text-base font-semibold tracking-[-0.02em] text-brand-dark">
                {titleCopy}
              </p>
              <p className="max-w-3xl text-sm leading-relaxed text-slate-500">
                {detailCopy}
              </p>
            </div>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-slate-50/80 px-3.5 py-3">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">
              Security
            </p>
            <p className="mt-1 text-xs leading-relaxed text-slate-600">
              Guard does not change package-manager routing until this machine receives signed cloud access.
            </p>
          </div>
        </div>

        <ConnectProgressRail steps={steps} />

        {localRecoveryHint != null && (
          <details className="rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-3">
            <summary className="cursor-pointer list-none text-sm font-medium text-brand-dark">
              What still works locally
            </summary>
            <p className="mt-2 text-sm leading-relaxed text-slate-600">{localRecoveryHint}</p>
          </details>
        )}

        {connectError !== null ? <ConnectErrorBanner connectError={connectError} /> : null}

        <div className="flex flex-wrap items-center gap-2">
          <ActionButton variant="primary" onClick={onStartConnect} disabled={primaryBusy}>
            {primaryBusy ? (
              <HiMiniArrowPath className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <HiMiniShieldCheck className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            )}
            {primaryLabel}
          </ActionButton>
          {showManualLink && (
            <ActionButton href={manualHref} variant="outline">
              Open sign-in page
              <HiMiniArrowTopRightOnSquare className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
            </ActionButton>
          )}
        </div>
      </div>
    </div>
  );
}

type CliFallbackProps = {
  commands: NonNullable<PackageFirewallStatusResponse["cli_fallback"]>;
};

export function CliFallback({ commands }: CliFallbackProps) {
  const items = Object.entries(commands);
  return (
    <details className="rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-3.5">
      <summary className="cursor-pointer list-none text-sm font-medium text-slate-600">
        Advanced: run connect from the terminal
      </summary>
      <div className="mt-3 space-y-2">
        {items.map(([label, command]) => (
          <div key={label} className="min-w-0">
            <span className="mr-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
              {label}
            </span>
            <code className="break-all font-mono text-sm text-brand-dark">{command}</code>
          </div>
        ))}
      </div>
    </details>
  );
}

type EntitlementNoticeProps = {
  connectError: string | null;
  connectPurpose?: "package_firewall" | "audit";
  connectStarting: boolean;
  data: PackageFirewallStatusResponse;
  detail?: string;
  headline?: string;
  onStartConnect: () => void;
};

export function EntitlementNotice({
  connectError,
  connectPurpose = "package_firewall",
  connectStarting,
  data,
  detail,
  headline,
  onStartConnect,
}: EntitlementNoticeProps) {
  const connectRequired =
    data.entitlement.reason === "guard_cloud_connect_required" ||
    data.entitlement.reason === "guard_cloud_reconnect_required";
  const reconnectLikeState =
    data.entitlement.reason === "guard_cloud_reconnect_required" ||
    (data.entitlement.reason === "guard_cloud_connect_required" &&
      (data.entitlement.tier !== "unknown" || data.package_shims.some((shim) => shim.installed)));
  const connectMode = reconnectLikeState ? "repair" : "connect";
  const localRecoveryHint = data.package_shims.some((shim) => shim.installed)
    ? connectRequired
      ? "Existing shims on this machine can still be fixed or removed locally. Connect is only needed for new installs and cloud-gated verification."
      : null
    : null;
  const compactConnectNotice =
    data.package_shims.some((shim) => shim.installed) ||
    data.protection?.path_status === "restart_required";
  return (
    <div className="space-y-5 px-4 py-5 sm:px-5 sm:py-6">
      {connectRequired && data.connect_flow !== null ? (
        <ConnectFlowCard
          compact={compactConnectNotice}
          connectError={connectError}
          connectStarting={connectStarting}
          connectFlow={data.connect_flow}
          detail={detail}
          headline={headline}
          localRecoveryHint={localRecoveryHint}
          mode={connectMode}
          onStartConnect={onStartConnect}
          purpose={connectPurpose}
        />
      ) : (
        <UpgradeCta entitlement={data.entitlement} />
      )}
      {data.cli_fallback !== null && <CliFallback commands={data.cli_fallback} />}
    </div>
  );
}

function activationHeadline(protection: PackageManagerProtection | null): string {
  if (protection === null) return "Activation status unavailable";
  if (protection.path_status === "in_path") return "Protection live now";
  if (protection.path_status === "restart_required") return "Restart shell or apps to finish activation";
  return "Fix PATH to finish activation";
}

type ActivationSummaryProps = {
  activationAssistError: string | null;
  lastAuditProofAt?: string | null;
  openingShell: boolean;
  onOpenShell: () => void;
  onRefreshStatus: () => void;
  protection: PackageManagerProtection | null;
};

export function ActivationSummary({
  activationAssistError,
  lastAuditProofAt = null,
  openingShell,
  onOpenShell,
  onRefreshStatus,
  protection,
}: ActivationSummaryProps) {
  if (protection === null) {
    return null;
  }
  const copy = resolvePackageManagerProtectionCopy(protection);
  const Icon =
    protection.path_status === "in_path"
      ? HiMiniCheckCircle
      : protection.path_status === "restart_required"
      ? HiMiniArrowPath
      : HiMiniExclamationTriangle;
  const toneClass =
    protection.path_status === "in_path"
      ? "border-brand-green/20 bg-brand-green/[0.04]"
      : protection.path_status === "restart_required"
      ? "border-brand-blue/20 bg-brand-blue/[0.04]"
      : "border-brand-attention/20 bg-brand-attention/[0.04]";
  const iconClass =
    protection.path_status === "in_path"
      ? "text-brand-green"
      : protection.path_status === "restart_required"
      ? "text-brand-blue"
      : "text-brand-attention";
  const canOpenShell =
    protection.path_status === "restart_required" &&
    protection.shell_profile_configured &&
    isMacClient();
  return (
    <div className={`rounded-xl border px-4 py-3 ${toneClass}`}>
      <div className="flex items-start gap-2.5">
        <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${iconClass}`} aria-hidden="true" />
        <div className="min-w-0">
          <p className="text-sm font-medium text-brand-dark">{activationHeadline(protection)}</p>
          <p className="mt-0.5 text-xs text-slate-600">{copy.pathDetail}</p>
          {lastAuditProofAt !== null && (
            <p className="mt-1 text-xs text-slate-500">
              Last audit proof {formatRelativeTime(lastAuditProofAt)}
            </p>
          )}
          {protection.path_status === "restart_required" && (
            <div className="mt-3 flex flex-wrap items-center gap-2">
              {canOpenShell && (
                <ActionButton variant="primary" onClick={onOpenShell} disabled={openingShell}>
                  {openingShell ? "Opening shell…" : "Open new shell"}
                </ActionButton>
              )}
              <ActionButton variant="outline" onClick={onRefreshStatus} disabled={openingShell}>
                Refresh after restart
              </ActionButton>
            </div>
          )}
          {activationAssistError !== null && (
            <p className="mt-2 text-xs text-brand-attention">{activationAssistError}</p>
          )}
        </div>
      </div>
    </div>
  );
}

type ReceiptProofCardProps = {
  receipt: PackageFirewallActionResponse["receipt"];
};

export function ReceiptProofCard({ receipt }: ReceiptProofCardProps) {
  if (receipt === null) {
    return null;
  }
  return (
    <div className="mt-2 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2.5">
      <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
        Proof receipt
      </p>
      <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
        <div>
          <span className="text-[10px] font-medium uppercase tracking-wide text-slate-400">
            ID
          </span>
          <p className="break-all font-mono text-xs text-brand-dark">{receipt.id}</p>
        </div>
        <div>
          <span className="text-[10px] font-medium uppercase tracking-wide text-slate-400">
            Operation
          </span>
          <p className="font-mono text-xs text-brand-dark">{receipt.operation}</p>
        </div>
      </div>
    </div>
  );
}

type DismissButtonProps = {
  onDismiss: () => void;
};

export function DismissButton({ onDismiss }: DismissButtonProps) {
  return (
    <button
      type="button"
      onClick={onDismiss}
      aria-label="Dismiss result"
      className="shrink-0 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
    >
      <HiMiniXCircle className="h-4 w-4" aria-hidden="true" />
    </button>
  );
}

export type CompletedOp = {
  op: string;
  manager: string | null;
  response: PackageFirewallActionResponse;
};

type NextActionHeroProps = {
  action: PackageFirewallNextAction;
  anyPending: boolean;
  onRunAction: (op: NonNullable<PackageFirewallNextAction["op"]>, manager: string | null) => void;
};

export function NextActionHero({ action, anyPending, onRunAction }: NextActionHeroProps) {
  const handleClick = useCallback(() => {
    if (action.op === null) {
      return;
    }
    onRunAction(action.op, action.manager);
  }, [action.manager, action.op, onRunAction]);

  return (
    <div className="rounded-2xl border border-brand-blue/15 bg-gradient-to-br from-brand-blue/[0.05] to-white px-4 py-4 sm:px-5 sm:py-5">
      <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-brand-blue">Next step</p>
      <p className="mt-2 text-lg font-semibold text-brand-dark">{action.label}</p>
      <p className="mt-1 max-w-2xl text-sm leading-relaxed text-slate-600">{action.detail}</p>
      {action.op !== null && (
        <div className="mt-4">
          <ActionButton variant="primary" onClick={handleClick} disabled={anyPending}>
            {action.label}
          </ActionButton>
        </div>
      )}
    </div>
  );
}

type ActionResultPanelProps = {
  completed: CompletedOp;
  onDismiss: () => void;
};

export function ActionResultPanel({ completed, onDismiss }: ActionResultPanelProps) {
  const { response } = completed;
  const isOk = ["completed", "ok", "success", "succeeded"].includes(response.status);
  const detail = response.result_detail;
  const parsed = isOk ? parsePackageFirewallActionResult(completed.op, response) : null;
  let resultMessage: string;
  if (parsed?.summary != null) {
    resultMessage = parsed.summary;
  } else if (detail["activation_state"] === "restart_required") {
    resultMessage =
      "Guard installed the shim and updated your shell profile. Open a new shell or restart AI apps to route package-manager commands through Guard.";
  } else if (detail["activation_state"] === "in_path") {
    resultMessage = "Guard installed the shim and protection is live in this session.";
  } else {
    resultMessage = response.result;
  }
  const resultLines = parsed?.lines ?? [];
  return (
    <div
      className={`rounded-xl border px-4 py-3 ${
        isOk
          ? "border-brand-green/20 bg-brand-green/[0.04]"
          : "border-brand-attention/20 bg-brand-attention/[0.04]"
      }`}
      role="status"
      aria-live="polite"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-2">
          {isOk ? (
            <HiMiniCheckCircle
              className="mt-0.5 h-4 w-4 shrink-0 text-brand-green"
              aria-hidden="true"
            />
          ) : (
            <HiMiniExclamationTriangle
              className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention"
              aria-hidden="true"
            />
          )}
          <div className="min-w-0">
            <p className="text-sm font-medium capitalize text-brand-dark">
              {completed.op}
              {completed.manager !== null ? ` — ${completed.manager}` : ""}
            </p>
            <p className="mt-0.5 text-xs text-slate-600">{resultMessage}</p>
            {resultLines.length > 0 && (
              <ul className="mt-2 space-y-1 text-xs text-slate-600">
                {resultLines.map((line, index) => (
                  <li key={index}>{line}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
        <DismissButton onDismiss={onDismiss} />
      </div>
      <ReceiptProofCard receipt={response.receipt} />
    </div>
  );
}
