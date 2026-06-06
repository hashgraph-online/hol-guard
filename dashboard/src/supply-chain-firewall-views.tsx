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
  connectError: string | null;
  connectStarting: boolean;
  connectFlow: NonNullable<PackageFirewallStatusResponse["connect_flow"]>;
  localRecoveryHint?: string | null;
  mode: "connect" | "repair";
  onStartConnect: () => void;
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
  index: number;
  title: string;
};

function ConnectStep({ body, current, done, index, title }: ConnectStepProps) {
  const toneClass = done
    ? "border-brand-green/20 bg-brand-green/[0.04]"
    : current
    ? "border-brand-blue/20 bg-brand-blue/[0.04]"
    : "border-slate-200 bg-white/85";
  const badgeClass = done
    ? "bg-brand-green/10 text-brand-green"
    : current
    ? "bg-brand-blue/10 text-brand-blue"
    : "bg-slate-100 text-slate-500";
  return (
    <div className={`rounded-[18px] border px-3.5 py-3 ${toneClass}`}>
      <div className="flex items-start gap-3">
        <span className={`inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold ${badgeClass}`}>
          {done ? <HiMiniCheckCircle className="h-3.5 w-3.5" aria-hidden="true" /> : index}
        </span>
        <div className="min-w-0">
          <p className="text-sm font-semibold text-brand-dark">{title}</p>
          <p className="mt-1 text-xs leading-relaxed text-slate-500">{body}</p>
        </div>
      </div>
    </div>
  );
}

function resolveConnectSteps(
  connectFlow: NonNullable<PackageFirewallStatusResponse["connect_flow"]>,
): Array<{ body: string; current: boolean; done: boolean; title: string }> {
  const running = connectFlow.state === "running";
  const failed = connectFlow.state === "failed";
  const browserOpened = connectFlow.browser_opened === true;
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
      title: "Unlock firewall actions",
      body: "Guard verifies package-firewall access before it changes package-manager routing.",
      done: false,
      current: false,
    },
  ];
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
  connectError,
  connectStarting,
  connectFlow,
  localRecoveryHint,
  mode,
  onStartConnect,
}: ConnectFlowCardProps) {
  const manualHref = connectFlow.authorize_url ?? connectFlow.connect_url;
  const running = connectFlow.state === "running";
  const failed = connectFlow.state === "failed";
  const primaryBusy = connectStarting || running;
  const primaryLabel = running
    ? "Waiting for browser approval"
    : failed
    ? "Try connect again"
    : connectFlow.action_label;
  const steps = resolveConnectSteps(connectFlow);
  const statusTone = running ? "blue" : mode === "repair" ? "attention" : "blue";
  const statusLabel = running ? "Waiting for approval" : mode === "repair" ? "Repair required" : "Connection required";
  const showManualLink = connectFlow.authorize_url !== null || running || failed;
  if (compact) {
    return (
      <div className="space-y-3">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-brand-blue">
              HOL Guard Cloud
            </p>
            <Tag tone={statusTone}>{statusLabel}</Tag>
          </div>
          <div className="space-y-1">
            <p className="text-base font-semibold tracking-[-0.02em] text-brand-dark">
              {connectFlow.title}
            </p>
            <p className="max-w-3xl text-sm leading-relaxed text-slate-500">
              {connectFlow.detail}
            </p>
          </div>
        </div>

        <div className="grid gap-2 text-xs leading-relaxed text-slate-500 md:grid-cols-3">
          {steps.map((step, index) => (
            <div key={step.title} className="min-w-0">
              <p className="font-semibold text-brand-dark">
                {index + 1}. {step.title}
              </p>
              <p className="mt-0.5">{step.body}</p>
            </div>
          ))}
        </div>

        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs leading-relaxed text-slate-500">
          {localRecoveryHint !== null && <span>{localRecoveryHint}</span>}
          <span>Guard changes routing only after this machine receives signed cloud access.</span>
        </div>

        {connectError !== null && (
          <p className="text-xs leading-relaxed text-brand-attention">{connectError}</p>
        )}

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
                {connectFlow.title}
              </p>
              <p className="max-w-3xl text-sm leading-relaxed text-slate-500">
                {connectFlow.detail}
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

        <div className="grid gap-2.5 md:grid-cols-3">
          {steps.map((step, index) => (
            <ConnectStep
              key={step.title}
              index={index + 1}
              title={step.title}
              body={step.body}
              current={step.current}
              done={step.done}
            />
          ))}
        </div>

        {localRecoveryHint != null && (
          <div className="rounded-2xl border border-slate-200 bg-slate-50/80 px-3.5 py-3">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">
              Available now
            </p>
            <p className="mt-1 text-xs leading-relaxed text-slate-600">{localRecoveryHint}</p>
          </div>
        )}

        {connectError !== null && (
          <div className="rounded-[18px] border border-brand-attention/25 bg-brand-attention/[0.05] px-3.5 py-3">
            <p className="text-sm font-medium text-brand-dark">Guard could not start local connect</p>
            <p className="mt-1 text-xs leading-relaxed text-slate-600">{connectError}</p>
          </div>
        )}

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
    <details className="rounded-xl border border-slate-200 bg-slate-50/80 px-4 py-3">
      <summary className="cursor-pointer list-none text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
        CLI fallback
      </summary>
      <div className="mt-3 space-y-1.5">
        {items.map(([label, command]) => (
          <div key={label} className="min-w-0">
            <span className="mr-2 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
              {label}
            </span>
            <code className="break-all font-mono text-xs text-brand-dark">{command}</code>
          </div>
        ))}
      </div>
    </details>
  );
}

type EntitlementNoticeProps = {
  connectError: string | null;
  connectStarting: boolean;
  data: PackageFirewallStatusResponse;
  onStartConnect: () => void;
};

export function EntitlementNotice({
  connectError,
  connectStarting,
  data,
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
    <div className="space-y-4 px-4 py-4">
      {connectRequired && data.connect_flow !== null ? (
        <ConnectFlowCard
          compact={compactConnectNotice}
          connectError={connectError}
          connectStarting={connectStarting}
          connectFlow={data.connect_flow}
          localRecoveryHint={localRecoveryHint}
          mode={connectMode}
          onStartConnect={onStartConnect}
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
  openingShell: boolean;
  onOpenShell: () => void;
  onRefreshStatus: () => void;
  protection: PackageManagerProtection | null;
};

export function ActivationSummary({
  activationAssistError,
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

type ActionResultPanelProps = {
  completed: CompletedOp;
  onDismiss: () => void;
};

export function ActionResultPanel({ completed, onDismiss }: ActionResultPanelProps) {
  const { response } = completed;
  const isOk = ["completed", "ok", "success", "succeeded"].includes(response.status);
  const detail = response.result_detail;
  const resultMessage =
    detail["activation_state"] === "restart_required"
      ? "Guard installed the shim and updated your shell profile. Open a new shell or restart AI apps to route package-manager commands through Guard."
      : detail["activation_state"] === "in_path"
      ? "Guard installed the shim and protection is live in this session."
      : response.result;
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
          </div>
        </div>
        <DismissButton onDismiss={onDismiss} />
      </div>
      <ReceiptProofCard receipt={response.receipt} />
    </div>
  );
}
