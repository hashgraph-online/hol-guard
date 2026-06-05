import {
  HiMiniShieldCheck,
  HiMiniArrowTopRightOnSquare,
  HiMiniCheckCircle,
  HiMiniXCircle,
  HiMiniExclamationTriangle,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import type {
  PackageFirewallStatusResponse,
  PackageFirewallActionResponse,
  PackageFirewallEntitlement,
} from "./guard-types";

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

type CliFallbackProps = {
  commands: NonNullable<PackageFirewallStatusResponse["cli_fallback"]>;
};

export function CliFallback({ commands }: CliFallbackProps) {
  const items = Object.entries(commands);
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
      <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
        CLI fallback
      </p>
      <div className="space-y-1.5">
        {items.map(([label, command]) => (
          <div key={label} className="min-w-0">
            <span className="mr-2 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
              {label}
            </span>
            <code className="break-all font-mono text-xs text-brand-dark">{command}</code>
          </div>
        ))}
      </div>
    </div>
  );
}

type FreeUserViewProps = {
  data: PackageFirewallStatusResponse;
};

export function FreeUserView({ data }: FreeUserViewProps) {
  return (
    <div className="space-y-4 px-4 py-4">
      <UpgradeCta entitlement={data.entitlement} />
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.15em] text-slate-400">
          Would be protected
        </p>
        {data.supported_managers.length === 0 ? (
          <p className="text-xs text-slate-500">No supported managers detected on this machine.</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {data.supported_managers.map((mgr) => (
              <span
                key={mgr}
                className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 font-mono text-xs text-slate-600"
              >
                {mgr}
              </span>
            ))}
          </div>
        )}
      </div>
      {data.cli_fallback !== null && <CliFallback commands={data.cli_fallback} />}
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
            <p className="mt-0.5 text-xs text-slate-600">{response.result}</p>
          </div>
        </div>
        <DismissButton onDismiss={onDismiss} />
      </div>
      <ReceiptProofCard receipt={response.receipt} />
    </div>
  );
}
