import {
  HiMiniArrowPath,
  HiMiniBeaker,
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
  HiMiniShieldCheck,
  HiMiniTrash,
  HiMiniWrenchScrewdriver,
  HiMiniXMark,
} from "react-icons/hi2";
import { ActionButton, IconActionButton, Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { PackageFirewallStatusResponse, PackageShimEntry } from "./guard-types";
import { resolveShimStatus } from "./supply-chain-firewall-manager-row";

type ManagerDrawerActions = {
  install?: (manager: string) => void;
  repair?: (manager: string) => void;
  test?: (manager: string) => void;
  removeRequest?: (manager: string) => void;
};

type SupplyChainManagerDrawerProps = {
  manager: string;
  shim: PackageShimEntry | undefined;
  actions: PackageFirewallStatusResponse["actions"];
  anyPending: boolean;
  isMine: boolean;
  actionHandlers: ManagerDrawerActions;
  onClose: () => void;
};

function DetailRow({ label, value }: { label: string; value: string | null | undefined }) {
  if (value === null || value === undefined || value.trim().length === 0) {
    return null;
  }
  return (
    <div className="grid gap-1 sm:grid-cols-[8rem_minmax(0,1fr)] sm:items-start">
      <dt className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">
        {label}
      </dt>
      <dd className="break-all font-mono text-xs text-brand-dark">{value}</dd>
    </div>
  );
}

function actionIsAvailable(state: string | undefined): boolean {
  return state === "available";
}

export function SupplyChainManagerDrawer({
  manager,
  shim,
  actions,
  anyPending,
  isMine,
  actionHandlers,
  onClose,
}: SupplyChainManagerDrawerProps) {
  const status = resolveShimStatus(shim);
  const installAvailable = actionIsAvailable(actions.install);
  const repairAvailable = actionIsAvailable(actions.repair);
  const testAvailable = actionIsAvailable(actions.test);
  const removeAvailable = actionIsAvailable(actions.remove);

  const showInstall = (!shim || !shim.installed) && installAvailable;
  const showRepair =
    shim?.installed &&
    (shim.activation_state === "repair_required" || shim.path_broken) &&
    repairAvailable;
  const showTest = shim?.installed && shim.activation_state === "protected" && testAvailable;
  const showRemove = shim?.installed && removeAvailable;

  return (
    <div
      role="dialog"
      aria-label={`${manager} manager details`}
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-end sm:items-stretch sm:justify-end"
      data-testid="supply-chain-manager-drawer"
    >
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <div className="relative flex h-[88vh] w-full max-w-md flex-col overflow-hidden rounded-t-2xl bg-white shadow-2xl sm:h-full sm:rounded-none">
        <div className="flex items-start justify-between gap-3 border-b border-slate-100 px-5 py-4">
          <div className="min-w-0">
            <p className="font-mono text-lg font-semibold text-brand-dark">{manager}</p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <Tag tone={status.tone}>{status.label}</Tag>
              {shim?.detected ? <Tag tone="green">Detected</Tag> : null}
              {shim?.tested ? <Tag tone="green">Tested</Tag> : null}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close manager details drawer"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 hover:text-slate-600"
          >
            <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <div className="flex-1 space-y-5 overflow-y-auto px-5 py-4">
          <section aria-label="Manager coverage">
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">
              Coverage
            </p>
            <dl className="space-y-3">
              <DetailRow label="Activation" value={shim?.activation_state ?? "uninstalled"} />
              <DetailRow label="Integrity" value={shim?.integrity} />
              <DetailRow label="PATH order" value={shim?.path_summary} />
              <DetailRow label="Shim path" value={shim?.shim_path} />
              <DetailRow label="Real binary" value={shim?.real_binary_path} />
            </dl>
          </section>

          <section aria-label="Intercept proof">
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">
              Intercept proof
            </p>
            {shim?.last_intercept_proof_at !== null && shim?.last_intercept_proof_at !== undefined ? (
              <div className="flex items-start gap-2 rounded-xl border border-brand-green/20 bg-brand-green/[0.04] px-3 py-2.5">
                <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
                <p className="text-xs text-slate-600">
                  Last intercept proof {formatRelativeTime(shim.last_intercept_proof_at)}
                </p>
              </div>
            ) : shim?.installed ? (
              <div className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/70 px-3 py-2.5">
                <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" aria-hidden="true" />
                <p className="text-xs text-amber-900/90">
                  No intercept proof recorded yet. Run a test after PATH protection is active.
                </p>
              </div>
            ) : (
              <p className="text-xs text-slate-500">Install Guard shims before recording intercept proof.</p>
            )}
          </section>

          {shim?.activation_state === "restart_required" && (
            <div className="rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] px-3 py-2.5">
              <p className="text-xs text-slate-600">
                Guard updated your shell profile. Open a new shell or restart AI apps to activate this shim.
              </p>
            </div>
          )}

          {shim?.path_broken && (
            <div className="rounded-xl border border-amber-200 bg-amber-50/70 px-3 py-2.5">
              <p className="text-xs text-amber-900/90">
                PATH order is broken. Repair routing, then restart your shell before testing intercepts.
              </p>
            </div>
          )}
        </div>

        <div className="border-t border-slate-100 px-5 py-4">
          <div className="flex flex-wrap items-center gap-2">
            {showInstall && actionHandlers.install !== undefined ? (
              <IconActionButton
                variant="primary"
                label="Protect"
                icon={<HiMiniShieldCheck className="h-4 w-4" />}
                onClick={() => actionHandlers.install?.(manager)}
                disabled={anyPending}
              />
            ) : null}
            {showRepair && actionHandlers.repair !== undefined ? (
              <IconActionButton
                variant="primary"
                label="Fix PATH"
                icon={<HiMiniWrenchScrewdriver className="h-4 w-4" />}
                onClick={() => actionHandlers.repair?.(manager)}
                disabled={anyPending}
              />
            ) : null}
            {showTest && actionHandlers.test !== undefined ? (
              <IconActionButton
                variant="outline"
                label="Test"
                icon={<HiMiniBeaker className="h-4 w-4" />}
                onClick={() => actionHandlers.test?.(manager)}
                disabled={anyPending}
              />
            ) : null}
            {showRemove && actionHandlers.removeRequest !== undefined ? (
              <IconActionButton
                variant="danger"
                label="Remove"
                icon={<HiMiniTrash className="h-4 w-4" />}
                onClick={() => actionHandlers.removeRequest?.(manager)}
                disabled={anyPending}
              />
            ) : null}
            {isMine ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-brand-blue">
                <HiMiniArrowPath className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                Running…
              </span>
            ) : null}
          </div>
          <div className="mt-3">
            <ActionButton variant="ghost" onClick={onClose}>
              Close
            </ActionButton>
          </div>
        </div>
      </div>
    </div>
  );
}
