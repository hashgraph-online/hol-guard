import { useCallback } from "react";
import {
  HiMiniArrowPath,
  HiMiniBeaker,
  HiMiniCheckCircle,
  HiMiniClock,
  HiMiniExclamationTriangle,
  HiMiniShieldCheck,
  HiMiniTrash,
  HiMiniWrenchScrewdriver,
  HiMiniXCircle,
} from "react-icons/hi2";
import { formatRelativeTime } from "./approval-center-utils";
import { Tag, IconActionButton } from "./approval-center-primitives";
import type { PackageFirewallStatusResponse, PackageShimEntry } from "./guard-types";

export function resolveShimStatus(shim: PackageShimEntry | undefined): {
  label: string;
  tone: "green" | "blue" | "attention" | "slate";
  icon: "check" | "restart" | "warning" | "none";
} {
  if (!shim) {
    return { label: "Unprotected", tone: "attention", icon: "warning" };
  }
  if (!shim.installed && shim.detected) {
    return { label: "Detected, not protected", tone: "slate", icon: "warning" };
  }
  if (!shim.installed) {
    return { label: "Unprotected", tone: "attention", icon: "warning" };
  }
  if (shim.path_broken) {
    return { label: "PATH broken", tone: "attention", icon: "warning" };
  }
  if (shim.activation_state === "protected") {
    return { label: "Protected", tone: "green", icon: "check" };
  }
  if (shim.activation_state === "restart_required") {
    return { label: "Restart required", tone: "blue", icon: "restart" };
  }
  if (shim.activation_state === "repair_required") {
    return { label: "Needs PATH repair", tone: "attention", icon: "warning" };
  }
  return { label: "Unprotected", tone: "attention", icon: "warning" };
}

function actionIsAvailable(state: string | undefined): boolean {
  return state === "available";
}

type ManagerRowProps = {
  manager: string;
  shim: PackageShimEntry | undefined;
  actions: PackageFirewallStatusResponse["actions"];
  anyPending: boolean;
  isMine: boolean;
  isConfirmingRemove: boolean;
  onInstall: (manager: string) => void;
  onRepair: (manager: string) => void;
  onTest: (manager: string) => void;
  onRemoveRequest: (manager: string) => void;
  onRemoveConfirm: (manager: string) => void;
  onRemoveCancel: () => void;
  onOpenDetails: (manager: string) => void;
};

export function ManagerRow({
  manager,
  shim,
  actions,
  anyPending,
  isMine,
  isConfirmingRemove,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
  onRemoveConfirm,
  onRemoveCancel,
  onOpenDetails,
}: ManagerRowProps) {
  const status = resolveShimStatus(shim);
  const installState = actions.install ?? "disabled";
  const repairState = actions.repair ?? "disabled";
  const testState = actions.test ?? "disabled";
  const removeState = actions.remove ?? "disabled";
  const installAvailable = actionIsAvailable(installState);
  const repairAvailable = actionIsAvailable(repairState);
  const testAvailable = actionIsAvailable(testState);
  const removeAvailable = actionIsAvailable(removeState);

  const showInstall = (!shim || !shim.installed) && installAvailable;
  const showRepair =
    shim?.installed &&
    (shim.activation_state === "repair_required" || shim.path_broken) &&
    repairAvailable;
  const showTest = shim?.installed && shim.activation_state === "protected" && testAvailable;
  const showRemove = shim?.installed && removeAvailable;

  const handleInstall = useCallback(() => onInstall(manager), [onInstall, manager]);
  const handleRepair = useCallback(() => onRepair(manager), [onRepair, manager]);
  const handleTest = useCallback(() => onTest(manager), [onTest, manager]);
  const handleRemoveRequest = useCallback(() => onRemoveRequest(manager), [onRemoveRequest, manager]);
  const handleRemoveConfirm = useCallback(() => onRemoveConfirm(manager), [onRemoveConfirm, manager]);
  const handleOpenDetails = useCallback(() => onOpenDetails(manager), [onOpenDetails, manager]);

  return (
    <div className="border-b border-slate-100 last:border-b-0" role="row">
      <div className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 flex-col gap-1 sm:flex-1" role="cell">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            {status.icon === "check" ? (
              <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
            ) : status.icon === "restart" ? (
              <HiMiniArrowPath className="h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
            ) : (
              <HiMiniExclamationTriangle className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
            )}
            <button
              type="button"
              onClick={handleOpenDetails}
              className="truncate text-left font-mono text-sm font-semibold text-brand-dark hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded"
              aria-label={`Open ${manager} manager details`}
            >
              {manager}
            </button>
            {shim?.detected && <Tag tone="green">Detected</Tag>}
            {isMine && (
              <HiMiniArrowPath
                className="h-3.5 w-3.5 shrink-0 animate-spin text-brand-blue"
                aria-label="Running…"
              />
            )}
          </div>
          {shim?.path_summary !== null && shim?.path_summary !== undefined && (
            <p className="break-all font-mono text-[11px] leading-relaxed text-slate-500 sm:pl-6">
              Shell path: {shim.path_summary}
            </p>
          )}
          {shim?.last_intercept_proof_at !== null && shim?.last_intercept_proof_at !== undefined ? (
            <p className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 sm:pl-6">
              <HiMiniCheckCircle className="h-3.5 w-3.5 shrink-0 text-brand-green" aria-hidden="true" />
              Last protection test {formatRelativeTime(shim.last_intercept_proof_at)}
            </p>
          ) : shim?.installed ? (
            <p className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 sm:pl-6">
              <HiMiniClock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              No protection test recorded yet
            </p>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3" role="cell">
          <div className="shrink-0">
            <Tag tone={status.tone}>{status.label}</Tag>
          </div>

          <div className="shrink-0 [&_button]:min-h-11 [&_button]:h-11">
            {isConfirmingRemove ? (
              <div className="flex items-center gap-1.5">
                <IconActionButton
                  variant="ghost"
                  label="Cancel"
                  icon={<HiMiniXCircle className="h-4 w-4" />}
                  onClick={onRemoveCancel}
                  disabled={anyPending}
                />
                <IconActionButton
                  variant="danger"
                  label="Confirm"
                  icon={<HiMiniTrash className="h-4 w-4" />}
                  onClick={handleRemoveConfirm}
                  disabled={anyPending}
                />
              </div>
            ) : (
              <div className="flex flex-wrap items-center gap-1.5">
                {showInstall && (
                  <IconActionButton
                    variant="primary"
                    label="Protect"
                    icon={<HiMiniShieldCheck className="h-4 w-4" />}
                    onClick={handleInstall}
                    disabled={anyPending}
                  />
                )}
                {showRepair && (
                  <IconActionButton
                    variant="primary"
                    label="Fix PATH"
                    icon={<HiMiniWrenchScrewdriver className="h-4 w-4" />}
                    onClick={handleRepair}
                    disabled={anyPending}
                  />
                )}
                {showTest && (
                  <IconActionButton
                    variant="outline"
                    label="Test"
                    icon={<HiMiniBeaker className="h-4 w-4" />}
                    onClick={handleTest}
                    disabled={anyPending}
                  />
                )}
                {showRemove && (
                  <IconActionButton
                    variant="danger"
                    label="Remove"
                    icon={<HiMiniTrash className="h-4 w-4" />}
                    onClick={handleRemoveRequest}
                    disabled={anyPending}
                  />
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {shim?.activation_state === "restart_required" && (
        <div className="px-4 pb-2">
          <p className="text-xs text-slate-500">
            Guard updated your shell profile. Open a new shell or restart AI apps to activate this shim.
          </p>
        </div>
      )}

      {shim?.activation_state === "repair_required" && (
        <div className="px-4 pb-2">
          <p className="text-xs text-slate-500">
            Guard can add the shim directory to your shell profile automatically, then this manager will be ready after a restart.
          </p>
        </div>
      )}

      {shim?.path_broken && (
        <div className="px-4 pb-2">
          <p className="text-xs text-brand-attention">
            Restart your shell after repair so PATH exports reload.
          </p>
        </div>
      )}
    </div>
  );
}
