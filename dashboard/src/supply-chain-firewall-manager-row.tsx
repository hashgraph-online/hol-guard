import { Fragment, useCallback } from "react";
import {
  HiMiniArrowPath,
  HiMiniBeaker,
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
  if (shim.activation_state === "protected") {
    return { label: "Protected", tone: "green", icon: "check" };
  }
  if (shim.activation_state === "restart_required") {
    return { label: "Restart required", tone: "blue", icon: "restart" };
  }
  if (shim.path_broken) {
    return { label: "PATH broken", tone: "attention", icon: "warning" };
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
  repairAwaitingRefresh: boolean;
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

const STATUS_MARK_CLASS: Record<ReturnType<typeof resolveShimStatus>["tone"], string> = {
  green: "bg-brand-green",
  blue: "bg-brand-blue",
  attention: "bg-brand-attention",
  slate: "bg-slate-300",
};

/**
 * One line of the manager roster. Wide screens read it left to right as a
 * ledger entry: which tool, how its shell finds it, then its state and what
 * you can do about it. Phones stack the same three parts.
 */
export function ManagerRow({
  manager,
  shim,
  actions,
  anyPending,
  repairAwaitingRefresh,
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
  const installAvailable = actionIsAvailable(actions.install ?? "disabled");
  const repairAvailable = actionIsAvailable(actions.repair ?? "disabled");
  const testAvailable = actionIsAvailable(actions.test ?? "disabled");
  const removeAvailable = actionIsAvailable(actions.remove ?? "disabled");

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
    <li className="grid min-w-0 gap-x-6 gap-y-2 py-3.5 md:grid-cols-[minmax(0,9rem)_minmax(0,1fr)_auto] md:items-start">
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="flex min-w-0 items-center gap-2">
          <span aria-hidden="true" className={`size-2 shrink-0 rounded-full ${STATUS_MARK_CLASS[status.tone]}`} />
          <button
            type="button"
            onClick={handleOpenDetails}
            className="inline-flex min-h-11 min-w-0 items-center truncate rounded text-left font-mono text-sm font-semibold text-brand-dark hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 md:min-h-0"
            aria-label={`Open ${manager} manager details`}
          >
            {manager}
          </button>
          {isMine && (
            <HiMiniArrowPath
              className="h-3.5 w-3.5 shrink-0 animate-spin text-brand-blue"
              aria-label="Running…"
            />
          )}
        </span>
        {shim?.detected && <span className="pl-4 text-xs text-slate-500">Detected</span>}
      </div>

      <div className="flex min-w-0 flex-col gap-1 pl-4 md:pl-0">
        {shim?.path_summary !== null && shim?.path_summary !== undefined && (
          <p className="break-words font-mono text-[11px] leading-relaxed text-slate-600">
            Shell path: <PathText value={shim.path_summary} />
          </p>
        )}
        {shim?.last_intercept_proof_at !== null && shim?.last_intercept_proof_at !== undefined ? (
          <p className="text-xs text-slate-500">
            Last protection test {formatRelativeTime(shim.last_intercept_proof_at)}
          </p>
        ) : shim?.installed ? (
          <p className="text-xs text-slate-500">No protection test recorded yet</p>
        ) : null}
        {shim?.activation_state === "restart_required" && (
          <p className="text-xs text-slate-600">
            Guard updated your shell profile. Open a new shell or restart AI apps to activate this shim.
          </p>
        )}
        {shim?.activation_state === "repair_required" && !shim.path_broken && (
          <p className="text-xs text-slate-600">
            Guard can add the shim directory to your shell profile automatically, then this manager will be ready after a restart.
          </p>
        )}
        {shim?.path_broken && (
          <p className="text-xs font-medium text-slate-700">
            Restart your shell after repair so PATH exports reload.
          </p>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 pl-4 md:justify-end md:pl-0 [&_button]:h-11 md:[&_button]:h-9 md:[&_button]:min-h-9">
        <Tag tone={status.tone}>{status.label}</Tag>
        {isConfirmingRemove ? (
          <>
            <IconActionButton
              showLabel
              variant="ghost"
              label="Cancel"
              icon={<HiMiniXCircle className="h-4 w-4" />}
              onClick={onRemoveCancel}
              disabled={anyPending}
            />
            <IconActionButton
              showLabel
              variant="danger"
              label="Confirm"
              icon={<HiMiniTrash className="h-4 w-4" />}
              onClick={handleRemoveConfirm}
              disabled={anyPending}
            />
          </>
        ) : (
          <>
            {showInstall && (
              <IconActionButton
                showLabel
                variant="primary"
                label="Protect"
                icon={<HiMiniShieldCheck className="h-4 w-4" />}
                onClick={handleInstall}
                disabled={anyPending}
              />
            )}
            {showRepair && (
              <IconActionButton
                showLabel
                variant="primary"
                label="Fix PATH"
                icon={<HiMiniWrenchScrewdriver className="h-4 w-4" />}
                onClick={handleRepair}
                disabled={anyPending || repairAwaitingRefresh}
              />
            )}
            {showTest && (
              <IconActionButton
                showLabel
                variant="outline"
                label="Test"
                icon={<HiMiniBeaker className="h-4 w-4" />}
                onClick={handleTest}
                disabled={anyPending}
              />
            )}
            {/* Removing is reversible and asks twice, so it stays quiet
                until the inline Confirm. */}
            {showRemove && (
              <IconActionButton
                showLabel
                variant="ghost"
                label="Remove"
                icon={<HiMiniTrash className="h-4 w-4" />}
                onClick={handleRemoveRequest}
                disabled={anyPending}
              />
            )}
          </>
        )}
      </div>
    </li>
  );
}

/** Lets a long shell path wrap after each slash instead of mid-name. */
function PathText({ value }: { value: string }) {
  const parts = value.split("/");
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>
          {index > 0 ? (
            <>
              /<wbr />
            </>
          ) : null}
          {part}
        </Fragment>
      ))}
    </>
  );
}
