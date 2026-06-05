import { useCallback } from "react";
import type { ReactNode } from "react";
import {
  HiMiniShieldCheck,
  HiMiniWrenchScrewdriver,
  HiMiniBeaker,
  HiMiniTrash,
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
} from "react-icons/hi2";
import { ActionButton, Tag } from "./approval-center-primitives";
import type { PackageFirewallStatusResponse, PackageShimEntry } from "./guard-types";

type ShimStatusDotProps = {
  active: boolean;
};

function ShimStatusDot({ active }: ShimStatusDotProps) {
  return (
    <span
      className={`inline-block h-2 w-2 shrink-0 rounded-full ${active ? "bg-brand-green" : "bg-slate-300"}`}
      aria-hidden="true"
    />
  );
}

type RemoveConfirmRowProps = {
  manager: string;
  onConfirm: () => void;
  onCancel: () => void;
  anyPending: boolean;
};

function RemoveConfirmRow({ manager, onConfirm, onCancel, anyPending }: RemoveConfirmRowProps) {
  return (
    <div
      className="flex flex-wrap items-center gap-2 rounded-lg border border-brand-attention/30 bg-brand-attention/[0.04] px-3 py-2"
      role="alert"
    >
      <p className="text-xs font-medium text-brand-dark">
        Remove shim for <span className="font-mono">{manager}</span>?
      </p>
      <div className="ml-auto flex items-center gap-1.5">
        <ActionButton variant="ghost" onClick={onCancel} disabled={anyPending}>
          Cancel
        </ActionButton>
        <ActionButton
          variant="danger"
          onClick={onConfirm}
          disabled={anyPending}
          aria-busy={anyPending}
        >
          {anyPending ? "Removing…" : "Confirm Remove"}
        </ActionButton>
      </div>
    </div>
  );
}

type ActionBtnProps = {
  label: string;
  icon: ReactNode;
  variant: "primary" | "secondary" | "outline" | "danger";
  onClick: () => void;
  disabled: boolean;
};

function ActionBtn({ label, icon, variant, onClick, disabled }: ActionBtnProps) {
  return (
    <ActionButton variant={variant} onClick={onClick} disabled={disabled}>
      {icon}
      {label}
    </ActionButton>
  );
}

type ActionButtonRowProps = {
  shim: PackageShimEntry;
  actions: PackageFirewallStatusResponse["actions"];
  anyPending: boolean;
  onInstall: () => void;
  onRepair: () => void;
  onTest: () => void;
  onRemoveRequest: () => void;
};

function ActionButtonRow({
  shim,
  actions,
  anyPending,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
}: ActionButtonRowProps) {
  const installState = actions.install ?? "disabled";
  const repairState = actions.repair ?? "disabled";
  const testState = actions.test ?? "disabled";
  const removeState = actions.remove ?? "disabled";
  const installBlocked = installState === "paid_required" || installState === "reconnect_required";
  const repairBlocked = repairState === "paid_required" || repairState === "reconnect_required";
  const testBlocked = testState === "paid_required" || testState === "reconnect_required";
  const removeBlocked = removeState === "paid_required" || removeState === "reconnect_required";

  const showInstall = !shim.installed && installState !== "disabled";
  const showRepair = shim.installed && repairState !== "disabled";
  const showTest = testState !== "disabled";
  const showRemove = removeState !== "disabled" && shim.installed;

  return (
    <div className="flex flex-wrap gap-1.5">
      {showInstall && (
        <ActionBtn
          label="Protect"
          icon={<HiMiniShieldCheck className="mr-1 h-3.5 w-3.5" aria-hidden="true" />}
          variant="primary"
          onClick={onInstall}
          disabled={anyPending || installBlocked}
        />
      )}
      {showRepair && (
        <ActionBtn
          label="Repair"
          icon={<HiMiniWrenchScrewdriver className="mr-1 h-3.5 w-3.5" aria-hidden="true" />}
          variant="secondary"
          onClick={onRepair}
          disabled={anyPending || repairBlocked}
        />
      )}
      {showTest && (
        <ActionBtn
          label="Test"
          icon={<HiMiniBeaker className="mr-1 h-3.5 w-3.5" aria-hidden="true" />}
          variant="outline"
          onClick={onTest}
          disabled={anyPending || testBlocked}
        />
      )}
      {showRemove && (
        <ActionBtn
          label="Remove"
          icon={<HiMiniTrash className="mr-1 h-3.5 w-3.5" aria-hidden="true" />}
          variant="danger"
          onClick={onRemoveRequest}
          disabled={anyPending || removeBlocked}
        />
      )}
    </div>
  );
}

export type ManagerActionCardProps = {
  shim: PackageShimEntry;
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
};

export function ManagerActionCard({
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
}: ManagerActionCardProps) {
  const handleInstall = useCallback(() => onInstall(shim.manager), [onInstall, shim.manager]);
  const handleRepair = useCallback(() => onRepair(shim.manager), [onRepair, shim.manager]);
  const handleTest = useCallback(() => onTest(shim.manager), [onTest, shim.manager]);
  const handleRemoveRequest = useCallback(
    () => onRemoveRequest(shim.manager),
    [onRemoveRequest, shim.manager],
  );
  const handleRemoveConfirm = useCallback(
    () => onRemoveConfirm(shim.manager),
    [onRemoveConfirm, shim.manager],
  );

  return (
    <div className="space-y-3 rounded-xl border border-slate-100 bg-white p-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <ShimStatusDot active={shim.active} />
          <span className="truncate font-mono text-sm font-semibold text-brand-dark">
            {shim.manager}
          </span>
          {isMine && (
            <HiMiniArrowPath
              className="h-3.5 w-3.5 shrink-0 animate-spin text-brand-blue"
              aria-label="Running…"
            />
          )}
        </div>
        <div className="shrink-0">
          {shim.active ? (
            <Tag tone="green">
              <HiMiniCheckCircle className="mr-0.5 inline h-3 w-3" aria-hidden="true" />
              Protected
            </Tag>
          ) : shim.installed ? (
            <Tag tone="attention">
              <HiMiniExclamationTriangle className="mr-0.5 inline h-3 w-3" aria-hidden="true" />
              Inactive
            </Tag>
          ) : (
            <Tag tone="slate">Uninstalled</Tag>
          )}
        </div>
      </div>

      {isConfirmingRemove ? (
        <RemoveConfirmRow
          manager={shim.manager}
          onConfirm={handleRemoveConfirm}
          onCancel={onRemoveCancel}
          anyPending={anyPending}
        />
      ) : (
        <ActionButtonRow
          shim={shim}
          actions={actions}
          anyPending={anyPending}
          onInstall={handleInstall}
          onRepair={handleRepair}
          onTest={handleTest}
          onRemoveRequest={handleRemoveRequest}
        />
      )}

      {shim.shim_path !== null && (
        <p className="break-all font-mono text-[10px] text-slate-400">{shim.shim_path}</p>
      )}
    </div>
  );
}
