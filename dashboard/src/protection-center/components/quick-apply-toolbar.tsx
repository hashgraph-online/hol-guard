import { useCallback } from "react";
import { HiMiniCheckCircle, HiMiniNoSymbol, HiMiniSparkles } from "react-icons/hi2";

import type { EffectiveExtensionControls, ExtensionPermission } from "../../extension-controls-api";
import type { PermissionDraftState } from "../../extension-policy-draft";
import { managedPermissionState } from "../../extension-control-center-model";

export type QuickApplyChoice = {
  state: PermissionDraftState;
  label: string;
  detail: string;
  icon: typeof HiMiniSparkles;
};

export const QUICK_APPLY_CHOICES: readonly QuickApplyChoice[] = [
  {
    state: "inherit",
    label: "Recommended",
    detail: "Use Guard defaults for every matching capability.",
    icon: HiMiniSparkles,
  },
  {
    state: "allow",
    label: "Allow all",
    detail: "Allow every matching capability that organization policy permits.",
    icon: HiMiniCheckCircle,
  },
  {
    state: "block",
    label: "Deny all",
    detail: "Add a local block to every matching capability.",
    icon: HiMiniNoSymbol,
  },
];

/** Noun phrase the bulk actions apply to, singular and plural. */
export type QuickApplySubject = { one: string; other: string };

const DEFAULT_QUICK_APPLY_SUBJECT: QuickApplySubject = {
  one: "matching capability",
  other: "matching capabilities",
};

export function quickApplyPermissionIds(
  permissions: readonly { permission_id: string; configurable: boolean }[],
  effective: EffectiveExtensionControls,
  state: PermissionDraftState,
): string[] {
  return permissions
    .filter((permission) => permission.configurable)
    .filter((permission) => state !== "allow" || managedPermissionState(effective, permission.permission_id) !== "disabled")
    .map((permission) => permission.permission_id);
}

export function QuickApplyToolbar(props: {
  permissions: readonly ExtensionPermission[];
  effective: EffectiveExtensionControls;
  disabled: boolean;
  permissionState: (permissionId: string) => PermissionDraftState;
  onApply: (permissionIds: readonly string[], state: PermissionDraftState) => void;
  /** Noun phrase for the heading; defaults to the search console's "matching capability". */
  subject?: QuickApplySubject;
}) {
  const subject = props.subject ?? DEFAULT_QUICK_APPLY_SUBJECT;
  const configurableCount = props.permissions.filter((permission) => permission.configurable).length;
  const managedBlockCount = props.permissions.filter((permission) =>
    permission.configurable && managedPermissionState(props.effective, permission.permission_id) === "disabled"
  ).length;
  let managedBlockCopy = "";
  if (managedBlockCount) {
    const blockCopy = managedBlockCount === 1 ? "block stays" : "blocks stay";
    managedBlockCopy = ` ${managedBlockCount} organization ${blockCopy} enforced.`;
  }
  if (!configurableCount) return null;
  const heading = `Quick apply to ${configurableCount} ${configurableCount === 1 ? subject.one : subject.other}`;
  return (
    <div className="mt-4 flex flex-col gap-3 border-y border-[rgba(63,65,116,0.12)] bg-[rgba(85,153,254,0.045)] px-3 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-4">
      <div className="min-w-0">
        <p className="text-sm font-semibold text-brand-dark">{heading}</p>
        <p className="mt-0.5 text-xs leading-5 text-brand-dark/65">
          Changes stay in draft until you review and approve them.
          {managedBlockCopy}
        </p>
      </div>
      <div role="group" aria-label={`Quick apply to ${configurableCount} ${subject.other}`} className="flex flex-wrap gap-2">
        {QUICK_APPLY_CHOICES.map((choice) => (
          <QuickApplyButton
            key={choice.state}
            choice={choice}
            permissionIds={quickApplyPermissionIds(props.permissions, props.effective, choice.state)}
            disabled={props.disabled}
            permissionState={props.permissionState}
            onApply={props.onApply}
          />
        ))}
      </div>
    </div>
  );
}

export function QuickApplyButton(props: {
  choice: QuickApplyChoice;
  permissionIds: readonly string[];
  disabled: boolean;
  permissionState: (permissionId: string) => PermissionDraftState;
  onApply: (permissionIds: readonly string[], state: PermissionDraftState) => void;
}) {
  const active = props.permissionIds.length > 0
    && props.permissionIds.every((permissionId) => props.permissionState(permissionId) === props.choice.state);
  const handleClick = useCallback(() => {
    props.onApply(props.permissionIds, props.choice.state);
  }, [props.choice.state, props.onApply, props.permissionIds]);
  const Icon = props.choice.icon;
  return (
    <button
      type="button"
      aria-pressed={active}
      title={props.choice.detail}
      disabled={props.disabled || props.permissionIds.length === 0}
      onClick={handleClick}
      className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-[rgba(63,65,116,0.18)] bg-white px-3 text-xs font-semibold text-brand-dark shadow-sm transition-colors hover:border-brand-blue hover:text-brand-blue disabled:cursor-not-allowed disabled:opacity-45 aria-pressed:border-brand-blue aria-pressed:bg-brand-blue aria-pressed:text-white"
    >
      <Icon className="size-4" aria-hidden="true" />
      {props.choice.label}
    </button>
  );
}
