import { managedControlsHref } from "./managed-controls/local-protection-model";

export function AppliedPolicyToast(props: {
  revision: number;
  onUndo: () => void;
  onViewHistory: () => void;
  applyAcrossHref?: string | null;
}) {
  return <div role="status" data-testid="extension-policy-applied-toast" className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3">
    <p className="text-sm font-medium text-emerald-950">Applied · revision {props.revision}</p>
    <div className="flex flex-wrap gap-2">
      {props.applyAcrossHref ? (
        <a href={props.applyAcrossHref} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center rounded-xl border border-emerald-300 bg-white/70 px-3 text-sm font-semibold text-emerald-950">Apply across my devices</a>
      ) : null}
      <button type="button" onClick={props.onViewHistory} className="min-h-11 rounded-xl border border-emerald-300 bg-white/70 px-3 text-sm font-semibold text-emerald-950">View history</button>
      <button type="button" onClick={props.onUndo} className="min-h-11 rounded-xl bg-emerald-800 px-3 text-sm font-semibold text-white">Undo</button>
    </div>
  </div>;
}

export function appliedPolicyCloudHref(input: {
  cloudControlsUrl?: string;
  extensionId: string;
  extensionName: string;
  changedPermissionIds: readonly string[];
}): string | null {
  return managedControlsHref({
    extensionName: input.extensionName,
    extensionId: input.extensionId,
    permissionId: input.changedPermissionIds.length === 1 ? input.changedPermissionIds[0] : undefined,
    effectiveState: "allowed",
    source: "Set on this device",
    cloudControlsUrl: input.cloudControlsUrl,
  });
}
