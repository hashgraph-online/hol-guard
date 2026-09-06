import { useCallback, useRef, useState } from "react";
import { HiMiniArrowTopRightOnSquare, HiMiniCloud, HiMiniExclamationTriangle } from "react-icons/hi2";

import { startGuardCloudConnect } from "../guard-api";
import { extensionEffectiveState, permissionEffectiveState } from "../extension-control-center-model";
import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../extension-controls-api";
import type { GuardRuntimeSnapshot } from "../guard-types";
import { effectiveStatusKey } from "../protection-center/effective-status-key";
import {
  buildLocalProtectionView,
  type LocalProtectionView,
  type LocalProtectionInput,
  type ProtectionSource,
} from "./local-protection-model";

function safeCloudSignInHref(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}

function ManagedControlsPrimaryAction(props: {
  action: LocalProtectionView["primaryAction"];
  connecting: boolean;
  checking: boolean;
  connectHref: string | null;
  onConnect: () => void;
  onRefresh: () => void;
}) {
  if (!props.action) return null;
  if (props.action.href) {
    return (
      <a href={props.action.href} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white">
        {props.action.label}
        <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
      </a>
    );
  }
  if (props.action.action === "refresh") {
    return (
      <button
        type="button"
        onClick={props.onRefresh}
        disabled={props.checking}
        aria-busy={props.checking}
        className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-60"
      >
        {props.checking ? "Checking…" : props.action.label}
      </button>
    );
  }
  if (props.action.action === "connect-cloud") {
    if (props.connectHref) {
      return (
        <a href={props.connectHref} className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark">
          <HiMiniCloud className="size-4" aria-hidden="true" />
          Open Guard Cloud sign-in
        </a>
      );
    }
    return (
      <button type="button" onClick={props.onConnect} disabled={props.connecting} className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50">
        <HiMiniCloud className="size-4" aria-hidden="true" />
        {props.connecting ? "Starting sign-in..." : props.action.label}
      </button>
    );
  }
  return null;
}

function layerTargetsExtension(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
  kind: "local-admin" | "signed-cloud",
): boolean {
  const permissionIds = new Set(extension.permissions.map((permission) => permission.permission_id));
  return effective.layers.some((layer) =>
    layer.kind === kind
    && layer.controls.some((control) =>
      (control.target_kind === "extension" && control.target_id === extension.extension_id)
      || (control.target_kind === "permission" && permissionIds.has(control.target_id)),
    ),
  );
}

type ExtensionProtectionAuthority = {
  effectiveState: LocalProtectionInput["effectiveState"];
  source: ProtectionSource;
  sources: readonly ProtectionSource[];
};

function managedSource(effective: EffectiveExtensionControls): ProtectionSource {
  const managed = effective.managed_controls;
  return managed?.authority_mode === "managed-restrictive"
    ? `Managed by ${managed.workspace_id}`
    : "Synced from Guard Cloud";
}

export function extensionProtectionAuthority(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
): ExtensionProtectionAuthority {
  if (effective.global_lockdown) {
    return { effectiveState: "lockdown", source: "Emergency Lockdown", sources: ["Emergency Lockdown"] };
  }
  const permissionIds = new Set(extension.permissions.map((permission) => permission.permission_id));
  const extensionProjection = effective.projection?.extensions.find(
    (item) => item.extension_id === extension.extension_id,
  );
  const permissionProjections = effective.projection?.permissions.filter(
    (item) => item.extension_id === extension.extension_id || permissionIds.has(item.permission_id),
  ) ?? [];
  const projections = extensionProjection ? [extensionProjection, ...permissionProjections] : permissionProjections;
  const managed = managedSource(effective);
  const hasManaged = projections.some((item) => item.managed_state !== "inherited")
    || layerTargetsExtension(effective, extension, "signed-cloud");
  const hasLocal = projections.some((item) => item.local_state !== "inherited")
    || layerTargetsExtension(effective, extension, "local-admin");
  const sources: ProtectionSource[] = [];
  if (hasManaged) sources.push(managed);
  if (hasLocal) sources.push("Set on this device");
  if (sources.length === 0) sources.push(extension.required ? "Required by Guard" : "Recommended by Guard");

  const managedBlocks = projections.some(
    (item) => item.effective_state === "blocked" && item.managed_state === "disabled",
  ) || effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some((control) =>
    control.state === "disabled"
    && ((control.target_kind === "extension" && control.target_id === extension.extension_id)
      || (control.target_kind === "permission" && permissionIds.has(control.target_id))),
  ));
  const localBlocks = projections.some(
    (item) => item.effective_state === "blocked" && item.local_state === "disabled",
  ) || effective.layers.some((layer) => layer.kind === "local-admin" && layer.controls.some((control) =>
    control.state === "disabled"
    && ((control.target_kind === "extension" && control.target_id === extension.extension_id)
      || (control.target_kind === "permission" && permissionIds.has(control.target_id))),
  ));
  const extensionBlocked = extensionProjection?.effective_state === "blocked"
    || extensionEffectiveState(effective, extension) === "disabled";
  const permissionStates = extension.permissions.map(
    (permission) => permissionEffectiveState(effective, extension, permission),
  );
  const blockedPermissionCount = permissionStates.filter((state) => state === "disabled").length;
  let effectiveState: LocalProtectionInput["effectiveState"];
  if (extensionBlocked) effectiveState = "blocked";
  else if (blockedPermissionCount > 0 && blockedPermissionCount < permissionStates.length) effectiveState = "partial";
  else if (blockedPermissionCount > 0 || localBlocks || managedBlocks) effectiveState = "blocked";
  else if (extension.required) effectiveState = "required";
  else effectiveState = extensionEffectiveState(effective, extension) === "enabled" ? "allowed" : "blocked";
  let source: ProtectionSource = sources.at(-1) ?? "Recommended by Guard";
  if (localBlocks) source = "Set on this device";
  if (managedBlocks) source = managed;
  return { effectiveState, source, sources };
}

export function extensionProtectionSource(
  effective: EffectiveExtensionControls,
  extension: ExtensionCatalogItem,
): ProtectionSource {
  return extensionProtectionAuthority(effective, extension).source;
}

function cloudBase(runtime: GuardRuntimeSnapshot | null | undefined): string | undefined {
  const candidate = runtime?.dashboard_url?.trim() || runtime?.connect_url?.trim();
  return candidate || undefined;
}

function recoveryNotice(recovery: LocalProtectionInput["recovery"]): string {
  if (recovery === "unsupported-version") {
    return "This Control Set uses a newer control schema. Update Guard before applying it; the last verified authority remains in force.";
  }
  if (recovery === "catalog-mismatch") {
    return "The Control Set and local Extension catalog do not match. Guard keeps the last verified authority fail-safe until compatibility is restored.";
  }
  if (recovery === "degraded") {
    return "Local control authority needs recovery. Guard keeps the last verified authority fail-safe while you refresh or repair it.";
  }
  return "Guard Cloud data is stale. Local protection continues with the last verified authority; check again to see whether a newer Control Set is available.";
}

type RefreshState = "idle" | "checking" | "complete" | "error";

export function extensionLocalProtectionInput(
  extension: ExtensionCatalogItem,
  effective: EffectiveExtensionControls,
  runtime?: GuardRuntimeSnapshot | null,
): LocalProtectionInput {
  const managed = effective.managed_controls;
  const authority = extensionProtectionAuthority(effective, extension);
  const failureCodes = new Set(effective.failures.map((failure) => failure.code.toLowerCase()));
  let recovery: LocalProtectionInput["recovery"];
  if (failureCodes.has("unsupported-control-schema")) recovery = "unsupported-version";
  else if (failureCodes.has("catalog-digest-mismatch") || failureCodes.has("catalog-unavailable")) recovery = "catalog-mismatch";
  else if (runtime?.cloud_policy_sync_error || [...failureCodes].some((code) => code.includes("stale"))) recovery = "stale";
  else if (effective.health !== "protected") recovery = "degraded";
  return {
    extensionName: extension.name,
    extensionId: extension.extension_id,
    effectiveState: authority.effectiveState,
    source: authority.source,
    sources: authority.sources,
    catalogDigest: effective.catalog_digest,
    recovery,
    cloudControlsUrl: cloudBase(runtime),
    controlSetName: managed?.control_set_name ?? managed?.control_set_id,
    controlSetVersion: managed?.bundle_version,
    workspace: managed?.workspace_id,
    authorityMode: managed?.authority_mode,
    acknowledgementRevision: managed?.acknowledgement.extension_authority_revision,
    acknowledgementStatus: managed?.acknowledgement.status,
    lastAcknowledgedAt: runtime?.cloud_policy_last_ack_at ?? undefined,
    effectiveProjectionDigest: managed?.acknowledgement.effective_projection_digest,
  };
}

export function ExtensionManagedControlsPanel(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  runtime?: GuardRuntimeSnapshot | null;
  onRefresh: () => Promise<void> | void;
}) {
  const [connecting, setConnecting] = useState(false);
  const [connectHref, setConnectHref] = useState<string | null>(null);
  const [connectMessage, setConnectMessage] = useState<string | null>(null);
  const [refreshState, setRefreshState] = useState<RefreshState>("idle");
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const refreshBaselineRef = useRef<string | null>(null);
  const input = extensionLocalProtectionInput(props.extension, props.effective, props.runtime);
  const view = buildLocalProtectionView(input);
  const connected = props.runtime?.cloud_state === "paired_active" || props.runtime?.cloud_state === "paired_waiting";
  const hasManagedControl = layerTargetsExtension(props.effective, props.extension, "signed-cloud");
  const refresh = useCallback(async () => {
    if (refreshState === "checking") return;
    refreshBaselineRef.current = effectiveStatusKey(props.effective, { runtime: props.runtime });
    setRefreshState("checking");
    setRefreshError(null);
    try {
      await props.onRefresh();
      setRefreshState("complete");
    } catch {
      setRefreshState("error");
      setRefreshError("Guard could not refresh this status. The last verified local authority remains in force; try again.");
    }
  }, [props.effective, props.onRefresh, props.runtime, refreshState]);
  const connect = useCallback(() => {
    setConnecting(true);
    setConnectMessage(null);
    void startGuardCloudConnect()
      .then((status) => {
        if (!status.connect_required) {
          setConnectMessage("Guard Cloud is connected.");
          return;
        }
        const href = safeCloudSignInHref(status.connect_flow?.authorize_url)
          ?? safeCloudSignInHref(status.connect_flow?.connect_url);
        setConnectHref(href);
        setConnectMessage(href ? "Complete sign-in to resume synced Control Sets." : "Guard could not start sign-in. Try again.");
      })
      .catch((error: unknown) => {
        setConnectMessage(error instanceof Error ? error.message : "Guard could not start sign-in. Try again.");
      })
      .finally(() => setConnecting(false));
  }, []);
  return (
    <section aria-labelledby="managed-controls-heading" className="space-y-4">
      <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Source and authority</p>
            <h2 id="managed-controls-heading" className="mt-1 text-lg font-semibold text-brand-dark">
              {hasManagedControl ? "Active managed control" : "No Control Set targets this Extension"}
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75">{view.summary}</p>
          </div>
          <span className="inline-flex self-start rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-semibold text-brand-dark">
            {view.source}
          </span>
        </div>
        {view.status === "needs-attention" || view.status === "unsupported" ? (
          <p role="alert" className="mt-4 flex gap-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-950">
            <HiMiniExclamationTriangle className="mt-0.5 size-4 shrink-0" />
            {recoveryNotice(input.recovery)}
          </p>
        ) : null}
        <dl className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {view.technicalDetails.map((detail) => (
            <div key={detail.label}>
              <dt className="text-xs font-semibold uppercase tracking-wide text-brand-dark/55">{detail.label}</dt>
              <dd className="mt-1 break-all text-sm text-brand-dark">{detail.value}</dd>
            </div>
          ))}
        </dl>
        <div className="mt-5 flex flex-wrap gap-2">
          <ManagedControlsPrimaryAction
            action={view.primaryAction}
            connecting={connecting}
            checking={refreshState === "checking"}
            connectHref={connectHref}
            onConnect={connect}
            onRefresh={refresh}
          />
        </div>
        {connectMessage ? <p role="status" className="mt-3 text-sm text-brand-dark/75">{connectMessage}</p> : null}
        {refreshState === "checking" ? <p role="status" aria-live="polite" className="mt-3 text-sm text-brand-dark/75">Checking current protection status…</p> : null}
        {refreshState === "complete" ? (
          <p role="status" aria-live="polite" className="mt-3 text-sm text-brand-dark/75">
            {effectiveStatusKey(props.effective, { runtime: props.runtime }) === refreshBaselineRef.current
              ? "Check complete. No change detected; the current verified authority is still in use."
              : "Check complete. Protection status updated."}
          </p>
        ) : null}
        {refreshState === "error" && refreshError ? <p role="alert" className="mt-3 text-sm text-rose-800">{refreshError}</p> : null}
      </div>
      {!connected ? (
        <p className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-brand-dark/75">
          Guard Cloud is disconnected. Local protection and local tightening remain available on this device; cross-device Control Sets resume after reconnecting.
        </p>
      ) : null}
      {hasManagedControl && input.authorityMode === "managed-restrictive" ? (
        <p className="rounded-2xl border border-indigo-200 bg-indigo-50 p-4 text-sm leading-6 text-indigo-950">
          This is a managed-restrictive Control Set. Local settings can add stricter blocks, but they cannot weaken this workspace restriction.
        </p>
      ) : null}
    </section>
  );
}
