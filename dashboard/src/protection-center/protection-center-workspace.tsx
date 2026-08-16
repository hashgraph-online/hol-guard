import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniClipboard,
  HiMiniClipboardDocumentCheck,
  HiMiniExclamationTriangle,
  HiMiniShieldCheck,
  HiMiniXMark,
} from "react-icons/hi2";

import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import {
  canonicalExtensionId,
  DEFAULT_EXTENSION_DETAIL_URL_STATE,
  extensionDetailHref,
  extensionStateLabel,
  parseExtensionRoute,
  readExtensionDetailUrlState,
  type ExtensionDetailUrlState,
  type ExtensionRoute,
} from "../extension-control-center-model";
import {
  acknowledgeDegradedExtensionControlAuthority,
  applyExtensionMutation,
  ExtensionControlApiError,
  fetchEffectiveExtensionControls,
  fetchExtensionCatalog,
  previewExtensionMutation,
  recoverExtensionControlAuthority,
  type EffectiveExtensionControls,
  type ExtensionCatalogItem,
  type ExtensionCatalogResponse,
  type ExtensionMutationPayload,
} from "../extension-controls-api";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { useModalDialog } from "../use-modal-dialog";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { PROTECTION_TERMS, protectionCenterLoadError } from "./copy/protection-copy";
import { PatternSearchConsole } from "./components/pattern-search-console";
import { ProtectionAuthorityNotice } from "./components/protection-authority-notice";
import { ProtectionModuleDetail } from "./protection-module-detail";
import {
  EXTENSION_PANEL_CLASS,
} from "./protection-surface";
import {
  InlineError,
  ProtectionModuleRow,
  ProtectionStatusHero,
} from "./components/protection-primitives";
import { deriveProtectionStatus } from "./model/protection-presentation";
import { WorkspacePageHeader } from "../workspace-page-header";

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; catalog: ExtensionCatalogResponse; effective: EffectiveExtensionControls };

type ExtensionMutationTarget = Pick<ExtensionCatalogItem, "extension_id" | "name">;
export type ProtectionPendingChange = { extension: ExtensionMutationTarget; enabled: boolean } | { globalLockdown: boolean };

type RouteState = { route: ExtensionRoute; detail: ExtensionDetailUrlState };

export function currentExtensionRouteState(): RouteState {
  return {
    route: parseExtensionRoute(window.location.pathname),
    detail: readExtensionDetailUrlState(window.location.search),
  };
}

export function requiresExtensionRecoveryApproval(error: unknown): boolean {
  return error instanceof ExtensionControlApiError &&
    (error.code === "approval_required" || error.code?.startsWith("approval_gate_") === true);
}

/**
 * Never surface a raw protocol code for authority actions. Every failure gets
 * a plain-language cause and a next step so the operator is never stuck.
 */
export function authorityActionErrorMessage(error: unknown): string {
  if (error instanceof ExtensionControlApiError) {
    if (error.code === "authority_not_recoverable") {
      return "Guard could not start this repair because the protection state changed underneath it. Guard reloaded the latest status. If protection still needs attention, run `hol-guard command controls recover-authority` in your terminal.";
    }
    if (error.code === "authority_recovery_failed" || error.code === "authority_recovery_incomplete") {
      return "Guard started the repair but could not verify a fully protected state. Protection stays fail-safe. Try again, or run `hol-guard command controls recover-authority` in your terminal.";
    }
    if (error.code === "authority_not_degraded") {
      return "The limited state already changed. Guard reloaded the latest status.";
    }
    if (requiresExtensionRecoveryApproval(error)) {
      return "Guard needs your approval password to continue. Enter it and try again.";
    }
  }
  return error instanceof Error && error.message && !/^authority_|^approval_/.test(error.message)
    ? error.message
    : "Guard could not complete this action. Local protection continues. Try again, or run `hol-guard command controls recover-authority` in your terminal.";
}

function randomToken(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

export function buildExtensionMutation(
  state: Extract<LoadState, { kind: "ready" }>,
  change: ProtectionPendingChange,
): ExtensionMutationPayload {
  const layers = structuredClone(state.effective.layers);
  let local = layers.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: state.catalog.catalog_digest,
      global_lockdown: false,
      controls: [],
    };
    layers.push(local);
  }
  if ("globalLockdown" in change) {
    local.global_lockdown = change.globalLockdown;
  } else {
    local.controls = local.controls.filter(
      (control) => control.target_kind !== "extension" || control.target_id !== change.extension.extension_id,
    );
    local.controls.push({
      target_kind: "extension",
      target_id: change.extension.extension_id,
      state: change.enabled ? "enabled" : "disabled",
    });
    local.controls.sort((left, right) =>
      `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`),
    );
  }
  return {
    previous_revision: state.effective.revision,
    catalog_digest: state.catalog.catalog_digest,
    layers,
    actor_id: "dashboard-admin",
    idempotency_key: randomToken(),
    nonce: randomToken(),
  };
}

export function ReviewModal(props: {
  change: ProtectionPendingChange;
  busy: boolean;
  error: string | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const dialogRef = useModalDialog<HTMLFormElement>(props.onCancel, !props.busy);
  const title = "globalLockdown" in props.change
    ? `${props.change.globalLockdown ? "Enable" : "Disable"} Emergency Lockdown`
    : `${props.change.enabled ? "Permit" : "Block"} ${props.change.extension.name}`;
  const current = "globalLockdown" in props.change
    ? props.change.globalLockdown ? "Off" : "Active"
    : props.change.enabled ? "Blocked" : "Allowed";
  const requested = "globalLockdown" in props.change
    ? props.change.globalLockdown ? "Active" : "Off"
    : props.change.enabled ? "Allowed within Guard safety rules" : "Blocked";
  const handleSubmit = useCallback((event: React.FormEvent) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }, props.busy);
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm">
      <form ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="protection-review-title" onSubmit={handleSubmit} className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Review protection change</p>
            <h2 id="protection-review-title" className="mt-2 text-xl font-semibold text-brand-dark">{title}</h2>
          </div>
          <button type="button" disabled={props.busy} onClick={props.onCancel} aria-label="Close review" className="grid size-11 place-items-center rounded-full text-brand-dark hover:bg-white/70 disabled:opacity-50">
            <HiMiniXMark className="size-5" />
          </button>
        </div>
        <div className="mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-[rgba(85,153,254,0.08)] p-4 text-sm text-brand-dark">
          <span>Current</span>
          <span aria-hidden="true">→</span>
          <strong>Requested</strong>
          <span>{current}</span>
          <span />
          <span>{requested}</span>
        </div>
        <p className="mt-4 text-sm leading-6 text-brand-dark">Guard's built-in minimum safety rules and organization policy remain active. This change does not disable detection.</p>
        <div className="mt-5">
          <ApprovalProofFieldInputs approvalGate={props.approvalGate} approvalPassword={password} approvalTotpCode={totp} onApprovalPasswordChange={(event) => setPassword(event.target.value)} onApprovalTotpCodeChange={(event) => setTotp(event.target.value)} />
        </div>
        {props.error ? <p role="alert" className="mt-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">{props.error}</p> : null}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" disabled={props.busy} onClick={props.onCancel} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark hover:bg-white/70 disabled:opacity-50">Cancel</button>
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60">{props.busy ? "Verifying…" : "Confirm change"}</button>
        </div>
      </form>
    </div>
  );
}

function sourceIsManaged(effective: EffectiveExtensionControls, extensionId: string): boolean {
  return effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some((control) => control.target_kind === "extension" && control.target_id === extensionId));
}

export function ProtectionCenterWorkspace() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [routeState, setRouteState] = useState<RouteState>(() => currentExtensionRouteState());
  const [pending, setPending] = useState<ProtectionPendingChange | null>(null);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [recoveryStatus, setRecoveryStatus] = useState<string | null>(null);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const aliasRedirected = useRef<string | null>(null);

  const load = useCallback(async (): Promise<EffectiveExtensionControls | null> => {
    // Keep the already-rendered protection data mounted while a refresh is in
    // flight so an applied change's confirmation toast survives the reload.
    setState((current) => (current.kind === "ready" ? current : { kind: "loading" }));
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      if (catalog.catalog_digest !== effective.catalog_digest) throw new Error("Protection data changed while Guard was loading. Check again before making changes.");
      setState({ kind: "ready", catalog, effective });
      return effective;
    } catch (error) {
      // A failed refresh after an authority action must not unmount the page
      // (and with it the mapped action error); only an initial load may fall
      // back to the full-page error state.
      setState((current) => (current.kind === "ready" ? current : { kind: "error", message: error instanceof Error ? error.message : "Extensions are unavailable" }));
      return null;
    }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const onPopState = () => setRouteState(currentExtensionRouteState());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const catalogExtensions = useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((a, b) => a.name.localeCompare(b.name)) : [], [state]);
  const requestedExtensionId = routeState.route.kind === "detail" ? routeState.route.extensionId : null;
  const canonicalSelected = useMemo(() => canonicalExtensionId(catalogExtensions, requestedExtensionId), [catalogExtensions, requestedExtensionId]);
  const selectedExtension = useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);

  useEffect(() => {
    if (state.kind !== "ready" || routeState.route.kind !== "detail" || !canonicalSelected) return;
    if (routeState.route.extensionId === canonicalSelected) return;
    const key = `${routeState.route.extensionId}->${canonicalSelected}`;
    if (aliasRedirected.current === key) return;
    aliasRedirected.current = key;
    const href = extensionDetailHref(canonicalSelected, routeState.detail);
    window.history.replaceState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: routeState.detail });
  }, [canonicalSelected, routeState, state]);

  const openExtension = useCallback((extension: ExtensionCatalogItem) => {
    const href = extensionDetailHref(extension.extension_id, DEFAULT_EXTENSION_DETAIL_URL_STATE);
    window.history.pushState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: extension.extension_id }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);

  const closeExtension = useCallback(() => {
    window.history.pushState({}, "", "/extensions");
    setRouteState({ route: { kind: "overview" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);

  const updateDetailState = useCallback((next: ExtensionDetailUrlState) => {
    if (!canonicalSelected) return;
    const href = extensionDetailHref(canonicalSelected, next);
    window.history.pushState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: next });
  }, [canonicalSelected]);

  const requestChange = useCallback((change: ProtectionPendingChange) => {
    setMutationError(null);
    void resolveApprovalGate({ failClosed: true })
      .then(() => setPending(change))
      .catch(() => setMutationError("Guard could not load local approval settings. Check the local connection and try again."));
  }, [resolveApprovalGate]);

  const confirm = useCallback(async (credentials: { approval_password?: string; approval_totp_code?: string }) => {
    if (state.kind !== "ready" || !pending) return;
    setBusy(true);
    setMutationError(null);
    try {
      const payload = buildExtensionMutation(state, pending);
      Object.assign(payload, credentials);
      payload.session_nonce = randomToken();
      const preview = await previewExtensionMutation(payload);
      if (typeof preview.proof_id !== "string") throw new Error("Guard did not issue a one-use proof for this protection change.");
      payload.proof_id = preview.proof_id;
      await applyExtensionMutation(payload);
      setPending(null);
      await load();
    } catch (error) {
      const recovery = error instanceof ExtensionControlApiError ? error.recoveryAction : undefined;
      setMutationError(`${error instanceof Error ? error.message : "Protection change failed"}${recovery ? ` · ${recovery}` : ""}`);
    } finally {
      setBusy(false);
    }
  }, [load, pending, state]);

  const runAuthorityAction = useCallback(async (kind: "repair" | "acknowledge", credentials: { approval_password?: string; approval_totp_code?: string }) => {
    const startHealth = state.kind === "ready" ? state.effective.health : null;
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus(null);
    try {
      const effective = kind === "acknowledge"
        ? await acknowledgeDegradedExtensionControlAuthority(credentials)
        : await recoverExtensionControlAuthority(credentials);
      if (kind === "acknowledge") {
        if (effective.health !== "degraded-acknowledged") throw new Error("Guard could not confirm the limited state.");
        setRecoveryStatus("The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored.");
      } else {
        if (effective.health !== "protected") throw new Error("Guard could not verify repaired protection.");
        setRecoveryStatus("Local protection repaired and verified.");
      }
      if (state.kind === "ready") setState({ ...state, effective });
    } catch (error) {
      // The authority state can change underneath the attempt (a repair that
      // rebuilt authority but failed its verification response, or a repair
      // that finished in another tab). Reload the truth before deciding what
      // to tell the operator so the page never disagrees with the daemon.
      const fresh = await load();
      const wanted = kind === "acknowledge" ? "degraded-acknowledged" : "protected";
      if (fresh && fresh.health === wanted) {
        setRecoveryError(null);
        setRecoveryStatus(kind === "acknowledge"
          ? "The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored."
          : "Local protection repaired and verified.");
      } else if (fresh && startHealth !== null && fresh.health !== startHealth) {
        // The state moved on during the attempt; the original error describes
        // a view that no longer exists. Show the transition, not the stale error.
        setRecoveryError(null);
        setRecoveryStatus("The protection state changed during the attempt. This page now shows the latest status.");
      } else {
        setRecoveryStatus(null);
        setRecoveryError(authorityActionErrorMessage(error));
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [load, state]);

  // Resolve the approval gate once the authority needs attention so the
  // notice's proof modal opens with the right password/TOTP shape.
  const authorityNeedsAttention = state.kind === "ready" && state.effective.health !== "protected";
  useEffect(() => {
    if (!authorityNeedsAttention) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setRecoveryError("Guard could not load the local approval settings yet. Check the connection and try again, or run `hol-guard command controls recover-authority` in your terminal.");
    });
  }, [authorityNeedsAttention, resolveApprovalGate]);

  if (state.kind === "loading") return <div className="grid min-h-[60vh] place-items-center" aria-busy="true"><HiMiniArrowPath className="size-7 animate-spin text-brand-blue motion-reduce:animate-none" aria-label="Loading Extensions" /></div>;
  if (state.kind === "error") {
    const loadError = protectionCenterLoadError(state.message);
    return <div className="mx-auto max-w-4xl"><div className={`${EXTENSION_PANEL_CLASS} guard-extensions-tone-danger`}><h1 className="text-xl font-semibold text-red-950">{loadError.title}</h1><p role="alert" className="mt-2 text-sm text-red-800">{loadError.detail}</p><p className="mt-3 text-xs font-medium text-red-900">Local protection continues on this device.</p><button type="button" onClick={load} className="mt-4 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-white">Try again</button></div></div>;
  }

  const authorityNotice = state.kind === "ready" ? <ProtectionAuthorityNotice
    effective={state.effective}
    busy={recoveryBusy}
    error={recoveryError}
    status={recoveryStatus}
    approvalGate={resolvedApprovalGate}
    onAction={(kind, credentials) => { void runAuthorityAction(kind, credentials); }}
    onCheckAgain={() => {
      void load();
      // Re-resolve the approval gate too so a failed load does not leave the
      // action disabled until a full page reload.
      setRecoveryError(null);
      void resolveApprovalGate({ failClosed: true }).catch(() => {
        setRecoveryError("Guard could not load the local approval settings yet. Check the connection and try again, or run `hol-guard command controls recover-authority` in your terminal.");
      });
    }}
  /> : null;

  if (routeState.route.kind === "detail" && selectedExtension) {
    return <>{authorityNotice}{recoveryStatus && state.effective.health === "protected" ? <p role="status" className="mb-3 text-sm font-medium text-emerald-800">{recoveryStatus}</p> : null}<ProtectionModuleDetail extension={selectedExtension} effective={state.effective} catalogDigest={state.catalog.catalog_digest} onBack={closeExtension} onRefresh={load} onRequestExtensionChange={(extension, enabled) => requestChange({ extension: { extension_id: extension.extension_id, name: extension.name }, enabled })} />{pending ? <ReviewModal change={pending} busy={busy} error={mutationError} approvalGate={resolvedApprovalGate} onCancel={() => { if (!busy) setPending(null); }} onConfirm={confirm} /> : null}</>;
  }

  if (routeState.route.kind === "detail" || routeState.route.kind === "invalid") {
    return <><div className="mx-auto max-w-4xl"><div className={`${EXTENSION_PANEL_CLASS} guard-extensions-tone-attention`}><h1 className="font-semibold text-amber-950">Extension not found</h1><p className="mt-2 text-sm text-amber-900">This link does not match an extension in the current Guard catalog.</p><button type="button" onClick={closeExtension} className="mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white">Back to Extensions</button></div></div>{authorityNotice}</>;
  }

  const status = deriveProtectionStatus(state.effective);
  const healthBroken = state.effective.health !== "protected";

  const handlePrimaryStatusAction = () => {
    // Authority repair actions live in the authority notice below; the status
    // line keeps only the lockdown review action.
    requestChange({ globalLockdown: false });
  };

  return <div className="w-full">
    <WorkspacePageHeader
      eyebrow="On this device"
      title={PROTECTION_TERMS.pageTitle}
      description="Pick a tool to see the commands Guard watches and change how they're handled."
    />
    <div className="mt-6">
      <ProtectionStatusHero status={status} onPrimaryAction={status.primaryAction === "review-lockdown" ? handlePrimaryStatusAction : undefined} />
      {recoveryStatus && !healthBroken ? <p role="status" className="mt-3 text-sm font-medium text-emerald-800">{recoveryStatus}</p> : null}
    </div>
    {healthBroken ? authorityNotice : null}
    {mutationError && !pending ? <div className="mt-4"><InlineError message={mutationError} /></div> : null}

    <PatternSearchConsole catalog={catalogExtensions} effective={state.effective} onRefresh={load} onOpenExtension={openExtension} />

    <section className="mt-10" aria-labelledby="all-tools-heading">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 id="all-tools-heading" className="text-xl font-semibold tracking-tight text-brand-dark">All tools</h2>
          <p className="mt-1 text-sm text-slate-500">Every tool Guard can watch on this device. Open one to adjust its command patterns.</p>
        </div>
        <span className="text-sm text-brand-dark/70">{catalogExtensions.length} tools</span>
      </div>
      <div className="mt-4">{catalogExtensions.map((extension) => <ProtectionModuleRow
        key={extension.extension_id}
        name={extension.name}
        description={extension.description}
        behavior={extensionStateLabel(state.effective, extension)}
        required={extension.required}
        managed={sourceIsManaged(state.effective, extension.extension_id)}
        onOpen={() => openExtension(extension)}
      />)}</div>
    </section>

    {pending ? <ReviewModal change={pending} busy={busy} error={mutationError} approvalGate={resolvedApprovalGate} onCancel={() => { if (!busy) setPending(null); }} onConfirm={confirm} /> : null}
  </div>;
}
