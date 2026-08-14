import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniClipboard,
  HiMiniClipboardDocumentCheck,
  HiMiniExclamationTriangle,
  HiMiniLockClosed,
  HiMiniShieldCheck,
  HiMiniXMark,
} from "react-icons/hi2";

import { ApprovalProofModal } from "../approval-proof-modal";
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
import { ExtensionsFilterBar } from "../extensions-filter-bar";
import {
  EMPTY_EXTENSION_FILTERS,
  filterExtensions,
  hasActiveFilters,
  isExtensionEnabled,
  type ExtensionFilterState,
} from "../extensions-filters";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { useDebounce } from "../use-debounce";
import { useModalDialog } from "../use-modal-dialog";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { PROTECTION_TERMS, protectionCenterLoadError } from "./copy/protection-copy";
import { ProtectionLandingExperience } from "./protection-landing-experience";
import { PatternSearchConsole } from "./components/pattern-search-console";
import { ProtectionModuleDetail } from "./protection-module-detail";
import {
  EXTENSION_BODY_CLASS,
  EXTENSION_KICKER_CLASS,
  EXTENSION_LIST_CLASS,
  EXTENSION_PANEL_CLASS,
  EXTENSION_PANEL_COMPACT_CLASS,
  EXTENSION_SURFACE_CLASS,
  EXTENSION_TITLE_CLASS,
} from "./protection-surface";
import {
  InlineError,
  ProtectionDensityControl,
  ProtectionModuleRow,
  ProtectionStatusHero,
  TechnicalDetails,
  useProtectionDensity,
} from "./components/protection-primitives";
import { deriveProtectionStatus } from "./model/protection-presentation";

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; catalog: ExtensionCatalogResponse; effective: EffectiveExtensionControls };

type ExtensionMutationTarget = Pick<ExtensionCatalogItem, "extension_id" | "name">;
export type ProtectionPendingChange = { extension: ExtensionMutationTarget; enabled: boolean } | { globalLockdown: boolean };

type RouteState = { route: ExtensionRoute; detail: ExtensionDetailUrlState };

export type ExtensionRecoveryAction = {
  actionLabel?: string;
  copyLabel: string;
  command: string;
  description: string;
  title: string;
};

export function currentExtensionRouteState(): RouteState {
  return {
    route: parseExtensionRoute(window.location.pathname),
    detail: readExtensionDetailUrlState(window.location.search),
  };
}

export function extensionRecoveryAction(health: EffectiveExtensionControls["health"]): ExtensionRecoveryAction | null {
  if (health === "protected") return null;
  if (health === "tampered" || health === "recovery-required") {
    return {
      title: "Repair extension controls",
      actionLabel: "Repair now",
      copyLabel: "Copy repair command",
      description: "Guard locked these settings after detecting damaged authority data. Authenticate on this device to rebuild trusted authority.",
      command: "hol-guard command controls recover-authority",
    };
  }
  if (health === "degraded-unacknowledged") {
    return {
      title: "Acknowledge degraded extension controls",
      actionLabel: "Acknowledge degraded state",
      copyLabel: "Copy status command",
      description: "Guard is failing closed because extension-control authority is degraded. Authenticate to acknowledge the degraded state. Acknowledgement does not restore protected authority.",
      command: "hol-guard status",
    };
  }
  if (health === "degraded-acknowledged") {
    return {
      title: "Degraded extension controls acknowledged",
      copyLabel: "Copy status command",
      description: "Guard remains fail-closed while extension-control authority is degraded. Restore protected authority before changing extension policy.",
      command: "hol-guard status",
    };
  }
  return {
    title: "Finish local enrollment",
    copyLabel: "Copy enrollment command",
    description: "Authenticate in this device's terminal to protect extension settings, then check again.",
    command: "hol-guard command controls enroll",
  };
}

export function requiresExtensionRecoveryApproval(error: unknown): boolean {
  return error instanceof ExtensionControlApiError &&
    (error.code === "approval_required" || error.code?.startsWith("approval_gate_") === true);
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

export function ExtensionStatusBanner(props: {
  busy?: boolean;
  effective: EffectiveExtensionControls;
  error?: string | null;
  status?: string | null;
  onRecover?: () => void;
  onRetry: () => void;
}) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const recovery = extensionRecoveryAction(props.effective.health);
  const handleCopy = useCallback(async () => {
    if (!recovery) return;
    try {
      await navigator.clipboard.writeText(recovery.command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }, [recovery]);

  if (props.effective.health === "protected") {
    return <div className="flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900"><HiMiniShieldCheck className="size-5 shrink-0" aria-hidden="true" /><span><strong>Protected authority</strong> · revision {props.effective.revision}</span></div>;
  }
  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required" || props.effective.health === "degraded-unacknowledged";
  const busyLabel = props.effective.health === "degraded-unacknowledged" ? "Acknowledging…" : "Repairing…";
  return <div className="rounded-2xl border border-amber-200 bg-amber-50 p-5"><div className="flex items-start gap-3"><span className="mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-800"><HiMiniExclamationTriangle className="size-5" aria-hidden="true" /></span><div className="min-w-0 flex-1"><h2 className="font-semibold text-amber-950">{recovery?.title}</h2><p className="mt-1 text-sm leading-6 text-amber-950">{recovery?.description}</p><div className="mt-4 flex flex-wrap items-center gap-2">{repairable && props.onRecover ? <button type="button" aria-busy={props.busy} disabled={props.busy} onClick={props.onRecover} className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white disabled:opacity-60">{props.busy ? <HiMiniArrowPath className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" /> : <HiMiniShieldCheck className="size-4" aria-hidden="true" />}{props.busy ? busyLabel : recovery?.actionLabel}</button> : null}<button type="button" onClick={props.onRetry} className="inline-flex min-h-11 items-center gap-2 rounded-lg border border-amber-300 bg-white px-3 py-2 text-sm font-semibold text-amber-950 hover:bg-amber-100"><HiMiniArrowPath className="size-4" aria-hidden="true" />Check again</button></div><div className="mt-4 border-t border-amber-200 pt-3"><p className="text-xs font-semibold uppercase tracking-wide text-amber-900">Command-line fallback</p><div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center"><code className="min-w-0 flex-1 overflow-x-auto rounded-lg border border-amber-200 bg-white px-3 py-2 text-xs text-amber-950">{recovery?.command}</code><button type="button" onClick={handleCopy} className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-amber-300 bg-white px-3 py-2 text-sm font-semibold text-brand-blue">{copyState === "copied" ? <HiMiniClipboardDocumentCheck className="size-4" aria-hidden="true" /> : <HiMiniClipboard className="size-4" aria-hidden="true" />}{copyState === "copied" ? "Copied" : recovery?.copyLabel}</button></div>{copyState === "failed" ? <span role="status" className="mt-2 block text-sm text-red-800">Copy failed. Select the command above.</span> : null}</div>{props.error ? <p role="alert" className="mt-3 text-sm font-medium text-red-800">{props.error}</p> : null}{props.status ? <p role="status" className="mt-3 text-sm font-medium text-amber-950">{props.status}</p> : null}</div></div></div>;
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
  const [recoveryApprovalOpen, setRecoveryApprovalOpen] = useState(false);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [recoveryStatus, setRecoveryStatus] = useState<string | null>(null);
  const [filters, setFilters] = useState<ExtensionFilterState>(EMPTY_EXTENSION_FILTERS);
  const [density, setDensity] = useProtectionDensity();
  const [moreDetailOpen, setMoreDetailOpen] = useState(() => density !== "simple");
  const [provenanceOpen, setProvenanceOpen] = useState(false);
  const [troubleshootingOpen, setTroubleshootingOpen] = useState(false);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const aliasRedirected = useRef<string | null>(null);

  const load = useCallback(async () => {
    // Keep the already-rendered protection data mounted while a refresh is in
    // flight so an applied change's confirmation toast survives the reload.
    setState((current) => (current.kind === "ready" ? current : { kind: "loading" }));
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      if (catalog.catalog_digest !== effective.catalog_digest) throw new Error("Protection data changed while Guard was loading. Check again before making changes.");
      setState({ kind: "ready", catalog, effective });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Extensions are unavailable" });
    }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    // Open with Advanced/Developer. Stay open on Simple so density radios remain usable after the user reveals them.
    if (density !== "simple") setMoreDetailOpen(true);
  }, [density]);

  useEffect(() => {
    const onPopState = () => setRouteState(currentExtensionRouteState());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const catalogExtensions = useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((a, b) => a.name.localeCompare(b.name)) : [], [state]);
  const requestedExtensionId = routeState.route.kind === "detail" ? routeState.route.extensionId : null;
  const canonicalSelected = useMemo(() => canonicalExtensionId(catalogExtensions, requestedExtensionId), [catalogExtensions, requestedExtensionId]);
  const selectedExtension = useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);
  const debouncedQuery = useDebounce(filters.query, 120);
  const effectiveFilters = useMemo<ExtensionFilterState>(() => ({ ...filters, query: debouncedQuery }), [filters, debouncedQuery]);
  const filtered = useMemo(() => state.kind === "ready" ? filterExtensions(catalogExtensions, state.effective, effectiveFilters) : [], [catalogExtensions, state, effectiveFilters]);

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

  const recover = useCallback(async (credentials?: { approval_password?: string; approval_totp_code?: string }) => {
    const acknowledgingDegraded = state.kind === "ready" && state.effective.health === "degraded-unacknowledged";
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus(acknowledgingDegraded ? "Confirming the limited state…" : "Repairing local protection…");
    try {
      const effective = acknowledgingDegraded
        ? await acknowledgeDegradedExtensionControlAuthority(credentials)
        : await recoverExtensionControlAuthority(credentials);
      if (acknowledgingDegraded) {
        if (effective.health !== "degraded-acknowledged") throw new Error("Guard could not confirm the limited state.");
        setRecoveryStatus("The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored.");
      } else {
        if (effective.health !== "protected") throw new Error("Guard could not verify repaired protection.");
        setRecoveryStatus("Local protection repaired and verified.");
      }
      if (state.kind === "ready") setState({ ...state, effective });
      setRecoveryApprovalOpen(false);
    } catch (error) {
      if (!credentials && requiresExtensionRecoveryApproval(error)) {
        try {
          await resolveApprovalGate({ failClosed: true });
          setRecoveryApprovalOpen(true);
          setRecoveryStatus(null);
        } catch {
          setRecoveryError("Guard could not load local approval settings. Check the local connection and try again.");
          setRecoveryStatus(null);
        }
      } else {
        setRecoveryError(error instanceof Error ? error.message : "Guard could not repair local protection.");
        setRecoveryStatus(null);
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [resolveApprovalGate, state]);

  if (state.kind === "loading") return <main className="grid min-h-[60vh] place-items-center" aria-busy="true"><HiMiniArrowPath className="size-7 animate-spin text-brand-blue motion-reduce:animate-none" aria-label="Loading Extensions" /></main>;
  if (state.kind === "error") {
    const loadError = protectionCenterLoadError(state.message);
    return <main className={`${EXTENSION_SURFACE_CLASS} mx-auto max-w-4xl p-6`}><div className={`${EXTENSION_PANEL_CLASS} guard-extensions-tone-danger`}><h1 className="text-xl font-semibold text-red-950">{loadError.title}</h1><p role="alert" className="mt-2 text-sm text-red-800">{loadError.detail}</p><p className="mt-3 text-xs font-medium text-red-900">Local protection continues on this device.</p><button type="button" onClick={load} className="mt-4 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-white">Try again</button></div></main>;
  }

  const recoveryModal = recoveryApprovalOpen ? <ApprovalProofModal
    title={state.effective.health === "degraded-unacknowledged" ? "Confirm limited protection state" : "Repair local protection"}
    detail={state.effective.health === "degraded-unacknowledged" ? "Authenticate this acknowledgement on your device. It does not restore full protection." : "Authenticate this repair on your device. Guard uses the proof once and does not store it."}
    confirmLabel={state.effective.health === "degraded-unacknowledged" ? "Acknowledge limited state" : "Repair protection"}
    approvalGate={resolvedApprovalGate}
    busy={recoveryBusy}
    error={recoveryError}
    onCancel={() => { if (!recoveryBusy) setRecoveryApprovalOpen(false); }}
    onConfirm={(credentials) => { void recover(credentials); }}
  /> : null;

  if (routeState.route.kind === "detail" && selectedExtension) {
    return <><ProtectionModuleDetail extension={selectedExtension} effective={state.effective} catalogDigest={state.catalog.catalog_digest} onBack={closeExtension} onRefresh={load} onRequestExtensionChange={(extension, enabled) => requestChange({ extension: { extension_id: extension.extension_id, name: extension.name }, enabled })} />{pending ? <ReviewModal change={pending} busy={busy} error={mutationError} approvalGate={resolvedApprovalGate} onCancel={() => { if (!busy) setPending(null); }} onConfirm={confirm} /> : null}{recoveryModal}</>;
  }

  if (routeState.route.kind === "detail" || routeState.route.kind === "invalid") {
    return <><main className={`${EXTENSION_SURFACE_CLASS} mx-auto max-w-4xl p-6`}><div className={`${EXTENSION_PANEL_CLASS} guard-extensions-tone-attention`}><h1 className="font-semibold text-amber-950">Extension not found</h1><p className="mt-2 text-sm text-amber-900">This link does not match an extension in the current Guard catalog.</p><button type="button" onClick={closeExtension} className="mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white">Back to Extensions</button></div></main>{recoveryModal}</>;
  }

  const status = deriveProtectionStatus(state.effective);
  const locked = state.effective.health !== "protected";
  const visible = density === "simple" ? catalogExtensions : filtered;

  const handlePrimaryStatusAction = () => {
    if (status.primaryAction === "repair" || status.primaryAction === "retry-repair") {
      void recover();
    } else if (status.primaryAction === "review-lockdown") {
      requestChange({ globalLockdown: false });
    } else if (status.primaryAction === "finish-setup") {
      setDensity("advanced");
      setTroubleshootingOpen(true);
      requestAnimationFrame(() => document.getElementById("advanced-protection-controls")?.scrollIntoView({ block: "nearest" }));
    } else {
      void load();
    }
  };

  return <main className={`${EXTENSION_SURFACE_CLASS} mx-auto w-full max-w-6xl px-4 py-8 sm:px-6 lg:px-8`}>
    <header className="flex flex-col gap-5 pb-2 lg:flex-row lg:items-end lg:justify-between">
      <div><p className={EXTENSION_KICKER_CLASS}>On this device</p><h1 className={EXTENSION_TITLE_CLASS}>{PROTECTION_TERMS.pageTitle}</h1><p className={`mt-2 max-w-2xl ${EXTENSION_BODY_CLASS}`}>See which tools Guard is watching, then open one to understand or change it.</p></div>
      <details
        className="w-full max-w-sm"
        data-testid="protection-more-detail"
        open={moreDetailOpen}
        onToggle={(event) => setMoreDetailOpen(event.currentTarget.open)}
      >
        <summary className="cursor-pointer text-sm font-semibold text-brand-dark">More detail</summary>
        <div className="mt-3"><ProtectionDensityControl value={density} onChange={setDensity} /></div>
      </details>
    </header>

    <PatternSearchConsole catalog={catalogExtensions} effective={state.effective} onRefresh={load} />

    <div className="mt-6"><ProtectionStatusHero status={status} busy={recoveryBusy} onPrimaryAction={status.primaryAction === "none" ? undefined : handlePrimaryStatusAction}>
      <p className="text-xs text-brand-dark/70">Cloud continuity is separate from local protection. Signing out or losing Cloud connectivity does not turn local protection off.</p>
    </ProtectionStatusHero></div>

    {mutationError && !pending ? <div className="mt-4"><InlineError message={mutationError} /></div> : null}
    {recoveryError ? <div className="mt-4"><InlineError message={recoveryError} /></div> : null}
    {recoveryStatus ? <p role="status" className={`mt-4 ${EXTENSION_PANEL_COMPACT_CLASS} text-sm text-brand-dark`}>{recoveryStatus}</p> : null}

    {density === "simple" ? <ProtectionLandingExperience
      catalog={catalogExtensions}
      catalogDigest={state.catalog.catalog_digest}
      effective={state.effective}
      filters={filters}
      onFilters={(patch) => setFilters((previous) => ({ ...previous, ...patch }))}
      onClearFilters={() => setFilters(EMPTY_EXTENSION_FILTERS)}
      onOpen={openExtension}
    /> : null}

    {density !== "simple" ? <section id="advanced-protection-controls" className="mt-6 space-y-3" aria-label="Advanced protection controls">
      <details open={troubleshootingOpen} onToggle={(event) => setTroubleshootingOpen(event.currentTarget.open)} className={EXTENSION_PANEL_CLASS}>
        <summary className="cursor-pointer text-sm font-semibold text-brand-dark">Troubleshooting</summary>
        <div className="mt-3"><ExtensionStatusBanner busy={recoveryBusy} effective={state.effective} error={recoveryError} status={recoveryStatus} onRecover={() => { void recover(); }} onRetry={load} /></div>
      </details>
      <button type="button" disabled={locked} onClick={() => requestChange({ globalLockdown: !state.effective.global_lockdown })} className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-[rgba(63,65,116,0.14)] bg-white/80 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50"><HiMiniLockClosed className="size-4" />{state.effective.global_lockdown ? "Review ending Emergency Lockdown" : "Review Emergency Lockdown"}</button>
    </section> : null}

    {density !== "simple" ? <section aria-labelledby="protection-modules-heading" className="mt-8">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between"><div><h2 id="protection-modules-heading" className="text-xl font-semibold text-brand-dark">All extensions</h2><p className={`mt-1 ${EXTENSION_BODY_CLASS}`}>Open an extension to understand its current behavior and available controls.</p></div><span className="text-sm text-brand-dark/70">{catalogExtensions.length} available</span></div>
      <div className="mt-4"><ExtensionsFilterBar filters={filters} onChange={(patch) => setFilters((previous) => ({ ...previous, ...patch }))} onClear={() => setFilters(EMPTY_EXTENSION_FILTERS)} extensions={catalogExtensions} effective={state.effective} /></div>
      {visible.length ? <div className={EXTENSION_LIST_CLASS}>{visible.map((extension) => <ProtectionModuleRow
        key={extension.extension_id}
        name={extension.name}
        description={extension.description}
        behavior={extensionStateLabel(state.effective, extension)}
        required={extension.required}
        managed={sourceIsManaged(state.effective, extension.extension_id)}
        onOpen={() => openExtension(extension)}
      />)}</div> : hasActiveFilters(effectiveFilters) ? <div className={`${EXTENSION_PANEL_CLASS} mt-4 text-center`}><p className="text-sm font-semibold text-brand-dark">No protections match these filters.</p><button type="button" onClick={() => setFilters(EMPTY_EXTENSION_FILTERS)} className="mt-3 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white">Clear filters</button></div> : <div className={`${EXTENSION_PANEL_CLASS} mt-4 text-center text-sm text-brand-dark/70`}>No protection modules are registered.</div>}
    </section> : null}

    {density === "developer" ? <div className="mt-8"><TechnicalDetails title="Developer policy details"><button type="button" onClick={() => setProvenanceOpen((value) => !value)} aria-expanded={provenanceOpen} className="flex min-h-11 w-full items-center justify-between rounded-xl border border-slate-200 bg-white px-4 text-left text-sm font-semibold text-slate-800"><span>Policy provenance and catalog identity</span>{provenanceOpen ? <HiMiniChevronUp className="size-4" /> : <HiMiniChevronDown className="size-4" />}</button>{provenanceOpen ? <div className="mt-3 grid gap-3 sm:grid-cols-2"><div className="rounded-xl bg-white p-3"><div className="text-xs font-semibold uppercase text-slate-500">Catalog digest</div><code className="mt-1 block break-all text-xs text-slate-700">{state.catalog.catalog_digest}</code></div><div className="rounded-xl bg-white p-3"><div className="text-xs font-semibold uppercase text-slate-500">Authority layers</div><div className="mt-1 text-sm text-slate-700">{state.effective.layers.length} active layer{state.effective.layers.length === 1 ? "" : "s"}</div></div>{state.effective.layers.map((layer) => <div key={`${layer.kind}:${layer.catalog_digest}`} className="rounded-xl bg-white p-3"><div className="flex items-center gap-2"><HiMiniCheckCircle className="size-4 text-emerald-600" /><strong className="text-sm">{layer.kind}</strong></div><p className="mt-1 text-xs text-slate-500">{layer.controls.length} explicit controls</p></div>)}</div> : null}</TechnicalDetails></div> : null}

    {pending ? <ReviewModal change={pending} busy={busy} error={mutationError} approvalGate={resolvedApprovalGate} onCancel={() => { if (!busy) setPending(null); }} onConfirm={confirm} /> : null}
    {recoveryModal}
  </main>;
}
