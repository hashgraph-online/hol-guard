import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  canonicalExtensionId,
  DEFAULT_EXTENSION_DETAIL_URL_STATE,
  extensionDetailHref,
  readExtensionDetailUrlState,
  type ExtensionDetailUrlState,
} from "../extension-control-center-model";
import { parseProtectionRoute, localCliHref, addCustomExtensionHref, type ProtectionRoute } from "../local-cli-links";
import { AddCustomExtensionWorkspace, LocalCliDetail, useLocalCliCatalog } from "./local-clis-panel";
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
import type { GuardRuntimeSnapshot } from "../guard-types";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { protectionCenterLoadError } from "./copy/protection-copy";
import { ProtectionAuthorityNotice } from "./components/protection-authority-notice";
import { ExtensionsOverview } from "./extensions-overview";
import { pushExtensionHistory, replaceExtensionHistory } from "./extension-navigation";
import { ProtectionModuleDetail } from "./protection-module-detail";
import {
  ExtensionsLoadError,
  ExtensionsLoadingState,
  ExtensionsNotFound,
} from "./protection-workspace-states";
import { deriveProtectionStatus } from "./model/protection-presentation";
import { ReviewModal, type ProtectionPendingChange } from "./protection-change-review";

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; catalog: ExtensionCatalogResponse; effective: EffectiveExtensionControls };

type RouteState = { route: ProtectionRoute; detail: ExtensionDetailUrlState };

export function currentExtensionRouteState(): RouteState {
  return {
    route: parseProtectionRoute(window.location.pathname),
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

export function ProtectionCenterWorkspace(props: {
  runtime?: GuardRuntimeSnapshot | null;
  onRefreshRuntime: () => Promise<GuardRuntimeSnapshot | null>;
  onNavigate: (path: string) => void;
}) {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [routeState, setRouteState] = useState<RouteState>(() => currentExtensionRouteState());
  const [pending, setPending] = useState<ProtectionPendingChange | null>(null);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [recoveryStatus, setRecoveryStatus] = useState<string | null>(null);
  const { resolvedApprovalGate, resolveApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const aliasRedirected = useRef<string | null>(null);
  const overviewKeepAlive = useRef(false);
  const loadInFlightRef = useRef<Promise<EffectiveExtensionControls | null> | null>(null);
  const refreshInFlightRef = useRef<Promise<void> | null>(null);
  const localClis = useLocalCliCatalog();
  const load = useCallback((): Promise<EffectiveExtensionControls | null> => {
    if (loadInFlightRef.current !== null) return loadInFlightRef.current;
    const request = (async (): Promise<EffectiveExtensionControls | null> => {
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
    })();
    loadInFlightRef.current = request;
    void request.then(
      () => { if (loadInFlightRef.current === request) loadInFlightRef.current = null; },
      () => { if (loadInFlightRef.current === request) loadInFlightRef.current = null; },
    );
    return request;
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
    replaceExtensionHistory(extensionDetailHref(canonicalSelected, routeState.detail));
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: routeState.detail });
  }, [canonicalSelected, routeState, state]);

  const openExtension = useCallback((extension: ExtensionCatalogItem) => {
    pushExtensionHistory(extensionDetailHref(extension.extension_id, DEFAULT_EXTENSION_DETAIL_URL_STATE));
    setRouteState({ route: { kind: "detail", extensionId: extension.extension_id }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);

  const closeExtension = useCallback(() => {
    pushExtensionHistory("/extensions");
    setRouteState({ route: { kind: "overview" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const updateExtensionDetailState = useCallback((detail: ExtensionDetailUrlState) => {
    if (!canonicalSelected) return;
    pushExtensionHistory(extensionDetailHref(canonicalSelected, detail));
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail });
  }, [canonicalSelected]);

  const openLocalCliDetail = useCallback((cliId: string) => {
    pushExtensionHistory(localCliHref(cliId));
    setRouteState({ route: { kind: "local-cli", cliId }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const openAddCustom = useCallback(() => {
    pushExtensionHistory(addCustomExtensionHref());
    setRouteState({ route: { kind: "add-custom" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const handleCustomExtensionAdded = useCallback((cliId: string) => {
    void localClis.load();
    openLocalCliDetail(cliId);
  }, [localClis.load, openLocalCliDetail]);

  const retryLocalClis = useCallback(() => { void localClis.load(); }, [localClis.load]);
  const retryLoad = useCallback(() => { void load(); }, [load]);
  const refreshProtection = useCallback((): Promise<void> => {
    if (refreshInFlightRef.current !== null) return refreshInFlightRef.current;
    const request = (async () => {
      const [refreshed, refreshedRuntime] = await Promise.all([load(), props.onRefreshRuntime()]);
      if (refreshed === null || refreshedRuntime === null) {
        throw new Error("Protection status could not be refreshed.");
      }
    })();
    refreshInFlightRef.current = request;
    void request.then(
      () => { if (refreshInFlightRef.current === request) refreshInFlightRef.current = null; },
      () => { if (refreshInFlightRef.current === request) refreshInFlightRef.current = null; },
    );
    return request;
  }, [load, props.onRefreshRuntime]);
  const handleCancelPending = useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);

  const requestChange = useCallback((change: ProtectionPendingChange) => {
    setMutationError(null);
    void resolveApprovalGate({ failClosed: true })
      .then(() => setPending(change))
      .catch(() => setMutationError("Guard could not load local approval settings. Check the local connection and try again."));
  }, [resolveApprovalGate]);

  const handleRequestExtensionChange = useCallback((extension: ExtensionCatalogItem, enabled: boolean) => {
    requestChange({ extension: { extension_id: extension.extension_id, name: extension.name }, enabled });
  }, [requestChange]);

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
      const fresh = await load();
      const wanted = kind === "acknowledge" ? "degraded-acknowledged" : "protected";
      if (fresh && fresh.health === wanted) {
        setRecoveryError(null);
        setRecoveryStatus(kind === "acknowledge"
          ? "The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored."
          : "Local protection repaired and verified.");
      } else if (fresh && startHealth !== null && fresh.health !== startHealth) {
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

  const handleAuthorityAction = useCallback((
    kind: "repair" | "acknowledge",
    credentials: { approval_password?: string; approval_totp_code?: string },
  ) => {
    void runAuthorityAction(kind, credentials);
  }, [runAuthorityAction]);

  const handleCheckAgain = useCallback(async (): Promise<void> => {
    setRecoveryError(null);
    const [protectionResult, approvalResult] = await Promise.allSettled([
      refreshProtection(),
      refreshApprovalGate({ failClosed: true }),
    ]);
    if (approvalResult.status === "rejected") {
      setRecoveryError("Guard could not load the local approval settings yet. Check the connection and try again, or run `hol-guard command controls recover-authority` in your terminal.");
    }
    if (protectionResult.status === "rejected") throw protectionResult.reason;
  }, [refreshApprovalGate, refreshProtection]);

  const handleOpenApprovalSettings = useCallback(() => {
    props.onNavigate("/settings?section=approval");
  }, [props.onNavigate]);

  const authorityNeedsAttention = state.kind === "ready" && state.effective.health !== "protected";
  useEffect(() => {
    if (!authorityNeedsAttention) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setRecoveryError("Guard could not load the local approval settings yet. Check the connection and try again, or run `hol-guard command controls recover-authority` in your terminal.");
    });
  }, [authorityNeedsAttention, resolveApprovalGate]);

  const showOverview = state.kind === "ready" && routeState.route.kind === "overview";
  if (showOverview) overviewKeepAlive.current = true;
  const keepOverviewMounted = state.kind === "ready" && (showOverview || overviewKeepAlive.current);
  const localCliRoute = routeState.route.kind === "local-cli" ? routeState.route : null;
  const selectedLocalCli = localCliRoute
    ? localClis.data?.items.find((item) => item.cli_id === localCliRoute.cliId) ?? null
    : null;
  const showLocalCli = localCliRoute !== null;
  const showDetail = routeState.route.kind === "detail" && selectedExtension !== null;
  const showNotFound = routeState.route.kind === "invalid"
    || (routeState.route.kind === "detail" && selectedExtension === null && state.kind === "ready")
    || (showLocalCli && localClis.data !== null && selectedLocalCli === null);

  const handlePrimaryStatusAction = useCallback(() => {
    requestChange({ globalLockdown: false });
  }, [requestChange]);

  const loadError = state.kind === "error" ? protectionCenterLoadError(state.message) : null;
  const status = state.kind === "ready" ? deriveProtectionStatus(state.effective) : null;
  const healthBroken = state.kind === "ready" && state.effective.health !== "protected";

  return (
    <div className="w-full" data-testid="extensions-workspace">
      {state.kind === "loading" ? <ExtensionsLoadingState label="Loading Extensions" /> : null}
      {state.kind === "error" && loadError ? (
        <ExtensionsLoadError title={loadError.title} detail={loadError.detail} onRetry={retryLoad} />
      ) : null}
      {state.kind === "ready" && healthBroken ? (
        <ProtectionAuthorityNotice
          effective={state.effective}
          busy={recoveryBusy}
          error={recoveryError}
          status={recoveryStatus}
          approvalGate={resolvedApprovalGate}
          onAction={handleAuthorityAction}
          onCheckAgain={handleCheckAgain}
          onOpenApprovalSettings={handleOpenApprovalSettings}
        />
      ) : null}
      {state.kind === "ready" && recoveryStatus && !healthBroken && !showOverview ? (
        <p role="status" className="mb-3 text-sm font-medium text-emerald-800">{recoveryStatus}</p>
      ) : null}
      {keepOverviewMounted && state.kind === "ready" && status ? (
        <ExtensionsOverview
          catalogExtensions={catalogExtensions}
          effective={state.effective}
          localCliItems={localClis.data?.items ?? []}
          localCliError={localClis.error}
          mutationError={mutationError && !pending ? mutationError : null}
          recoveryStatus={recoveryStatus}
          healthBroken={healthBroken}
          status={status}
          active={showOverview}
          onPrimaryStatusAction={handlePrimaryStatusAction}
          onRefresh={refreshProtection}
          onOpenExtension={openExtension}
          onOpenLocalCli={openLocalCliDetail}
          onAddCustom={openAddCustom}
        />
      ) : null}
      {showLocalCli && localClis.error && !localClis.data ? (
        <ExtensionsLoadError
          title="Custom extension unavailable"
          detail={localClis.error}
          onRetry={retryLocalClis}
        />
      ) : null}
      {showLocalCli && localClis.error && localClis.data ? (
        <p role="alert" className="mb-3 text-sm font-medium text-rose-800">{localClis.error}</p>
      ) : null}
      {showLocalCli && !localClis.data && !localClis.error ? (
        <ExtensionsLoadingState label="Loading custom extension" />
      ) : null}
      {routeState.route.kind === "add-custom" && state.kind === "ready" ? (
        <AddCustomExtensionWorkspace
          items={localClis.data?.items ?? []}
          revision={localClis.data?.revision ?? 0}
          onBack={closeExtension}
          onAdded={handleCustomExtensionAdded}
        />
      ) : null}
      {showLocalCli && selectedLocalCli && localClis.data ? (
        <LocalCliDetail
          item={selectedLocalCli}
          revision={localClis.data.revision}
          continuity={localClis.data.cloud}
          onBack={closeExtension}
          onRefresh={localClis.load}
        />
      ) : null}
      {showDetail && selectedExtension && state.kind === "ready" ? (
        <ProtectionModuleDetail
          extension={selectedExtension}
          effective={state.effective}
          catalogDigest={state.catalog.catalog_digest}
          runtime={props.runtime}
          urlState={routeState.detail}
          onUrlState={updateExtensionDetailState}
          onBack={closeExtension}
          onRefresh={refreshProtection}
          onRequestExtensionChange={handleRequestExtensionChange}
        />
      ) : null}
      {showNotFound ? (
        <ExtensionsNotFound
          title={showLocalCli ? "Custom extension not found" : "Extension not found"}
          detail={showLocalCli
            ? "This link does not match a CLI Guard has seen on this device."
            : "This link does not match an extension in the current Guard catalog."}
          onBack={closeExtension}
        />
      ) : null}
      {pending ? (
        <ReviewModal
          change={pending}
          busy={busy}
          error={mutationError}
          approvalGate={resolvedApprovalGate}
          onCancel={handleCancelPending}
          onConfirm={confirm}
        />
      ) : null}
    </div>
  );
}
