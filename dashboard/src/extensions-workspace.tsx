import { useCallback, useEffect, useMemo, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniClipboard,
  HiMiniClipboardDocumentCheck,
  HiMiniExclamationTriangle,
  HiMiniLockClosed,
  HiMiniMagnifyingGlass,
  HiMiniPuzzlePiece,
  HiMiniShieldCheck,
  HiMiniXMark,
} from "react-icons/hi2";

import {
  applyExtensionMutation,
  ExtensionControlApiError,
  fetchEffectiveExtensionControls,
  fetchExtensionCatalog,
  previewExtensionMutation,
  recoverExtensionControlAuthority,
  type EffectiveExtensionControls,
  type ExtensionCatalogItem,
  type ExtensionCatalogResponse,
  type ExtensionControlLayer,
  type ExtensionMutationPayload,
} from "./extension-controls-api";
import { ApprovalProofModal } from "./approval-proof-modal";
import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { useResolvedApprovalGate } from "./use-resolved-approval-gate";
import {
  classifyDomain,
  DOMAIN_LABELS,
  EMPTY_EXTENSION_FILTERS,
  type ExtensionFilterState,
  filterExtensions,
  hasActiveFilters,
  isExtensionEnabled,
  RISK_CLASS_LABELS,
  RISK_CLASS_TONE,
} from "./extensions-filters";
import { ExtensionsFilterBar } from "./extensions-filter-bar";
import { useDebounce } from "./use-debounce";

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; catalog: ExtensionCatalogResponse; effective: EffectiveExtensionControls };

type PendingChange = { extension: ExtensionCatalogItem; enabled: boolean } | { globalLockdown: boolean };

export type ExtensionRecoveryAction = {
  copyLabel: string;
  command: string;
  description: string;
  title: string;
};

export function extensionRecoveryAction(
  health: EffectiveExtensionControls["health"],
): ExtensionRecoveryAction | null {
  if (health === "protected") return null;
  if (health === "tampered") {
    return {
      title: "Repair extension controls",
      copyLabel: "Copy repair command",
      description:
        "Guard locked these settings after detecting damaged authority data. Authenticate on this device to rebuild trusted authority.",
      command: "hol-guard command controls recover-authority",
    };
  }
  return {
    title: "Finish local enrollment",
    copyLabel: "Copy enrollment command",
    description:
      "Authenticate in this device's terminal to protect extension settings, then check again.",
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
  change: PendingChange,
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
    return (
      <div className="flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
        <HiMiniShieldCheck className="size-5 shrink-0" aria-hidden="true" />
        <span><strong>Protected authority</strong> · revision {props.effective.revision}</span>
      </div>
    );
  }
  const tampered = props.effective.health === "tampered";
  return (
    <div className={`rounded-2xl border p-5 ${tampered ? "border-brand-blue/20 bg-brand-blue/[0.04]" : "border-amber-200 bg-amber-50"}`}>
      <div className="flex items-start gap-3">
        <span className="mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-700">
          <HiMiniExclamationTriangle className="size-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="font-semibold text-brand-dark">{recovery?.title}</h2>
          <p className="mt-1 text-sm leading-6 text-slate-700">{recovery?.description}</p>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            {tampered && props.onRecover ? (
              <button type="button" aria-busy={props.busy} disabled={props.busy} onClick={props.onRecover} className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:opacity-60">
                {props.busy ? <HiMiniArrowPath className="size-4 animate-spin" aria-hidden="true" /> : <HiMiniShieldCheck className="size-4" aria-hidden="true" />}
                {props.busy ? "Repairing…" : "Repair now"}
              </button>
            ) : null}
            <button type="button" onClick={props.onRetry} className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50">
              <HiMiniArrowPath className="size-4" aria-hidden="true" />
              Check again
            </button>
          </div>
          <div className="mt-4 border-t border-brand-blue/10 pt-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Command-line fallback</p>
            <div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center">
              <code className="min-w-0 flex-1 overflow-x-auto rounded-lg border border-slate-200 bg-slate-100 px-3 py-2 text-xs text-brand-dark">{recovery?.command}</code>
              <button type="button" onClick={handleCopy} className="inline-flex min-h-10 shrink-0 items-center justify-center gap-2 rounded-lg border border-brand-blue/25 bg-white px-3 py-2 text-sm font-semibold text-brand-blue hover:bg-brand-blue/[0.05]">
                {copyState === "copied" ? <HiMiniClipboardDocumentCheck className="size-4" aria-hidden="true" /> : <HiMiniClipboard className="size-4" aria-hidden="true" />}
                {copyState === "copied" ? "Copied" : recovery?.copyLabel}
              </button>
            </div>
            {copyState === "failed" ? <span role="status" className="mt-2 block text-sm text-brand-attention">Copy failed. Select the command above.</span> : null}
          </div>
          {props.error ? <p role="alert" className="mt-3 text-sm font-medium text-brand-attention">{props.error}</p> : null}
          {props.status ? <p role="status" className="mt-3 text-sm font-medium text-brand-dark">{props.status}</p> : null}
        </div>
      </div>
    </div>
  );
}

function ExtensionCard(props: {
  extension: ExtensionCatalogItem;
  enabled: boolean;
  locked: boolean;
  onChange: (change: PendingChange) => void;
}) {
  const handleChange = useCallback(() => {
    props.onChange({ extension: props.extension, enabled: !props.enabled });
  }, [props]);
  const domain = classifyDomain(props.extension.extension_id);
  const knownRisks = props.extension.risk_classes.filter((risk) => risk in RISK_CLASS_LABELS) as Array<keyof typeof RISK_CLASS_LABELS>;
  return (
    <article className="group flex min-h-52 flex-col rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_rgba(15,23,42,0.05)] transition hover:-translate-y-0.5 hover:border-blue-200 hover:shadow-[0_18px_45px_rgba(30,64,175,0.10)]">
      <div className="flex items-start justify-between gap-4">
        <div className="flex size-11 items-center justify-center rounded-2xl bg-blue-50 text-brand-blue">
          <HiMiniPuzzlePiece className="size-6" aria-hidden="true" />
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={props.enabled}
          aria-label={`${props.enabled ? "Disable" : "Enable"} ${props.extension.name}`}
          disabled={props.locked || props.extension.required}
          onClick={handleChange}
          className={`relative h-7 w-12 rounded-full transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:cursor-not-allowed disabled:opacity-50 ${props.enabled ? "bg-brand-blue" : "bg-slate-300"}`}
        >
          <span className={`absolute top-1 size-5 rounded-full bg-white shadow transition ${props.enabled ? "left-6" : "left-1"}`} />
        </button>
      </div>
      <div className="mt-5 flex items-center gap-2">
        <h2 className="font-semibold text-slate-950">{props.extension.name}</h2>
        {props.extension.required ? <span className="rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-brand-blue">Required</span> : null}
      </div>
      <p className="mt-2 line-clamp-3 text-sm leading-6 text-slate-600">{props.extension.description}</p>
      {knownRisks.length > 0 ? (
        <div className="mt-3 flex flex-wrap gap-1">
          {knownRisks.map((risk) => (
            <span key={risk} className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${RISK_CLASS_TONE[risk].label}`}>
              {RISK_CLASS_LABELS[risk]}
            </span>
          ))}
        </div>
      ) : null}
      <div className="mt-auto flex items-center justify-between gap-2 pt-4 text-xs text-slate-500">
        <span className="truncate">{DOMAIN_LABELS[domain]} · {props.extension.source}</span>
        <span className="shrink-0">v{props.extension.version}</span>
      </div>
    </article>
  );
}

export function ReviewModal(props: {
  change: PendingChange;
  busy: boolean;
  error: string | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !props.busy) {
        props.onCancel();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [props.busy, props.onCancel]);
  const handlePasswordChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotpChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    setTotp(event.target.value);
  }, []);
  const title = "globalLockdown" in props.change
    ? `${props.change.globalLockdown ? "Enable" : "Disable"} global lockdown`
    : `${props.change.enabled ? "Enable" : "Disable"} ${props.change.extension.name}`;
  const handleSubmit = useCallback((event: React.FormEvent) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, {
      approvalPassword: password,
      approvalTotpCode: totp,
    }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(
    props.approvalGate,
    { approvalPassword: password, approvalTotpCode: totp },
    props.busy,
  );
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm" role="presentation">
      <form onSubmit={handleSubmit} role="dialog" aria-modal="true" aria-labelledby="extension-review-title" className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Review control change</p><h2 id="extension-review-title" className="mt-2 text-xl font-semibold text-slate-950">{title}</h2></div>
          <button type="button" onClick={props.onCancel} aria-label="Close review" className="rounded-full p-2 text-slate-500 hover:bg-slate-100"><HiMiniXMark className="size-5" /></button>
        </div>
        <div className="mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-slate-50 p-4 text-sm">
          <span className="text-slate-500">Current</span><span aria-hidden="true">→</span><strong className="text-slate-950">Requested</strong>
          <span>{"globalLockdown" in props.change ? !props.change.globalLockdown ? "Open" : "Locked" : props.change.enabled ? "Disabled" : "Enabled"}</span><span /><span>{"globalLockdown" in props.change ? props.change.globalLockdown ? "Locked" : "Open" : props.change.enabled ? "Enabled" : "Disabled"}</span>
        </div>
        <div className="mt-5">
          <ApprovalProofFieldInputs
            approvalGate={props.approvalGate}
            approvalPassword={password}
            approvalTotpCode={totp}
            onApprovalPasswordChange={handlePasswordChange}
            onApprovalTotpCodeChange={handleTotpChange}
          />
        </div>
        {props.error ? <p className="mt-4 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.06] px-3 py-2 text-sm text-brand-attention">{props.error}</p> : null}
        <div className="mt-6 flex justify-end gap-3"><button type="button" onClick={props.onCancel} className="rounded-xl px-4 py-2.5 text-sm font-semibold text-slate-600 hover:bg-slate-100">Cancel</button><button type="submit" disabled={submitDisabled} className="rounded-xl bg-brand-blue px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:opacity-60">{props.busy ? "Verifying…" : "Confirm change"}</button></div>
      </form>
    </div>
  );
}

export function ExtensionsWorkspace() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [pending, setPending] = useState<PendingChange | null>(null);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [recoveryApprovalOpen, setRecoveryApprovalOpen] = useState(false);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [recoveryStatus, setRecoveryStatus] = useState<string | null>(null);
  const [provenanceOpen, setProvenanceOpen] = useState(false);
  const [filters, setFilters] = useState<ExtensionFilterState>(EMPTY_EXTENSION_FILTERS);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      setState({ kind: "ready", catalog, effective });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Extension controls are unavailable" });
    }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const locked = state.kind !== "ready" || state.effective.health !== "protected";
  const catalogExtensions = useMemo(
    () => (state.kind === "ready" ? [...state.catalog.extensions].sort((left, right) => left.name.localeCompare(right.name)) : []),
    [state],
  );
  const debouncedQuery = useDebounce(filters.query, 120);
  const effectiveFilters = useMemo<ExtensionFilterState>(() => ({ ...filters, query: debouncedQuery }), [filters, debouncedQuery]);
  const filteredExtensions = useMemo(
    () => (state.kind === "ready" ? filterExtensions(catalogExtensions, state.effective, effectiveFilters) : []),
    [catalogExtensions, state, effectiveFilters],
  );
  const updateFilters = useCallback((patch: Partial<ExtensionFilterState>) => {
    setFilters((prev) => ({ ...prev, ...patch }));
  }, []);
  const clearFilters = useCallback(() => setFilters(EMPTY_EXTENSION_FILTERS), []);
  const handleChange = useCallback((change: PendingChange) => {
    setMutationError(null);
    void resolveApprovalGate({ failClosed: true })
      .then(() => setPending(change))
      .catch(() => setMutationError("Guard could not load approval settings. Check the local connection and try again."));
  }, [resolveApprovalGate]);
  const handleCancel = useCallback(() => { if (!busy) setPending(null); }, [busy]);
  const handleConfirm = useCallback(async (credentials: { approval_password?: string; approval_totp_code?: string }) => {
    if (state.kind !== "ready" || pending === null) return;
    setBusy(true); setMutationError(null);
    try {
      const payload = buildExtensionMutation(state, pending);
      Object.assign(payload, credentials);
      payload.session_nonce = randomToken();
      const preview = await previewExtensionMutation(payload);
      if (typeof preview.proof_id !== "string") throw new Error("Guard did not issue a mutation proof");
      payload.proof_id = preview.proof_id;
      await applyExtensionMutation(payload);
      setPending(null);
      await load();
    } catch (error) {
      const recovery = error instanceof ExtensionControlApiError ? error.recoveryAction : undefined;
      setMutationError(`${error instanceof Error ? error.message : "Change failed"}${recovery ? ` · ${recovery}` : ""}`);
    } finally { setBusy(false); }
  }, [load, pending, state]);
  const recoverAuthority = useCallback(async (credentials?: { approval_password?: string; approval_totp_code?: string }) => {
    setRecoveryBusy(true); setRecoveryError(null); setRecoveryStatus("Repairing extension controls…");
    try {
      const effective = await recoverExtensionControlAuthority(credentials);
      if (effective.health !== "protected") throw new Error("Guard could not restore protected extension controls.");
      if (state.kind === "ready") setState({ ...state, effective });
      setRecoveryApprovalOpen(false);
      setRecoveryStatus("Extension controls repaired.");
    } catch (error) {
      if (credentials === undefined && requiresExtensionRecoveryApproval(error)) {
        try {
          await resolveApprovalGate({ failClosed: true });
          setRecoveryApprovalOpen(true);
        } catch {
          setRecoveryError("Guard could not load approval settings. Check the local connection and try again.");
          setRecoveryStatus(null);
        }
      } else {
        setRecoveryError(error instanceof Error ? error.message : "Guard could not repair extension controls.");
        setRecoveryStatus(null);
      }
    } finally { setRecoveryBusy(false); }
  }, [resolveApprovalGate, state]);
  const handleRecover = useCallback(() => { void recoverAuthority(); }, [recoverAuthority]);
  const handleRecoveryConfirm = useCallback((credentials: { approval_password?: string; approval_totp_code?: string }) => {
    void recoverAuthority(credentials);
  }, [recoverAuthority]);
  const handleRecoveryCancel = useCallback(() => { if (!recoveryBusy) setRecoveryApprovalOpen(false); }, [recoveryBusy]);
  const toggleProvenance = useCallback(() => setProvenanceOpen((value) => !value), []);
  const toggleLockdown = useCallback(() => { if (state.kind === "ready") handleChange({ globalLockdown: !state.effective.global_lockdown }); }, [handleChange, state]);

  if (state.kind === "loading") return <main className="grid min-h-[60vh] place-items-center" aria-busy="true"><HiMiniArrowPath className="size-7 animate-spin text-brand-blue" /></main>;
  if (state.kind === "error") return <main className="mx-auto max-w-5xl p-6"><div className="rounded-3xl border border-red-200 bg-red-50 p-6"><h1 className="font-semibold text-red-950">Extensions unavailable</h1><p className="mt-2 text-sm text-red-700">{state.message}</p><button type="button" onClick={load} className="mt-4 rounded-xl bg-red-700 px-4 py-2 text-sm font-semibold text-white">Try again</button></div></main>;

  return (
    <main className="mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
      <header className="flex flex-col gap-5 border-b border-slate-200 pb-7 sm:flex-row sm:items-end sm:justify-between">
        <div><p className="text-xs font-bold uppercase tracking-[0.22em] text-brand-blue">Command safety</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">Extensions</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">Inspect and govern the capabilities Guard uses to understand development commands.</p></div>
        <button type="button" onClick={toggleLockdown} disabled={locked} className={`inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold ${state.effective.global_lockdown ? "bg-red-700 text-white" : "border border-slate-300 bg-white text-slate-700"} disabled:opacity-50`}><HiMiniLockClosed className="size-4" />{state.effective.global_lockdown ? "Disable lockdown" : "Enable lockdown"}</button>
      </header>
      <div className="mt-6"><ExtensionStatusBanner busy={recoveryBusy} effective={state.effective} error={recoveryError} status={recoveryStatus} onRecover={handleRecover} onRetry={load} /></div>
      {mutationError && pending === null ? <p role="alert" className="mt-4 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.06] px-4 py-3 text-sm font-medium text-brand-attention">{mutationError}</p> : null}
      {state.effective.global_lockdown ? <div className="mt-4 flex items-center gap-3 rounded-2xl bg-slate-950 px-4 py-3 text-sm text-white"><HiMiniLockClosed className="size-5" /><span><strong>Global lockdown active.</strong> Optional extensions remain disabled regardless of individual settings.</span></div> : null}
      <section aria-labelledby="installed-extensions" className="mt-8">
        <div className="flex flex-col gap-1">
          <div className="flex items-center justify-between gap-4">
            <h2 id="installed-extensions" className="text-lg font-semibold text-slate-950">Installed extensions</h2>
            <span className="text-sm text-slate-500">{catalogExtensions.length} available</span>
          </div>
          <p className="text-sm text-slate-500">Search by name or command, or filter by risk, domain, or state to govern capabilities.</p>
        </div>
        <div className="mt-4"><ExtensionsFilterBar filters={filters} onChange={updateFilters} onClear={clearFilters} extensions={catalogExtensions} effective={state.effective} /></div>
        {filteredExtensions.length > 0 ? (
          <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {filteredExtensions.map((extension) => (
              <ExtensionCard key={extension.extension_id} extension={extension} enabled={isExtensionEnabled(state.effective, extension)} locked={locked || state.effective.global_lockdown} onChange={handleChange} />
            ))}
          </div>
        ) : hasActiveFilters(effectiveFilters) ? (
          <div className="mt-5 flex flex-col items-center gap-3 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center">
            <HiMiniMagnifyingGlass className="size-7 text-slate-300" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-slate-900">No extensions match these filters</h3>
            <p className="max-w-sm text-sm text-slate-500">Try a different search term, or clear the active filters to see all {catalogExtensions.length} extensions.</p>
            <button type="button" onClick={clearFilters} className="mt-1 rounded-xl bg-brand-blue px-4 py-2 text-sm font-semibold text-white hover:bg-brand-dark">Clear filters</button>
          </div>
        ) : (
          <div className="mt-5 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center text-sm text-slate-500">No extensions are registered.</div>
        )}
      </section>
      <section className="mt-8 overflow-hidden rounded-3xl border border-slate-200 bg-white"><button type="button" onClick={toggleProvenance} aria-expanded={provenanceOpen} className="flex w-full items-center justify-between p-5 text-left"><span><span className="block font-semibold text-slate-950">Policy provenance</span><span className="mt-1 block text-sm text-slate-500">Catalog {state.catalog.catalog_digest.slice(0, 12)}… · {state.effective.layers.length} authority layer{state.effective.layers.length === 1 ? "" : "s"}</span></span>{provenanceOpen ? <HiMiniChevronUp className="size-5" /> : <HiMiniChevronDown className="size-5" />}</button>{provenanceOpen ? <div className="border-t border-slate-200 p-5"><div className="grid gap-3 sm:grid-cols-2">{state.effective.layers.map((layer: ExtensionControlLayer) => <div key={`${layer.kind}-${layer.catalog_digest}`} className="rounded-2xl bg-slate-50 p-4"><div className="flex items-center gap-2"><HiMiniCheckCircle className="size-5 text-emerald-600" /><strong className="text-sm text-slate-900">{layer.kind === "local-admin" ? "Local administrator" : "Signed cloud policy"}</strong></div><p className="mt-2 text-xs text-slate-500">{layer.controls.length} explicit controls · catalog {layer.catalog_digest.slice(0, 12)}…</p></div>)}</div></div> : null}</section>
      {pending ? <ReviewModal change={pending} busy={busy} error={mutationError} approvalGate={resolvedApprovalGate} onCancel={handleCancel} onConfirm={handleConfirm} /> : null}
      {recoveryApprovalOpen ? <ApprovalProofModal title="Repair extension controls" detail="Authenticate this repair on your device. Guard uses the proof once and does not store it." confirmLabel="Repair controls" approvalGate={resolvedApprovalGate} busy={recoveryBusy} error={recoveryError} onCancel={handleRecoveryCancel} onConfirm={handleRecoveryConfirm} /> : null}
    </main>
  );
}
