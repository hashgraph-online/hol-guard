import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniExclamationTriangle,
  HiMiniLockClosed,
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
  type EffectiveExtensionControls,
  type ExtensionCatalogItem,
  type ExtensionCatalogResponse,
  type ExtensionControlLayer,
  type ExtensionMutationPayload,
} from "./extension-controls-api";

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; catalog: ExtensionCatalogResponse; effective: EffectiveExtensionControls };

type PendingChange = { extension: ExtensionCatalogItem; enabled: boolean } | { globalLockdown: boolean };

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

function effectiveState(effective: EffectiveExtensionControls, extension: ExtensionCatalogItem): boolean {
  const control = effective.controls.find(
    (candidate) => candidate.target.kind === "extension" && candidate.target.target_id === extension.extension_id,
  );
  return extension.required || control?.state !== "disabled";
}

function StatusBanner({ effective }: { effective: EffectiveExtensionControls }) {
  if (effective.health === "protected") {
    return (
      <div className="flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
        <HiMiniShieldCheck className="size-5 shrink-0" aria-hidden="true" />
        <span><strong>Protected authority</strong> · revision {effective.revision}</span>
      </div>
    );
  }
  const tampered = effective.health === "tampered";
  return (
    <div className={`rounded-2xl border p-5 ${tampered ? "border-red-200 bg-red-50" : "border-amber-200 bg-amber-50"}`}>
      <div className="flex items-start gap-3">
        <HiMiniExclamationTriangle className={`mt-0.5 size-6 shrink-0 ${tampered ? "text-red-600" : "text-amber-600"}`} aria-hidden="true" />
        <div>
          <h2 className="font-semibold text-slate-950">{tampered ? "Extension controls are locked" : "Finish local enrollment"}</h2>
          <p className="mt-1 text-sm leading-6 text-slate-700">
            {tampered
              ? "Guard detected authority integrity damage. Mutations remain blocked until local recovery completes."
              : "Enrollment requires direct confirmation in the device terminal. The dashboard cannot collect or relay this proof."}
          </p>
          {!tampered ? (
            <code className="mt-3 block w-fit rounded-lg bg-slate-950 px-3 py-2 text-xs text-white">hol-guard guard command controls enroll</code>
          ) : null}
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
      <div className="mt-auto flex items-center justify-between pt-4 text-xs text-slate-500">
        <span>{props.extension.source}</span><span>v{props.extension.version}</span>
      </div>
    </article>
  );
}

function ReviewModal(props: {
  change: PendingChange;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: (password: string, totp: string) => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const passwordInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    passwordInput.current?.focus();
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
    props.onConfirm(password, totp);
  }, [password, props, totp]);
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
        <label className="mt-5 block text-sm font-medium text-slate-700">Approval password<input ref={passwordInput} type="password" autoComplete="current-password" value={password} onChange={handlePasswordChange} className="mt-2 w-full rounded-xl border border-slate-300 px-3 py-2.5 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" /></label>
        <label className="mt-4 block text-sm font-medium text-slate-700">Authenticator code<input inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={handleTotpChange} className="mt-2 w-full rounded-xl border border-slate-300 px-3 py-2.5 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" /></label>
        {props.error ? <p className="mt-4 rounded-xl bg-red-50 px-3 py-2 text-sm text-red-700">{props.error}</p> : null}
        <div className="mt-6 flex justify-end gap-3"><button type="button" onClick={props.onCancel} className="rounded-xl px-4 py-2.5 text-sm font-semibold text-slate-600 hover:bg-slate-100">Cancel</button><button type="submit" disabled={props.busy} className="rounded-xl bg-brand-blue px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:opacity-60">{props.busy ? "Verifying…" : "Confirm change"}</button></div>
      </form>
    </div>
  );
}

export function ExtensionsWorkspace() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [pending, setPending] = useState<PendingChange | null>(null);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [provenanceOpen, setProvenanceOpen] = useState(false);
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
  const sortedExtensions = useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((left, right) => left.name.localeCompare(right.name)) : [], [state]);
  const handleChange = useCallback((change: PendingChange) => { setMutationError(null); setPending(change); }, []);
  const handleCancel = useCallback(() => { if (!busy) setPending(null); }, [busy]);
  const handleConfirm = useCallback(async (password: string, totp: string) => {
    if (state.kind !== "ready" || pending === null) return;
    setBusy(true); setMutationError(null);
    try {
      const payload = buildExtensionMutation(state, pending);
      payload.approval_password = password;
      payload.approval_totp_code = totp;
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
      <div className="mt-6"><StatusBanner effective={state.effective} /></div>
      {state.effective.global_lockdown ? <div className="mt-4 flex items-center gap-3 rounded-2xl bg-slate-950 px-4 py-3 text-sm text-white"><HiMiniLockClosed className="size-5" /><span><strong>Global lockdown active.</strong> Optional extensions remain disabled regardless of individual settings.</span></div> : null}
      <section aria-labelledby="installed-extensions" className="mt-8"><div className="flex items-center justify-between"><h2 id="installed-extensions" className="text-lg font-semibold text-slate-950">Installed extensions</h2><span className="text-sm text-slate-500">{sortedExtensions.length} available</span></div><div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">{sortedExtensions.map((extension) => <ExtensionCard key={extension.extension_id} extension={extension} enabled={effectiveState(state.effective, extension)} locked={locked || state.effective.global_lockdown} onChange={handleChange} />)}</div></section>
      <section className="mt-8 overflow-hidden rounded-3xl border border-slate-200 bg-white"><button type="button" onClick={toggleProvenance} aria-expanded={provenanceOpen} className="flex w-full items-center justify-between p-5 text-left"><span><span className="block font-semibold text-slate-950">Policy provenance</span><span className="mt-1 block text-sm text-slate-500">Catalog {state.catalog.catalog_digest.slice(0, 12)}… · {state.effective.layers.length} authority layer{state.effective.layers.length === 1 ? "" : "s"}</span></span>{provenanceOpen ? <HiMiniChevronUp className="size-5" /> : <HiMiniChevronDown className="size-5" />}</button>{provenanceOpen ? <div className="border-t border-slate-200 p-5"><div className="grid gap-3 sm:grid-cols-2">{state.effective.layers.map((layer: ExtensionControlLayer) => <div key={`${layer.kind}-${layer.catalog_digest}`} className="rounded-2xl bg-slate-50 p-4"><div className="flex items-center gap-2"><HiMiniCheckCircle className="size-5 text-emerald-600" /><strong className="text-sm text-slate-900">{layer.kind === "local-admin" ? "Local administrator" : "Signed cloud policy"}</strong></div><p className="mt-2 text-xs text-slate-500">{layer.controls.length} explicit controls · catalog {layer.catalog_digest.slice(0, 12)}…</p></div>)}</div></div> : null}</section>
      {pending ? <ReviewModal change={pending} busy={busy} error={mutationError} onCancel={handleCancel} onConfirm={handleConfirm} /> : null}
    </main>
  );
}
