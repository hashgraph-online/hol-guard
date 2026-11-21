import { useEffect, useMemo, useRef, useState } from "react";
import { fetchLocalCliApi } from "../guard-api";
import type { LocalCliItem } from "../local-cli-api";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { ApprovalProofFieldInputs, buildApprovalProofCredentials, isApprovalProofSubmitDisabled } from "../approval-proof-inline";
import type { LocalCliDiscoveryOutcome } from "./use-local-cli-catalog";
import { isSetupDigest, parseRecentMcpSetups, type RecentMcpSetup } from "./mcp-setup-receipts";

type PackageOption = {
  registry_type: "npm" | "pypi"; identifier: string; version: string;
  command: "npx" | "uvx"; arguments: string[]; transport: "stdio"; verified_package: false;
};
type RegistryEntry = {
  name: string; version: string; title: string; description: string;
  status: "active" | "deprecated" | "unknown";
  remote_endpoints: { url: string; transport: "streamable-http" | "sse" }[];
  package_count: number; package_options: PackageOption[];
  verified_package: false; configured: false; installed: false;
};
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);

async function registrySearch(query: string, signal: AbortSignal): Promise<{
  entries: RegistryEntry[]; moreAvailable: boolean;
}> {
  const response = await fetchLocalCliApi("/v1/local-clis/registry-search", {
    method: "POST", signal, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ search: query }),
  });
  const body: unknown = await response.json();
  if (!response.ok) throw new Error(object(body) && typeof body.message === "string" ? body.message : "Registry search failed.");
  if (!object(body) || body.source !== "official-mcp-registry" || body.coverage !== "search-page"
    || !Array.isArray(body.results) || body.results.length > 20 || typeof body.more_available !== "boolean") {
    throw new Error("Invalid registry response");
  }
  const entries = body.results.map((entry): RegistryEntry => {
    if (!object(entry) || entry.provenance !== "official-mcp-registry" || entry.verified_package !== false
      || entry.configured !== false || entry.installed !== false || !["active", "deprecated", "unknown"].includes(String(entry.status))
      || typeof entry.name !== "string" || entry.name.length > 256
      || typeof entry.title !== "string" || entry.title.length > 120
      || typeof entry.version !== "string" || entry.version.length > 80
      || typeof entry.description !== "string" || entry.description.length > 500
      || !Array.isArray(entry.remote_endpoints) || entry.remote_endpoints.length > 8
      || !Array.isArray(entry.package_options) || entry.package_options.length > 8
      || typeof entry.package_count !== "number" || !Number.isSafeInteger(entry.package_count)
      || entry.package_count < 0 || entry.package_count > 100) {
      throw new Error("Invalid registry provenance");
    }
    const endpoints = entry.remote_endpoints.map((remote) => {
      if (!object(remote) || typeof remote.url !== "string" || !remote.url.startsWith("https://")
        || !["streamable-http", "sse"].includes(String(remote.transport))) throw new Error("Invalid registry endpoint");
      return { url: remote.url, transport: remote.transport as "streamable-http" | "sse" };
    });
    const packages = entry.package_options.map((option): PackageOption => {
      if (!object(option) || !["npm", "pypi"].includes(String(option.registry_type))
        || typeof option.identifier !== "string" || option.identifier.length > 160
        || typeof option.version !== "string" || option.version.length > 80
        || !["npx", "uvx"].includes(String(option.command)) || option.transport !== "stdio"
        || option.verified_package !== false || !Array.isArray(option.arguments)
        || option.arguments.length > (option.registry_type === "pypi" ? 17 : 18)
        || !option.arguments.every((argument) => typeof argument === "string" && argument.length <= 160)) {
        throw new Error("Invalid registry package option");
      }
      return option as PackageOption;
    });
    return { name: entry.name, version: entry.version, title: entry.title, description: entry.description,
      status: entry.status as RegistryEntry["status"], remote_endpoints: endpoints,
      package_count: entry.package_count, package_options: packages,
      verified_package: false, configured: false, installed: false };
  });
  return { entries, moreAvailable: body.more_available };
}

type SetupBase = { host: "codex"; registry_name: string; version: string;
  setup_name: string; selection_digest: string; permissions_granted: false; host_change_applied: false;
  rollback_handle?: string };
type SetupCandidate = (SetupBase & { kind: "remote"; endpoint: string })
  | (SetupBase & { kind: "package"; package_identifier: string; package_version: string;
    command: string; arguments: string[]; verified_package: false });

export function McpRegistrySearch({ items, approvalGate, onOpenChange, onConfigured }: {
  items: LocalCliItem[]; approvalGate: GuardApprovalGatePublicConfig | null;
  onOpenChange: (open: boolean) => void; onConfigured: () => Promise<LocalCliDiscoveryOutcome>;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<RegistryEntry[] | null>(null);
  const [moreAvailable, setMoreAvailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);
  const operation = useRef<"search" | "preview" | "rollback-preview" | "apply" | null>(null);
  const interactionGeneration = useRef(0);
  const historyGeneration = useRef(0);
  const historyController = useRef<AbortController | null>(null);
  const [recent, setRecent] = useState<RecentMcpSetup[]>([]);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyBusy, setHistoryBusy] = useState(false);
  const returnFocus = useRef<HTMLButtonElement | null>(null);
  const [candidate, setCandidate] = useState<SetupCandidate | null>(null);
  const [configured, setConfigured] = useState<{ name: string; kind: "remote" | "package"; removed: boolean } | null>(null);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  useEffect(() => () => { controller.current?.abort(); historyController.current?.abort(); }, []);
  async function loadRecent() {
    historyController.current?.abort();
    const next = new AbortController();
    historyController.current = next;
    const generation = ++historyGeneration.current;
    setHistoryBusy(true); setHistoryError(null);
    try {
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST", signal: next.signal, headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: "recent" }),
      });
      const body: unknown = await response.json();
      if (!response.ok || !object(body)) throw new Error("Recent setup history is unavailable. Retry history.");
      const setups = parseRecentMcpSetups(body.setups);
      if (!next.signal.aborted && historyGeneration.current === generation) setRecent(setups);
    } catch (caught) {
      if (!next.signal.aborted && historyGeneration.current === generation) {
        setHistoryError(caught instanceof Error ? caught.message : "Recent setup history is unavailable. Retry history.");
      }
    } finally {
      if (historyGeneration.current === generation) setHistoryBusy(false);
    }
  }
  function invalidateHistory() {
    historyGeneration.current += 1; historyController.current?.abort(); setHistoryBusy(false);
  }
  async function previewUndo(setup: RecentMcpSetup, button: HTMLButtonElement) {
    if (operation.current) return;
    returnFocus.current = button;
    const generation = ++interactionGeneration.current; operation.current = "rollback-preview";
    const next = new AbortController(); controller.current = next;
    setBusy(true); setError(null); setCandidate(null); setConfigured(null); setPassword(""); setTotp("");
    try {
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: "rollback-preview", rollback_handle: setup.rollback_handle }),
        signal: next.signal,
      });
      const body: unknown = await response.json();
      if (next.signal.aborted || interactionGeneration.current !== generation) return;
      if (!response.ok) {
        if (object(body) && (body.error === "codex_config_changed" || body.code === "codex_config_changed")) void loadRecent();
        throw new Error(object(body) && typeof body.message === "string" ? body.message : "Could not review removal. Review this connection in Codex.");
      }
      if (!object(body) || body.host !== "codex" || body.rollback_handle !== setup.rollback_handle
        || body.setup_name !== setup.setup_name || body.selection_digest !== setup.selection_digest
        || body.registry_name !== setup.registry_name || body.version !== setup.version || body.kind !== setup.kind
        || body.permissions_granted !== false || body.host_change_applied !== false
        || (body.kind === "remote" ? typeof body.endpoint !== "string" || body.endpoint.length > 2048
          : typeof body.command !== "string" || body.command.length > 4096 || !Array.isArray(body.arguments)
            || body.arguments.length > 18 || !body.arguments.every((arg) => typeof arg === "string" && arg.length <= 160)
            || typeof body.package_identifier !== "string" || typeof body.package_version !== "string"
            || body.verified_package !== false)) throw new Error("Could not verify removal. Review this connection in Codex.");
      if (interactionGeneration.current === generation) setCandidate(body as SetupCandidate);
    } catch (caught) {
      if (!next.signal.aborted && interactionGeneration.current === generation) {
        setError(caught instanceof Error ? caught.message : "Could not review removal.");
      }
    }
    finally {
      if (controller.current === next && interactionGeneration.current === generation) {
        controller.current = null; operation.current = null; setBusy(false);
      }
    }
  }
  async function search() {
    if (query.trim().length < 2 || busy || operation.current) return;
    const generation = ++interactionGeneration.current;
    operation.current = "search";
    const next = new AbortController();
    controller.current = next; setBusy(true); setError(null); setEntries(null); setCandidate(null); setConfigured(null);
    try {
      const result = await registrySearch(query, next.signal);
      if (!next.signal.aborted) { setEntries(result.entries); setMoreAvailable(result.moreAvailable); }
    }
    catch (caught) { if (!next.signal.aborted) setError(caught instanceof Error ? caught.message : "Registry unavailable."); }
    finally {
      if (controller.current === next && interactionGeneration.current === generation) {
        controller.current = null; operation.current = null; setBusy(false);
      }
    }
  }
  async function preview(entry: RegistryEntry, target: { endpoint: string } | { packageOption: PackageOption }) {
    if (operation.current) return;
    const generation = ++interactionGeneration.current;
    operation.current = "preview";
    const next = new AbortController(); controller.current = next;
    setBusy(true); setError(null); setCandidate(null); setConfigured(null); setPassword(""); setTotp("");
    const setupName = entry.name.split("/").at(-1)?.toLowerCase().replace(/[^a-z0-9_-]/g, "-") ?? "mcp-server";
    try {
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: "preview", registry_name: entry.name, version: entry.version,
          setup_name: setupName, ...("endpoint" in target ? { kind: "remote", endpoint: target.endpoint }
            : { kind: "package", package_identifier: target.packageOption.identifier,
              package_version: target.packageOption.version }) }),
        signal: next.signal,
      });
      const body: unknown = await response.json();
      if (!response.ok) throw new Error(object(body) && typeof body.message === "string" ? body.message : "Could not review setup.");
      if (!object(body) || body.host !== "codex" || body.registry_name !== entry.name || body.version !== entry.version
        || body.setup_name !== setupName || body.permissions_granted !== false
        || body.host_change_applied !== false || typeof body.selection_digest !== "string"
        || !/^[a-f0-9]{64}$/.test(body.selection_digest)) throw new Error("Invalid Codex setup preview");
      if ("endpoint" in target) {
        if (body.endpoint !== target.endpoint || body.kind !== "remote") throw new Error("Invalid Codex endpoint preview");
      } else if (body.kind !== "package" || body.package_identifier !== target.packageOption.identifier
        || body.package_version !== target.packageOption.version || typeof body.command !== "string"
        || !Array.isArray(body.arguments) || !body.arguments.every((argument) => typeof argument === "string")
        || body.verified_package !== false) throw new Error("Invalid Codex package preview");
      if (!next.signal.aborted && interactionGeneration.current === generation) setCandidate(body as SetupCandidate);
    } catch (caught) {
      if (!next.signal.aborted && interactionGeneration.current === generation) {
        setError(caught instanceof Error ? caught.message : "Could not review setup.");
      }
    }
    finally {
      if (controller.current === next && interactionGeneration.current === generation) {
        controller.current = null; operation.current = null; setBusy(false);
      }
    }
  }
  async function apply() {
    if (!candidate || busy || operation.current || isApprovalProofSubmitDisabled(approvalGate,
      { approvalPassword: password, approvalTotpCode: totp }, false)) return;
    const generation = ++interactionGeneration.current;
    operation.current = "apply";
    setBusy(true); setError(null);
    try {
      const proof = buildApprovalProofCredentials(approvalGate,
        { approvalPassword: password, approvalTotpCode: totp });
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: candidate.rollback_handle ? "rollback" : "apply",
          ...(candidate.rollback_handle ? { rollback_handle: candidate.rollback_handle } : {}), registry_name: candidate.registry_name,
          version: candidate.version, setup_name: candidate.setup_name,
          ...(candidate.kind === "package" ? { kind: "package", package_identifier: candidate.package_identifier,
            package_version: candidate.package_version } : { kind: "remote", endpoint: candidate.endpoint }),
          selection_digest: candidate.selection_digest, confirm_host_change: true,
          session_nonce: crypto.randomUUID().replaceAll("-", ""), ...proof }),
      });
      const body: unknown = await response.json();
      if (!response.ok) {
        if (candidate.rollback_handle && object(body)
          && (body.error === "codex_config_changed" || body.code === "codex_config_changed")) setCandidate(null);
        throw new Error(object(body) && typeof body.message === "string" ? body.message : "Codex setup did not finish.");
      }
      if (!object(body) || body.host !== "codex" || body.setup_name !== candidate.setup_name
        || body.kind !== (candidate.kind === "package" ? "package" : "remote")
        || body.host_change_applied !== true || body.permissions_granted !== false
        || (candidate.rollback_handle ? body.setup_rolled_back !== true : !isSetupDigest(body.rollback_handle))) {
        throw new Error("Codex setup outcome is uncertain. Check recent setup history and review this connection in Codex before retrying.");
      }
      invalidateHistory();
      if (candidate.rollback_handle) setRecent((previous) => previous.filter((setup) => setup.rollback_handle !== candidate.rollback_handle));
      else setRecent((previous) => [{ rollback_handle: body.rollback_handle as string,
        setup_name: candidate.setup_name, kind: candidate.kind, registry_name: candidate.registry_name,
        version: candidate.version, selection_digest: candidate.selection_digest }, ...previous].slice(0, 32));
      void loadRecent();
      setConfigured({ name: candidate.setup_name, kind: candidate.kind, removed: Boolean(candidate.rollback_handle) });
      setCandidate(null); setPassword(""); setTotp("");
      void Promise.resolve().then(onConfigured).then((outcome) => {
        if (outcome === "partial" && interactionGeneration.current === generation) setError("Codex configuration changed, but Guard could not fully rescan host connections. Existing connections remain visible. Retry discovery in Extensions.");
      }).catch(() => {
        if (interactionGeneration.current === generation) setError("Codex configuration changed, but Guard could not fully rescan host connections. Retry discovery in Extensions.");
      });
    } catch (caught) { setPassword(""); setTotp(""); void loadRecent();
      setError(caught instanceof Error ? caught.message : "Codex setup did not finish. Review this connection in Codex before retrying."); }
    finally { operation.current = null; setBusy(false); }
  }
  const setupStatus = useMemo(() => {
    if (!configured) return null;
    const change = configured.removed ? "removed from" : "added to";
    let text = `${configured.name} was ${change} Codex. Restart Codex to load this configuration change.`;
    if (!configured.removed) {
      text += " Complete any provider-owned sign-in there.";
      if (configured.kind === "package") text += " Codex may download and run the pinned package on first use.";
      text += " Review each tool in Extensions after Codex loads it.";
    }
    return `${text} No tool permission was granted.`;
  }, [configured]);
  const setupReviewText = useMemo(() => {
    if (!candidate || candidate.rollback_handle) return null;
    if (candidate.kind === "package") {
      return "This changes Codex configuration. Codex may download and execute this package on first use. It does not authenticate an account or allow tools in Guard.";
    }
    return "This changes Codex configuration. It does not download a package, authenticate an account, activate this session, or allow tools in Guard.";
  }, [candidate]);
  return <details className="mt-6 rounded-2xl border border-slate-200 bg-white p-4" onToggle={(event) => {
    setOpen(event.currentTarget.open);
    onOpenChange(event.currentTarget.open);
    if (event.currentTarget.open) void loadRecent();
    else { invalidateHistory(); if (operation.current !== "apply") {
      controller.current?.abort(); controller.current = null; operation.current = null; setBusy(false);
      interactionGeneration.current += 1; setCandidate(null); setPassword(""); setTotp("");
    } }
  }}>
    <summary className="min-h-11 cursor-pointer py-3 font-semibold text-brand-dark">Find an MCP server in the public registry</summary>
    {open ? <section aria-label="Public MCP registry search">
      <p className="text-sm leading-6 text-brand-dark/75">Search official listing metadata. Review a pinned package or HTTPS endpoint before adding it to Codex.
        A listing does not verify package safety, connect an account, or enable tools. App-owned connections stay in their host.</p>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <label className="block min-w-56 flex-1 text-sm font-semibold text-brand-dark">Server or app name
          <input type="search" minLength={2} maxLength={80} value={query} onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); void search(); } }}
            className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 font-normal" />
        </label>
        <button type="button" onClick={() => { void search(); }} disabled={busy || query.trim().length < 2}
          className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-50">Search registry</button>
      </div>
      {busy ? <p role="status" className="mt-3 text-sm text-brand-dark/75">
        {{ search: "Searching public listings…", preview: "Checking the exact registry listing…",
          "rollback-preview": "Checking the saved setup…",
          apply: candidate?.rollback_handle ? "Removing the reviewed connection from Codex…" : "Adding the reviewed connection to Codex…" }[operation.current ?? "apply"]}
      </p> : null}
      {error ? <p role="alert" className="mt-3 text-sm text-red-700">{error}</p> : null}
      {setupStatus ? <p role="status" className="mt-3 text-sm text-brand-dark">{setupStatus}</p> : null}
      {candidate ? <section aria-label="Review Codex MCP setup" className="mt-4 rounded-xl border border-slate-200 p-4 text-sm text-brand-dark">
        <h3 className="font-semibold">{candidate.rollback_handle ? "Review removal from Codex" : "Review Codex connection"}</h3>
        <p className="mt-2">{candidate.registry_name} · version {candidate.version}</p>
        <p className="mt-1 break-all">Codex name: {candidate.setup_name}</p>
        {candidate.kind === "package" ? <>
          <p className="mt-2">Unverified registry package: {candidate.package_identifier} · pinned version {candidate.package_version}</p>
          <p className="mt-1 break-all font-mono text-xs">Launch: {[candidate.command, ...candidate.arguments].map((part) => JSON.stringify(part)).join(" ")}</p>
        </> : <>
          <p className="mt-1 break-all">HTTPS endpoint: {candidate.endpoint}</p>
        </>}
        {setupReviewText ? <p className="mt-2">{setupReviewText}</p> : null}
        {candidate.rollback_handle ? <p className="mt-2">Remove only the connection added by this setup.
          If Codex configuration has changed since then, Guard leaves it unchanged so you can review it in Codex.
          Removing setup does not revoke provider access or erase Guard tool choices.</p> : null}
        <div className="mt-3 max-w-sm"><ApprovalProofFieldInputs approvalGate={approvalGate}
          approvalPassword={password} approvalTotpCode={totp}
          onApprovalPasswordChange={(event) => setPassword(event.target.value)}
          onApprovalTotpCodeChange={(event) => setTotp(event.target.value.replace(/\D/g, "").slice(0, 6))} /></div>
        <div className="mt-3 flex flex-wrap gap-3">
          <button type="button" disabled={busy || isApprovalProofSubmitDisabled(approvalGate,
            { approvalPassword: password, approvalTotpCode: totp }, false)} onClick={() => { void apply(); }}
            className="min-h-11 rounded-xl bg-brand-blue px-4 font-semibold text-white disabled:opacity-50">{candidate.rollback_handle ? "Remove from Codex" : "Add to Codex"}</button>
          <button type="button" disabled={busy} onClick={() => { setCandidate(null); setPassword(""); setTotp(""); returnFocus.current?.focus(); }}
            className="min-h-11 rounded-xl border border-slate-300 px-4 font-semibold">Cancel</button>
        </div>
      </section> : null}
      <section aria-label="Recent MCP setup" className="mt-4 border-t border-slate-200 pt-4 text-sm text-brand-dark">
        <h3 className="font-semibold">Recent setup</h3>
        <p className="mt-1 text-brand-dark/75">Undo is available for up to an hour while this Guard runtime stays open.
          For older or changed connections, review configuration in Codex.</p>
        {historyBusy ? <p role="status" className="mt-2">Loading recent setup…</p> : null}
        {historyError ? <div className="mt-2"><p role="alert" className="text-red-700">{historyError}</p>
          <button type="button" disabled={historyBusy || busy} onClick={() => { void loadRecent(); }}
            className="mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold">Retry history</button></div> : null}
        {!historyBusy && !historyError && !recent.length ? <p className="mt-2 text-brand-dark/75">No setup available to undo in this runtime.</p> : null}
        {recent.length ? <ul className="mt-2 divide-y divide-slate-200">{recent.map((setup) => <li key={setup.rollback_handle}
          className="flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0 flex-1"><p className="break-all font-semibold">{setup.setup_name}</p>
            <p className="break-all text-brand-dark/75">{setup.registry_name} · {setup.version}</p>
            {setup.rollback_available === false ? <p className="mt-1 text-brand-dark/75">Configuration changed. Review this connection in Codex.</p> : null}</div>
          <button type="button" disabled={busy || setup.rollback_available === false} onClick={(event) => { void previewUndo(setup, event.currentTarget); }}
            aria-label={`Undo setup for ${setup.setup_name}`} className="min-h-11 rounded-xl border border-slate-300 px-4 font-semibold disabled:opacity-50">Undo setup</button>
        </li>)}</ul> : null}
      </section>
      {entries?.length === 0 ? <p className="mt-3 text-sm text-brand-dark/75">No listing on this search page. Try another name.</p> : null}
      {moreAvailable && entries ? <p className="mt-3 text-sm text-brand-dark/75">
        More listings match. Refine the name to find a specific server; this page is not the complete registry.
      </p> : null}
      {entries ? <ul className="mt-4 divide-y divide-slate-200">{entries.map((entry) => {
        const basename = entry.name.split("/").at(-1)?.toLowerCase();
        const possibleExisting = items.some((item) => item.surface === "mcp"
          && (item.name.toLowerCase() === entry.title.toLowerCase() || item.name.toLowerCase() === basename));
        return <li key={`${entry.name}/${entry.version}`} className="py-4 text-sm text-brand-dark">
          <p className="font-semibold">{entry.title} · {entry.version}</p>
          <p className="mt-1 text-brand-dark/75">{entry.description}</p>
          <p className="mt-2 break-all text-xs text-brand-dark/75">{entry.name}</p>
          <p className="mt-2 text-xs text-brand-dark/75">{entry.status} listing · {entry.remote_endpoints.length} HTTPS endpoint(s)
            · {entry.package_options.length} reviewed launch option(s) of {entry.package_count} package listing(s) · Packages unverified</p>
          {possibleExisting ? <p className="mt-2 text-xs font-semibold text-brand-dark">Possible existing connection. Inspect it before adding another.</p> : null}
          {entry.status === "active" && !possibleExisting && entry.remote_endpoints.some((remote) => remote.transport === "streamable-http")
            ? <button type="button" disabled={busy} onClick={() => {
              const endpoint = entry.remote_endpoints.find((remote) => remote.transport === "streamable-http");
              if (endpoint) void preview(entry, { endpoint: endpoint.url });
            }} className="mt-3 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark">
              Review HTTPS setup</button> : null}
          {entry.status === "active" && !possibleExisting ? entry.package_options.map((option) =>
            <button type="button" key={`${option.registry_type}/${option.identifier}/${option.version}`} disabled={busy}
              onClick={() => { void preview(entry, { packageOption: option }); }}
              className="ml-2 mt-3 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark">
              Review {option.registry_type} package · {option.identifier}@{option.version}
            </button>) : null}
        </li>;
      })}</ul> : null}
    </section> : null}
  </details>;
}
