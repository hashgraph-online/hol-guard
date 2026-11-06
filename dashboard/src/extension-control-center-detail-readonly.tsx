import { useMemo } from "react";
import {
  HiMiniArrowLeft,
  HiMiniArrowTopRightOnSquare,
  HiMiniChevronRight,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniLockClosed,
  HiMiniShieldCheck,
  HiMiniXMark,
} from "react-icons/hi2";

import type {
  EffectiveExtensionControls,
  ExtensionCatalogItem,
  ExtensionPermission,
  ExtensionRule,
} from "./extension-controls-api";
import {
  controlProvenance,
  extensionEffectiveState,
  extensionStateLabel,
  filterDetailPermissions,
  filterDetailRules,
  permissionEffectiveState,
  permissionForRule,
  permissionRelations,
  permissionStateLabel,
  treatmentLabel,
  type ExtensionDetailTab,
  type ExtensionDetailUrlState,
} from "./extension-control-center-model";
import { useModalDialog } from "./use-modal-dialog";

const RISK_TONE: Record<string, string> = {
  critical: "border-red-200 bg-red-50 text-red-800",
  high: "border-orange-200 bg-orange-50 text-orange-800",
  medium: "border-amber-200 bg-amber-50 text-amber-800",
  low: "border-slate-200 bg-slate-50 text-slate-700",
};

const TABS: Array<{ id: ExtensionDetailTab; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "commands", label: "Commands & rules" },
  { id: "policy", label: "Policy" },
];

function Pill({ children, tone = "border-slate-200 bg-slate-50 text-slate-700" }: { children: React.ReactNode; tone?: string }) {
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${tone}`}>{children}</span>;
}

function Definition({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</dt><dd className="mt-1 break-words text-sm text-slate-900">{children}</dd></div>;
}

function ListValue({ values, empty = "None" }: { values: string[]; empty?: string }) {
  return values.length ? <span>{values.join(", ")}</span> : <span className="text-slate-500">{empty}</span>;
}

function safeReferenceUrl(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}

function DetailFilters(props: { state: ExtensionDetailUrlState; onChange: (state: ExtensionDetailUrlState) => void }) {
  const patch = <K extends keyof ExtensionDetailUrlState>(key: K, value: ExtensionDetailUrlState[K]) => props.onChange({ ...props.state, [key]: value, ruleId: null });
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4" aria-label="Command and permission filters">
      <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500">Search
        <input value={props.state.query} onChange={(event) => patch("query", event.target.value.slice(0, 160))} placeholder="Rule, permission, capability…" className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 text-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" />
      </label>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <label className="text-xs font-semibold text-slate-600">Risk<select value={props.state.risk} onChange={(event) => patch("risk", event.target.value as ExtensionDetailUrlState["risk"])} className="mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm"><option value="all">All risk</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
        <label className="text-xs font-semibold text-slate-600">Effective state<select value={props.state.state} onChange={(event) => patch("state", event.target.value as ExtensionDetailUrlState["state"])} className="mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm"><option value="all">All states</option><option value="allowed">Allowed</option><option value="blocked">Blocked</option></select></label>
        <label className="text-xs font-semibold text-slate-600">Configurable<select value={props.state.configurable} onChange={(event) => patch("configurable", event.target.value as ExtensionDetailUrlState["configurable"])} className="mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm"><option value="all">All</option><option value="yes">Configurable</option><option value="no">Fixed</option></select></label>
        <label className="text-xs font-semibold text-slate-600">Source<select value={props.state.source} onChange={(event) => patch("source", event.target.value as ExtensionDetailUrlState["source"])} className="mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm"><option value="all">All sources</option><option value="built-in">Built in</option><option value="local-admin">Local admin</option><option value="signed-cloud">Signed cloud</option></select></label>
        <label className="text-xs font-semibold text-slate-600">Deprecation<select value={props.state.deprecated} onChange={(event) => patch("deprecated", event.target.value as ExtensionDetailUrlState["deprecated"])} className="mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm"><option value="all">All</option><option value="no">Current</option><option value="yes">Deprecated</option></select></label>
        <label className="text-xs font-semibold text-slate-600">Type<select value={props.state.type} onChange={(event) => patch("type", event.target.value as ExtensionDetailUrlState["type"])} className="mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm"><option value="all">Rules & permissions</option><option value="rule">Rules only</option><option value="permission">Permissions only</option></select></label>
        <label className="text-xs font-semibold text-slate-600">Sort<select value={props.state.sort} onChange={(event) => patch("sort", event.target.value as ExtensionDetailUrlState["sort"])} className="mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm"><option value="name">Name</option><option value="risk">Risk</option><option value="id">Canonical ID</option></select></label>
        <button type="button" onClick={() => props.onChange({ ...props.state, query: "", risk: "all", state: "all", configurable: "all", source: "all", deprecated: "all", type: "all", sort: "name", ruleId: null })} className="min-h-11 self-end rounded-xl border border-slate-300 bg-white px-3 text-sm font-semibold text-slate-700 hover:bg-slate-50">Clear filters</button>
      </div>
    </div>
  );
}

function PermissionInspector(props: { effective: EffectiveExtensionControls; extension: ExtensionCatalogItem; permission: ExtensionPermission; onClose: () => void }) {
  const dialogRef = useModalDialog<HTMLElement>(props.onClose);
  const relations = permissionRelations(props.extension, props.permission);
  const effectiveState = permissionEffectiveState(props.effective, props.extension, props.permission);
  return (
    <aside ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="permission-inspector-title" className="fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-5 shadow-2xl focus:outline-none sm:p-6">
      <div className="flex items-start justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Permission</p><h2 id="permission-inspector-title" className="mt-2 text-2xl font-semibold text-slate-950">{props.permission.label}</h2><code className="mt-2 block break-all text-xs text-slate-500">{props.permission.permission_id}</code></div><button type="button" onClick={props.onClose} aria-label="Close permission details" className="grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100"><HiMiniXMark className="size-5" /></button></div>
      <p className="mt-5 text-sm leading-6 text-slate-600">{props.permission.description}</p>
      <div className="mt-5 flex flex-wrap gap-2"><Pill tone={RISK_TONE[props.permission.risk_tier]}>{props.permission.risk_tier} baseline risk</Pill><Pill>{permissionStateLabel(props.effective, props.extension, props.permission)}</Pill>{!props.permission.configurable ? <Pill>Fixed</Pill> : null}{props.permission.deprecated ? <Pill tone="border-amber-200 bg-amber-50 text-amber-800">Deprecated</Pill> : null}</div>
      <section className="mt-7 rounded-2xl border border-slate-200 bg-slate-50 p-5"><h3 className="font-semibold text-slate-950">Baseline and effective behavior</h3><dl className="mt-4 grid gap-4 sm:grid-cols-2"><Definition label="Baseline floor">{treatmentLabel(props.permission.baseline_floor)}</Definition><Definition label="Default">{props.permission.default_enabled ? "Allowed" : "Blocked"}</Definition><Definition label="Effective">{effectiveState === "enabled" ? "Allowed" : "Blocked"}</Definition><Definition label="Provenance">{controlProvenance(props.effective, "permission", props.permission.permission_id).join(" · ")}</Definition></dl></section>
      <section className="mt-7"><h3 className="font-semibold text-slate-950">Capabilities and ownership</h3><dl className="mt-4 grid gap-4 sm:grid-cols-2"><Definition label="Action classes"><ListValue values={props.permission.action_classes} /></Definition><Definition label="Typed capabilities"><ListValue values={props.permission.typed_capabilities} empty="Rule-derived" /></Definition><Definition label="Governed rule IDs"><ListValue values={props.permission.rule_ids} /></Definition><Definition label="Introduced">{props.permission.introduced_version}</Definition></dl>{props.permission.rule_ids.length > 1 ? <p className="mt-4 rounded-xl bg-blue-50 p-3 text-sm text-slate-700">This permission governs {props.permission.rule_ids.length} rules. A future policy change to this permission affects every governed rule.</p> : null}</section>
      <section className="mt-7"><h3 className="font-semibold text-slate-950">Relationships</h3><dl className="mt-4 grid gap-4 sm:grid-cols-2"><Definition label="Depends on">{relations.dependencies.length ? relations.dependencies.map((item) => item.label).join(", ") : "None"}</Definition><Definition label="Conflicts with">{relations.conflicts.length ? relations.conflicts.map((item) => item.label).join(", ") : "None"}</Definition><Definition label="Implies">{relations.implied.length ? relations.implied.map((item) => item.label).join(", ") : "None"}</Definition><Definition label="Replacement">{props.permission.replacement_permission_id ?? "None"}</Definition></dl></section>
      <section className="mt-7"><h3 className="font-semibold text-slate-950">Safer guidance</h3>{props.permission.safer_guidance.length ? <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600">{props.permission.safer_guidance.map((item) => <li key={item}>{item}</li>)}</ul> : <p className="mt-2 text-sm text-slate-500">No alternate workflow is registered.</p>}{!props.permission.configurable ? <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700"><strong>Why this cannot be changed:</strong> {props.permission.fixed_reason ?? "Guard marks this capability as fixed."}</p> : null}</section>
    </aside>
  );
}

function RuleInspector(props: { extension: ExtensionCatalogItem; rule: ExtensionRule; onClose: () => void; onTest: () => void }) {
  const dialogRef = useModalDialog<HTMLElement>(props.onClose);
  const permission = permissionForRule(props.extension, props.rule);
  return (
    <aside ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="rule-inspector-title" className="fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-5 shadow-2xl focus:outline-none sm:p-6">
      <div className="flex items-start justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Command rule</p><h2 id="rule-inspector-title" className="mt-2 text-2xl font-semibold text-slate-950">{props.rule.title}</h2><code className="mt-2 block break-all text-xs text-slate-500">{props.rule.rule_id}</code></div><button type="button" onClick={props.onClose} aria-label="Close rule details" className="grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100"><HiMiniXMark className="size-5" /></button></div>
      <p className="mt-5 text-sm leading-6 text-slate-600">{props.rule.description}</p><div className="mt-5 flex flex-wrap gap-2"><Pill tone={RISK_TONE[props.rule.severity]}>{props.rule.severity} detector severity</Pill><Pill>{treatmentLabel(props.rule.default_mode)} default</Pill><Pill>{props.rule.matcher_kind}</Pill></div>
      <dl className="mt-7 grid gap-5 sm:grid-cols-2"><Definition label="Governing permission">{permission?.label ?? "Compatibility mapping"}</Definition><Definition label="Permission ID">{permission?.permission_id ?? "None"}</Definition><Definition label="Rule version">{String(props.rule.rule_version)}</Definition><Definition label="Risk classes"><ListValue values={props.rule.risk_classes} /></Definition><Definition label="Action classes"><ListValue values={props.rule.action_classes} /></Definition><Definition label="Matcher kind">{props.rule.matcher_kind}</Definition></dl>
      <section className="mt-7"><h3 className="font-semibold text-slate-950">Safe variants</h3>{props.rule.safe_variants.length ? <div className="mt-3 space-y-2">{props.rule.safe_variants.map((variant) => <div key={variant.variant_id} className="rounded-xl border border-slate-200 p-3"><div className="text-sm font-medium text-slate-900">{variant.title}</div><div className="mt-1 text-xs text-slate-500">{variant.matcher_kind} · {variant.variant_id}</div></div>)}</div> : <p className="mt-2 text-sm text-slate-500">No explicit safe variants are registered.</p>}</section>
      <section className="mt-7"><h3 className="font-semibold text-slate-950">Safer alternatives</h3>{props.rule.safer_alternatives.length ? <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600">{props.rule.safer_alternatives.map((item) => <li key={item}>{item}</li>)}</ul> : <p className="mt-2 text-sm text-slate-500">No alternate workflow is registered.</p>}</section>
      {props.rule.compatibility_fallback ? <div className="mt-7 flex gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900"><HiMiniExclamationTriangle className="mt-0.5 size-5 shrink-0" /><span>This compatibility fallback is still a canonical detector rule and retains its baseline facts.</span></div> : null}

    </aside>
  );
}

export function ExtensionControlCenterDetail(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  catalogDigest: string;
  urlState: ExtensionDetailUrlState;
  onUrlState: (state: ExtensionDetailUrlState) => void;
  onBack: () => void;
  onBroadControl?: () => void;
  externalPolicyPanelId?: string;
}) {
  const extensionState = extensionEffectiveState(props.effective, props.extension);
  const stateLabel = extensionStateLabel(props.effective, props.extension);
  const provenance = controlProvenance(props.effective, "extension", props.extension.extension_id);
  const permissions = useMemo(() => filterDetailPermissions(props.extension, props.effective, props.urlState), [props.extension, props.effective, props.urlState]);
  const rules = useMemo(() => filterDetailRules(props.extension, props.effective, props.urlState), [props.extension, props.effective, props.urlState]);
  const selectedRule = props.urlState.ruleId ? props.extension.rules.find((item) => item.rule_id === props.urlState.ruleId) ?? null : null;
  const selectedPermission = props.urlState.ruleId?.includes(".permission.") ? props.extension.permissions.find((item) => item.permission_id === props.urlState.ruleId) ?? null : null;
  const activeTab: ExtensionDetailTab = TABS.some((item) => item.id === props.urlState.tab) ? props.urlState.tab : "overview";
  const setTab = (tab: ExtensionDetailTab) => props.onUrlState({ ...props.urlState, tab, ruleId: tab === "commands" ? props.urlState.ruleId : null });
  const handleTabKey = (event: React.KeyboardEvent<HTMLButtonElement>, tab: ExtensionDetailTab) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight" && event.key !== "Home" && event.key !== "End") return;
    event.preventDefault();
    const current = TABS.findIndex((item) => item.id === tab);
    const next = event.key === "Home" ? 0 : event.key === "End" ? TABS.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + TABS.length) % TABS.length;
    setTab(TABS[next]!.id);
    requestAnimationFrame(() => document.getElementById(`extension-tab-${TABS[next]!.id}`)?.focus());
  };

  return (
    <main data-testid="extension-control-center-detail" className="mx-auto w-full max-w-7xl px-4 pb-10 pt-5 sm:px-6 lg:px-8">
      <nav aria-label="Breadcrumb"><button type="button" onClick={props.onBack} className="inline-flex min-h-11 items-center gap-2 rounded-lg px-2 text-sm font-semibold text-slate-600 hover:bg-slate-100 hover:text-brand-blue"><HiMiniArrowLeft className="size-4" />Protections</button></nav>
      <header className="mt-3 rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_rgba(15,23,42,0.05)] sm:p-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between"><div className="min-w-0"><p className="text-xs font-bold uppercase tracking-[0.2em] text-brand-blue">Extension control center</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">{props.extension.name}</h1><code className="mt-2 block break-all text-xs text-slate-500">{props.extension.extension_id}</code><p className="mt-4 max-w-3xl text-sm leading-6 text-slate-600">{props.extension.description}</p></div><div className="flex flex-wrap gap-2"><Pill tone={extensionState === "enabled" ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-slate-300 bg-slate-100 text-slate-700"}>{stateLabel}</Pill><Pill>{props.extension.required ? "Required" : "Optional"}</Pill><Pill>{props.extension.source}</Pill><Pill>v{props.extension.version}</Pill></div></div>
        <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><div className="rounded-2xl bg-slate-50 p-4"><div className="text-xs font-semibold uppercase text-slate-500">Authority</div><div className="mt-1 font-semibold text-slate-950">{props.effective.health}</div></div><div className="rounded-2xl bg-slate-50 p-4"><div className="text-2xl font-semibold text-slate-950">{props.extension.permission_count}</div><div className="text-xs text-slate-500">Permissions</div></div><div className="rounded-2xl bg-slate-50 p-4"><div className="text-2xl font-semibold text-slate-950">{props.extension.rule_count}</div><div className="text-xs text-slate-500">Rules</div></div><div className="rounded-2xl bg-slate-50 p-4"><div className="text-xs font-semibold uppercase text-slate-500">Provenance</div><div className="mt-1 text-sm font-semibold text-slate-950">{provenance.join(" · ")}</div></div></div>
        {props.effective.global_lockdown ? <div role="status" className="mt-5 flex gap-3 rounded-xl border border-slate-300 bg-slate-100 p-4 text-sm text-slate-800"><HiMiniLockClosed className="mt-0.5 size-5 shrink-0" /><span><strong>Global lockdown controls this capability.</strong> Matching actions remain blocked regardless of optional local settings.</span></div> : null}
        {props.onBroadControl && !props.extension.required && props.effective.health === "protected" ? <button type="button" onClick={props.onBroadControl} className="mt-5 min-h-11 rounded-xl border border-brand-blue/25 bg-white px-4 text-sm font-semibold text-brand-blue hover:bg-blue-50">Review broad capability control</button> : null}
      </header>

      <div className="mt-6 overflow-x-auto border-b border-slate-200" role="tablist" aria-label="Extension detail sections">{TABS.map((item) => <button id={`extension-tab-${item.id}`} key={item.id} type="button" role="tab" aria-selected={activeTab === item.id} aria-controls={item.id === "policy" && props.externalPolicyPanelId ? props.externalPolicyPanelId : `extension-panel-${item.id}`} onKeyDown={(event) => handleTabKey(event, item.id)} onClick={() => setTab(item.id)} className={`min-h-11 border-b-2 px-4 py-3 text-sm font-semibold whitespace-nowrap focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${activeTab === item.id ? "border-brand-blue text-brand-blue" : "border-transparent text-slate-500 hover:text-slate-900"}`}>{item.label}</button>)}</div>

      {activeTab !== props.urlState.tab ? <p role="status" className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">This older link points to a section that is not available in this build. Showing Overview instead.</p> : null}

      {activeTab === "overview" ? <section id="extension-panel-overview" role="tabpanel" aria-labelledby="extension-tab-overview" className="mt-6 grid gap-5 lg:grid-cols-2">
        <article className="rounded-3xl border border-slate-200 bg-white p-5"><div className="flex items-center gap-2"><HiMiniShieldCheck className="size-5 text-brand-blue" /><h2 className="font-semibold text-slate-950">Canonical coverage</h2></div><dl className="mt-5 grid gap-4 sm:grid-cols-2"><Definition label="Action classes"><ListValue values={props.extension.action_classes} /></Definition><Definition label="Risk classes"><ListValue values={props.extension.risk_classes} /></Definition><Definition label="Executables"><ListValue values={props.extension.executables} empty="Registry matcher metadata" /></Definition><Definition label="Project markers"><ListValue values={props.extension.project_markers} /></Definition><Definition label="Ecosystems"><ListValue values={props.extension.ecosystem_ids} /></Definition><Definition label="Aliases"><ListValue values={props.extension.aliases} /></Definition></dl></article>
        <article className="rounded-3xl border border-slate-200 bg-white p-5"><h2 className="font-semibold text-slate-950">Relationships and provenance</h2><dl className="mt-5 grid gap-4 sm:grid-cols-2"><Definition label="Depends on"><ListValue values={props.extension.dependencies} /></Definition><Definition label="Conflicts with"><ListValue values={props.extension.conflicts} /></Definition><Definition label="Delegated protection">{props.extension.delegated_protection ?? "None"}</Definition><Definition label="Catalog digest"><code className="break-all text-xs">{props.catalogDigest}</code></Definition><Definition label="Effective state">{stateLabel}</Definition><Definition label="Policy provenance">{provenance.join(" · ")}</Definition></dl></article>
        <article className="rounded-3xl border border-slate-200 bg-white p-5 lg:col-span-2"><h2 className="font-semibold text-slate-950">Safer alternatives</h2>{props.extension.safer_alternatives.length ? <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600">{props.extension.safer_alternatives.map((item) => <li key={item}>{item}</li>)}</ul> : <p className="mt-2 text-sm text-slate-500">No extension-level alternative is registered.</p>}{props.extension.reference_urls.length ? <div className="mt-5 border-t border-slate-100 pt-4"><h3 className="text-sm font-semibold text-slate-900">References</h3><div className="mt-2 flex flex-wrap gap-2">{props.extension.reference_urls.map((value) => { const href = safeReferenceUrl(value); return href ? <a key={value} href={href} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer" className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-3 text-sm font-semibold text-brand-blue">Open reference <HiMiniArrowTopRightOnSquare className="size-4" /></a> : null; })}</div></div> : null}</article>
      </section> : null}

      {activeTab === "commands" ? <section id="extension-panel-commands" role="tabpanel" aria-labelledby="extension-tab-commands" className="mt-6"><DetailFilters state={props.urlState} onChange={props.onUrlState} /><div role="status" aria-live="polite" className="mt-3 text-sm text-slate-500">Showing {permissions.length} permissions and {rules.length} rules.</div>
        {props.urlState.type !== "rule" ? <div className="mt-6"><h2 className="text-lg font-semibold text-slate-950">Permissions</h2><div className="mt-3 grid gap-3 lg:grid-cols-2">{permissions.map((permission) => <button key={permission.permission_id} type="button" onClick={() => props.onUrlState({ ...props.urlState, ruleId: permission.permission_id })} className="min-h-11 rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-blue-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"><div className="flex flex-wrap items-center gap-2"><span className="font-semibold text-slate-950">{permission.label}</span><Pill tone={RISK_TONE[permission.risk_tier]}>{permission.risk_tier}</Pill><Pill>{permissionStateLabel(props.effective, props.extension, permission)}</Pill>{!permission.configurable ? <Pill>Fixed</Pill> : null}</div><p className="mt-2 text-sm text-slate-600">{permission.description}</p><div className="mt-2 text-xs text-slate-500">Baseline floor {treatmentLabel(permission.baseline_floor)} · {permission.rule_ids.length} governed rule{permission.rule_ids.length === 1 ? "" : "s"}</div><code className="mt-1 block break-all text-[11px] text-slate-400">{permission.permission_id}</code></button>)}</div>{permissions.length === 0 ? <div className="mt-3 rounded-2xl border border-dashed border-slate-300 p-6 text-sm text-slate-500">No permissions match these filters.</div> : null}</div> : null}
        {props.urlState.type !== "permission" ? <div className="mt-8"><h2 className="text-lg font-semibold text-slate-950">Commands and rules</h2><div className="mt-3 hidden overflow-x-auto rounded-2xl border border-slate-200 bg-white md:block"><table className="min-w-full text-left text-sm"><thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-4 py-3">State</th><th className="px-4 py-3">Rule</th><th className="px-4 py-3">Severity / default</th><th className="px-4 py-3">Matcher</th><th className="px-4 py-3">Permission</th><th className="px-4 py-3"><span className="sr-only">Open</span></th></tr></thead><tbody className="divide-y divide-slate-100">{rules.map((rule) => { const permission = permissionForRule(props.extension, rule); const allowed = permission ? permissionEffectiveState(props.effective, props.extension, permission) === "enabled" : extensionState === "enabled"; return <tr key={rule.rule_id}><td className="px-4 py-3 font-semibold text-slate-700">{allowed ? "Allowed" : "Blocked"}</td><td className="max-w-md px-4 py-3"><div className="font-semibold text-slate-950">{rule.title}</div><code className="text-[11px] text-slate-500">{rule.rule_id}</code></td><td className="px-4 py-3"><Pill tone={RISK_TONE[rule.severity]}>{rule.severity}</Pill><div className="mt-1 text-xs text-slate-500">{treatmentLabel(rule.default_mode)}</div></td><td className="px-4 py-3 text-slate-600">{rule.matcher_kind}</td><td className="px-4 py-3 text-slate-600">{permission?.label ?? "Compatibility"}</td><td className="px-4 py-3"><button type="button" aria-label={`Inspect rule ${rule.title}`} onClick={() => props.onUrlState({ ...props.urlState, ruleId: rule.rule_id })} className="grid size-11 place-items-center rounded-xl text-brand-blue hover:bg-blue-50"><HiMiniChevronRight className="size-5" /></button></td></tr>; })}</tbody></table></div><div className="mt-3 grid gap-3 md:hidden">{rules.map((rule) => { const permission = permissionForRule(props.extension, rule); const allowed = permission ? permissionEffectiveState(props.effective, props.extension, permission) === "enabled" : extensionState === "enabled"; return <button type="button" key={rule.rule_id} onClick={() => props.onUrlState({ ...props.urlState, ruleId: rule.rule_id })} className="rounded-2xl border border-slate-200 bg-white p-4 text-left"><div className="flex flex-wrap gap-2"><Pill>{allowed ? "Allowed" : "Blocked"}</Pill><Pill tone={RISK_TONE[rule.severity]}>{rule.severity}</Pill></div><div className="mt-2 font-semibold text-slate-950">{rule.title}</div><code className="mt-1 block break-all text-[11px] text-slate-500">{rule.rule_id}</code><div className="mt-2 text-xs text-slate-500">{rule.matcher_kind} · {permission?.label ?? "Compatibility"}</div></button>; })}</div>{rules.length === 0 ? <div className="mt-3 rounded-2xl border border-dashed border-slate-300 p-6 text-sm text-slate-500">No rules match these filters.</div> : null}</div> : null}
      </section> : null}

      {activeTab === "policy" && !props.externalPolicyPanelId ? <section id="extension-panel-policy" role="tabpanel" aria-labelledby="extension-tab-policy" className="mt-6 rounded-3xl border border-slate-200 bg-white p-6"><h2 className="text-lg font-semibold text-slate-950">Policy</h2><p className="mt-2 max-w-2xl text-sm text-slate-600">This Batch 1 view is read-only below the existing broad capability control. Permission editing and semantic preview arrive in the next implementation batch.</p><dl className="mt-5 grid gap-4 sm:grid-cols-2"><Definition label="Effective capability">{stateLabel}</Definition><Definition label="Authority">{props.effective.health}</Definition><Definition label="Provenance">{provenance.join(" · ")}</Definition><Definition label="Global lockdown">{props.effective.global_lockdown ? "Active" : "Off"}</Definition></dl></section> : null}
      {activeTab === "test-lab" ? <section id="extension-panel-test-lab" role="tabpanel" aria-labelledby="extension-tab-test-lab" className="mt-6 rounded-3xl border border-slate-200 bg-white p-6"><h2 className="text-lg font-semibold text-slate-950">Test Lab</h2><div className="mt-3 flex gap-3 rounded-xl bg-blue-50 p-4 text-sm text-slate-700"><HiMiniInformationCircle className="mt-0.5 size-5 shrink-0 text-brand-blue" /><p>Side-effect-free command simulation is delivered in Batch 3. This placeholder never accepts or executes command text.</p></div>{props.urlState.ruleId ? <p className="mt-4 text-sm text-slate-600">Selected rule: <code>{props.urlState.ruleId}</code></p> : null}</section> : null}
      {activeTab === "activity" ? <section id="extension-panel-activity" role="tabpanel" aria-labelledby="extension-tab-activity" className="mt-6 rounded-3xl border border-slate-200 bg-white p-6"><h2 className="text-lg font-semibold text-slate-950">Activity</h2><p className="mt-2 text-sm text-slate-600">Extension-scoped decision and policy history arrives in Batch 4. No activity is synthesized in the dashboard.</p></section> : null}

      {selectedPermission ? <PermissionInspector effective={props.effective} extension={props.extension} permission={selectedPermission} onClose={() => props.onUrlState({ ...props.urlState, ruleId: null })} /> : null}
      {selectedRule ? <RuleInspector extension={props.extension} rule={selectedRule} onClose={() => props.onUrlState({ ...props.urlState, ruleId: null })} onTest={() => props.onUrlState({ ...props.urlState, tab: "test-lab", ruleId: selectedRule.rule_id })} /> : null}
    </main>
  );
}
