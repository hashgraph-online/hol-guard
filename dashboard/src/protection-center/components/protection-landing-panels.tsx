import { useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniCloud,
  HiMiniExclamationTriangle,
  HiMiniMagnifyingGlass,
} from "react-icons/hi2";

import { commandReasonLabel } from "../../command-activity/command-activity-presenters";
import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../../extension-controls-api";
import { isExtensionEnabled } from "../../extensions-filters";
import { ProtectionDecisionBadge, ProtectionModuleRow } from "./protection-primitives";
import {
  filterProtectionModulesByHumanQuery,
  type ProtectionCloudContinuity,
  type ProtectionDecisionView,
  type ProtectionHealthCheck,
  type ProtectionModuleRank,
} from "../model/protection-landing";
import {
  EXTENSION_BODY_CLASS,
  EXTENSION_CHIP_CLASS,
  EXTENSION_KICKER_CLASS,
  EXTENSION_LIST_CLASS,
  EXTENSION_PANEL_CLASS,
  EXTENSION_PANEL_COMPACT_CLASS,
  EXTENSION_TITLE_CLASS,
} from "../protection-surface";

function managedByOrganization(effective: EffectiveExtensionControls, extensionId: string): boolean {
  return effective.layers.some((layer) =>
    layer.kind === "signed-cloud" && layer.controls.some((control) => control.target_kind === "extension" && control.target_id === extensionId),
  );
}

export function CloudContinuityIndicator(props: {
  continuity: ProtectionCloudContinuity;
  loading?: boolean;
}) {
  return <aside aria-label="Cloud continuity" className={`flex items-start gap-3 ${EXTENSION_PANEL_COMPACT_CLASS}`}>
    <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-[rgba(85,153,254,0.1)] text-brand-blue" aria-hidden="true">
      {props.loading ? <HiMiniArrowPath className="size-5 animate-spin motion-reduce:animate-none" /> : <HiMiniCloud className="size-5" />}
    </span>
    <div className="min-w-0">
      <div className="text-sm font-semibold text-brand-dark">{props.loading ? "Checking Cloud continuity…" : props.continuity.label}</div>
      <p className="mt-1 text-xs leading-5 text-brand-dark/75">{props.continuity.detail}</p>
    </div>
  </aside>;
}

export function ProtectionWatchingMap(props: {
  modules: readonly ProtectionModuleRank[];
  onOpen: (extension: ExtensionCatalogItem) => void;
}) {
  const inUse = props.modules.filter((module) => module.section === "in-use");
  return <section aria-labelledby="extensions-watching-heading" className="mt-10">
    <p className={EXTENSION_KICKER_CLASS}>Watching</p>
    <h2 id="extensions-watching-heading" className={EXTENSION_TITLE_CLASS}>
      Guard is watching the tools your agent uses.
    </h2>
    {inUse.length ? <ul className="mt-6 flex flex-wrap gap-x-3 gap-y-2">
      {inUse.map((module) => <li key={module.extension.extension_id}>
        <button
          type="button"
          onClick={() => props.onOpen(module.extension)}
          className={EXTENSION_CHIP_CLASS}
        >
          {module.extension.name}
        </button>
      </li>)}
    </ul> : <p className={`mt-4 max-w-2xl ${EXTENSION_BODY_CLASS}`}>No recent tool activity yet. Recommended extensions are ready below.</p>}
  </section>;
}

export function ProtectionModuleExplorer(props: {
  modules: readonly ProtectionModuleRank[];
  effective: EffectiveExtensionControls;
  onOpen: (extension: ExtensionCatalogItem) => void;
  advancedFilters?: React.ReactNode;
  focusQuery?: string;
}) {
  const inUse = useMemo(() => props.modules.filter((module) => module.section === "in-use"), [props.modules]);
  const recommended = useMemo(() => props.modules.filter((module) => module.section === "recommended"), [props.modules]);
  const primary = inUse.length ? inUse : recommended.slice(0, 6);
  const heading = inUse.length ? "In use" : "Ready";
  const [query, setQuery] = useState("");
  const [browseOpen, setBrowseOpen] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!props.focusQuery) return;
    setQuery(props.focusQuery);
    setBrowseOpen(true);
    searchRef.current?.focus();
  }, [props.focusQuery]);
  const queried = useMemo(() => filterProtectionModulesByHumanQuery(props.modules, query), [props.modules, query]);
  const browseList = query.trim() ? queried : props.modules;

  return <section aria-labelledby="protection-modules-heading" className="mt-10">
    <h2 id="protection-modules-heading" className="text-xl font-semibold tracking-tight text-brand-dark">{heading}</h2>
    <p className={`mt-1 ${EXTENSION_BODY_CLASS}`}>Open an extension to see what Guard does, then try a command.</p>
    {primary.length ? <div className={EXTENSION_LIST_CLASS}>{primary.map((module) => <ProtectionModuleRow key={module.extension.extension_id} name={module.extension.name} description={module.extension.description} behavior={isExtensionEnabled(props.effective, module.extension) ? "Guard defaults active" : "Blocked on this device"} required={module.extension.required} managed={managedByOrganization(props.effective, module.extension.extension_id)} onOpen={() => props.onOpen(module.extension)} />)}</div> : <p className={`mt-4 ${EXTENSION_BODY_CLASS}`}>No extensions are registered yet.</p>}
    <details className="mt-5" open={browseOpen} onToggle={(event) => setBrowseOpen(event.currentTarget.open)}>
      <summary className="cursor-pointer text-sm font-semibold text-brand-dark">Browse all extensions</summary>
      <div className="mt-3">
        <label className="relative block">
          <span className="sr-only">Search extensions</span>
          <HiMiniMagnifyingGlass className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/55" aria-hidden="true" />
          <input ref={searchRef} type="search" value={query} onChange={(event) => setQuery(event.target.value.slice(0, 160))} placeholder="Search Git, packages, secrets, downloads…" className="min-h-11 w-full rounded-2xl border border-[rgba(63,65,116,0.12)] bg-white/80 py-2 pl-9 pr-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" />
        </label>
        {props.advancedFilters ? <div className="mt-3">
          <button type="button" aria-expanded={advancedOpen} onClick={() => setAdvancedOpen((value) => !value)} className="inline-flex min-h-10 items-center gap-2 rounded-lg px-2 text-xs font-semibold text-brand-dark hover:bg-white/70">
            Advanced filters <HiMiniChevronDown className={`size-4 ${advancedOpen ? "rotate-180" : ""}`} aria-hidden="true" />
          </button>
          {advancedOpen ? <div className="mt-2">{props.advancedFilters}</div> : null}
        </div> : null}
        {browseList.length ? <div className={EXTENSION_LIST_CLASS}>{browseList.map((module) => <ProtectionModuleRow key={`all-${module.extension.extension_id}`} name={module.extension.name} description={module.extension.description} behavior={isExtensionEnabled(props.effective, module.extension) ? "Guard defaults active" : "Blocked on this device"} required={module.extension.required} managed={managedByOrganization(props.effective, module.extension.extension_id)} onOpen={() => props.onOpen(module.extension)} />)}</div> : <p className={`mt-4 ${EXTENSION_BODY_CLASS}`}>No extensions match this search.</p>}
      </div>
    </details>
  </section>;
}

export function RecentProtectionDecisions(props: {
  decisions: readonly ProtectionDecisionView[];
  loading?: boolean;
  unavailable?: boolean;
}) {
  if (props.loading) {
    return <section aria-labelledby="recent-protection-decisions-heading" className="mt-8" aria-busy="true">
      <h2 id="recent-protection-decisions-heading" className="text-lg font-semibold text-brand-dark">Recent decisions</h2>
      <div className="guard-skeleton mt-4 h-24 w-full" />
    </section>;
  }
  if (props.unavailable) {
    return <section aria-labelledby="recent-protection-decisions-heading" className={`mt-8 ${EXTENSION_PANEL_CLASS}`}>
      <h2 id="recent-protection-decisions-heading" className="text-lg font-semibold text-brand-dark">Recent decisions</h2>
      <p className={`mt-2 ${EXTENSION_BODY_CLASS}`}>Recent local decision evidence could not be loaded. Protection status above remains independent of this activity view.</p>
    </section>;
  }
  return <section aria-labelledby="recent-protection-decisions-heading" className={`mt-8 ${EXTENSION_PANEL_CLASS}`}>
    <div>
      <h2 id="recent-protection-decisions-heading" className="text-lg font-semibold text-brand-dark">Recent decisions</h2>
      <p className={`mt-1 ${EXTENSION_BODY_CLASS}`}>Privacy-safe local evidence. Raw commands and paths are not shown.</p>
    </div>
    {props.decisions.length ? <div className="mt-3 space-y-1">{props.decisions.map((decision) => <article key={decision.activityId} className="rounded-2xl bg-white/55 px-3 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <ProtectionDecisionBadge result={decision.result} />
          <strong className="text-sm text-brand-dark">{decision.extensionNames.length ? decision.extensionNames.join(", ") : "Guard protection"}</strong>
        </div>
        <time className="text-xs font-medium text-brand-dark/70" dateTime={decision.occurredAt}>{new Date(decision.occurredAt).toLocaleString()}</time>
      </div>
      <details className="mt-2">
        <summary className="cursor-pointer text-xs font-semibold text-brand-blue">Why?</summary>
        <p className={`mt-2 ${EXTENSION_BODY_CLASS}`}>{commandReasonLabel(decision.reasonCode)}</p>
      </details>
    </article>)}</div> : <p className={`mt-3 ${EXTENSION_BODY_CLASS}`}>No recent local command decisions are recorded yet.</p>}
  </section>;
}

export function ProtectionHealthCheckPanel(props: {
  result: ProtectionHealthCheck | null;
  busy: boolean;
  error?: string | null;
  onRun: () => void;
}) {
  return <section aria-labelledby="protection-health-check-heading" className={`mt-8 ${EXTENSION_PANEL_CLASS}`}>
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h2 id="protection-health-check-heading" className="text-lg font-semibold text-brand-dark">Protection health check</h2>
        <p className={`mt-1 max-w-2xl ${EXTENSION_BODY_CLASS}`}>Safely re-read Guard's local catalog, trusted settings, and runtime. This check does not execute a command or change protection.</p>
      </div>
      <button type="button" onClick={props.onRun} disabled={props.busy} aria-busy={props.busy} className="inline-flex min-h-11 shrink-0 items-center gap-2 rounded-xl border border-brand-blue/25 bg-white/80 px-4 text-sm font-semibold text-brand-blue hover:bg-[rgba(85,153,254,0.08)] disabled:opacity-60">
        {props.busy ? <HiMiniArrowPath className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" /> : <HiMiniCheckCircle className="size-4" aria-hidden="true" />}
        {props.busy ? "Checking…" : "Run health check"}
      </button>
    </div>
    {props.error ? <p role="alert" className="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-800">{props.error}</p> : null}
    {props.result ? <div role="status" aria-live="polite" className={`mt-4 rounded-xl border p-4 ${props.result.status === "healthy" ? "border-emerald-200 bg-emerald-50" : "border-amber-200 bg-amber-50"}`}>
      <div className="flex items-start gap-2">
        {props.result.status === "healthy" ? <HiMiniCheckCircle className="mt-0.5 size-5 shrink-0 text-emerald-800" /> : <HiMiniExclamationTriangle className="mt-0.5 size-5 shrink-0 text-amber-800" />}
        <p className="text-sm font-medium text-brand-dark">{props.result.summary}</p>
      </div>
      <ul className="mt-3 space-y-1.5">{props.result.checks.map((check) => <li key={check.id} className="flex items-center gap-2 text-xs text-brand-dark/80"><span aria-hidden="true">{check.passed ? "✓" : "•"}</span>{check.label}</li>)}</ul>
    </div> : null}
  </section>;
}
