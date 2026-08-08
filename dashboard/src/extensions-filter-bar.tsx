import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { HiMiniAdjustmentsHorizontal, HiMiniMagnifyingGlass, HiMiniXMark } from "react-icons/hi2";

import type { ExtensionCatalogItem } from "./extension-controls-api";
import {
  classifyDomain,
  DOMAIN_LABELS,
  EMPTY_EXTENSION_FILTERS,
  type ExtensionDomain,
  type ExtensionFilterState,
  type ExtensionRequiredFilter,
  type ExtensionStateFilter,
  filterExtensions,
  hasActiveFilters,
  type RiskClass,
  RISK_CLASS_LABELS,
  RISK_CLASS_ORDER,
  RISK_CLASS_TONE,
} from "./extensions-filters";
import type { EffectiveExtensionControls } from "./extension-controls-api";

const SELECT_CLASS =
  "min-h-9 rounded-xl border border-slate-200 bg-white px-3 text-xs font-medium text-slate-700 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60";

const DOMAIN_ORDER: readonly ExtensionDomain[] = [
  "core",
  "package",
  "cloud",
  "database",
  "storage",
  "backup",
  "remote",
  "cicd",
  "platform",
  "managed-service",
  "search-messaging",
  "source-control",
] as const;

interface ExtensionsFilterBarProps {
  filters: ExtensionFilterState;
  onChange: (patch: Partial<ExtensionFilterState>) => void;
  onClear: () => void;
  extensions: ExtensionCatalogItem[];
  effective: EffectiveExtensionControls;
}

function SearchField(props: { value: string; onChange: (value: string) => void; inputRef: React.RefObject<HTMLInputElement | null> }) {
  const handleChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => props.onChange(event.target.value),
    [props],
  );
  const handleClear = useCallback(() => props.onChange(""), [props]);
  return (
    <label className="relative flex flex-1 items-center">
      <span className="sr-only">Search extensions</span>
      <HiMiniMagnifyingGlass
        className="pointer-events-none absolute left-3 size-4 text-slate-400"
        aria-hidden="true"
      />
      <input
        ref={props.inputRef}
        type="search"
        value={props.value}
        onChange={handleChange}
        placeholder="Search by name, command, or risk (press /)"
        className="min-h-9 w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-9 text-sm text-slate-900 placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
      />
      {props.value ? (
        <button
          type="button"
          onClick={handleClear}
          aria-label="Clear search"
          className="absolute right-2 flex size-5 items-center justify-center rounded-full text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600"
        >
          <HiMiniXMark className="size-4" aria-hidden="true" />
        </button>
      ) : null}
    </label>
  );
}

function RiskChips(props: {
  value: RiskClass | "all";
  onChange: (risk: RiskClass | "all") => void;
  counts: Map<RiskClass, number>;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by risk class">
      {RISK_CLASS_ORDER.map((risk) => {
        const isActive = props.value === risk;
        const tone = RISK_CLASS_TONE[risk];
        const count = props.counts.get(risk) ?? 0;
        return (
          <button
            key={risk}
            type="button"
            onClick={() => props.onChange(isActive ? "all" : risk)}
            aria-pressed={isActive}
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${isActive ? tone.active : tone.idle}`}
          >
            {RISK_CLASS_LABELS[risk]}
            <span className={isActive ? "opacity-70" : "text-slate-400"} aria-hidden="true">{count}</span>
          </button>
        );
      })}
    </div>
  );
}

function ActiveChip(props: { label: string; onRemove: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-brand-blue/10 px-2.5 py-1 text-xs font-medium text-brand-blue">
      {props.label}
      <button
        type="button"
        onClick={props.onRemove}
        aria-label={`Remove filter: ${props.label}`}
        className="flex size-4 items-center justify-center rounded-full transition-colors hover:bg-brand-blue/20"
      >
        <HiMiniXMark className="size-3" aria-hidden="true" />
      </button>
    </span>
  );
}

export function ExtensionsFilterBar(props: ExtensionsFilterBarProps) {
  const [showFacets, setShowFacets] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  // Keyboard: "/" focuses search, "Escape" clears search when focused.
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing = target?.tagName === "INPUT" || target?.tagName === "TEXTAREA" || target?.isContentEditable;
      if (event.key === "/" && !typing) {
        event.preventDefault();
        searchRef.current?.focus();
      } else if (event.key === "Escape" && document.activeElement === searchRef.current && props.filters.query) {
        props.onChange({ query: "" });
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [props]);

  const handleQuery = useCallback((value: string) => props.onChange({ query: value }), [props]);
  const handleRisk = useCallback((risk: RiskClass | "all") => props.onChange({ risk }), [props]);
  const handleDomain = useCallback(
    (event: React.ChangeEvent<HTMLSelectElement>) =>
      props.onChange({ domain: event.target.value === "all" ? "all" : (event.target.value as ExtensionDomain) }),
    [props],
  );
  const handleState = useCallback(
    (event: React.ChangeEvent<HTMLSelectElement>) => props.onChange({ state: event.target.value as ExtensionStateFilter }),
    [props],
  );
  const handleRequired = useCallback(
    (event: React.ChangeEvent<HTMLSelectElement>) => props.onChange({ required: event.target.value as ExtensionRequiredFilter }),
    [props],
  );
  const toggleFacets = useCallback(() => setShowFacets((prev) => !prev), []);

  const riskCounts = useMemo(
    () => {
      const counts = new Map<RiskClass, number>();
      for (const risk of RISK_CLASS_ORDER) counts.set(risk, 0);
      for (const extension of props.extensions) {
        for (const risk of extension.risk_classes) {
          if (risk in RISK_CLASS_LABELS) {
            const key = risk as RiskClass;
            counts.set(key, (counts.get(key) ?? 0) + 1);
          }
        }
      }
      return counts;
    },
    [props.extensions],
  );

  const totalCount = props.extensions.length;
  const filteredCount = useMemo(
    () => filterExtensions(props.extensions, props.effective, props.filters).length,
    [props.extensions, props.effective, props.filters],
  );
  const active = hasActiveFilters(props.filters);
  const facetsActive = props.filters.domain !== "all" || props.filters.state !== "all" || props.filters.required !== "all";

  return (
    <div className="space-y-3" aria-label="Extension filters">
      <div className="flex flex-wrap items-center gap-2">
        <SearchField value={props.filters.query} onChange={handleQuery} inputRef={searchRef} />
        <button
          type="button"
          onClick={toggleFacets}
          aria-expanded={showFacets}
          aria-label="Toggle domain, state, and requirement filters"
          className={`inline-flex min-h-9 items-center gap-1.5 rounded-xl border px-3 text-xs font-medium transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${showFacets || facetsActive ? "border-brand-blue bg-brand-blue/5 text-brand-blue" : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`}
        >
          <HiMiniAdjustmentsHorizontal className="size-4" aria-hidden="true" />
          Filters
          {facetsActive ? (
            <span className="flex size-4 items-center justify-center rounded-full bg-brand-blue text-[10px] font-bold text-white">
              {[props.filters.domain !== "all", props.filters.state !== "all", props.filters.required !== "all"].filter(Boolean).length}
            </span>
          ) : null}
        </button>
      </div>

      <RiskChips value={props.filters.risk} onChange={handleRisk} counts={riskCounts} />

      {showFacets ? (
        <div className="flex flex-wrap items-center gap-2 rounded-xl bg-slate-50/70 p-3">
          <select
            value={props.filters.domain}
            onChange={handleDomain}
            aria-label="Filter by domain"
            className={SELECT_CLASS}
          >
            <option value="all">All domains</option>
            {DOMAIN_ORDER.map((domain) => (
              <option key={domain} value={domain}>{DOMAIN_LABELS[domain]}</option>
            ))}
          </select>
          <select
            value={props.filters.state}
            onChange={handleState}
            aria-label="Filter by enabled state"
            className={SELECT_CLASS}
          >
            <option value="all">All states</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
          <select
            value={props.filters.required}
            onChange={handleRequired}
            aria-label="Filter by required status"
            className={SELECT_CLASS}
          >
            <option value="all">Required &amp; optional</option>
            <option value="required">Required only</option>
            <option value="optional">Optional only</option>
          </select>
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-1.5">
        {active ? (
          <>
            {props.filters.query ? (
              <ActiveChip label={`“${props.filters.query}”`} onRemove={() => props.onChange({ query: "" })} />
            ) : null}
            {props.filters.risk !== "all" ? (
              <ActiveChip
                label={RISK_CLASS_LABELS[props.filters.risk]}
                onRemove={() => props.onChange({ risk: "all" })}
              />
            ) : null}
            {props.filters.domain !== "all" ? (
              <ActiveChip
                label={DOMAIN_LABELS[props.filters.domain]}
                onRemove={() => props.onChange({ domain: "all" })}
              />
            ) : null}
            {props.filters.state !== "all" ? (
              <ActiveChip
                label={props.filters.state === "enabled" ? "Enabled" : "Disabled"}
                onRemove={() => props.onChange({ state: "all" })}
              />
            ) : null}
            {props.filters.required !== "all" ? (
              <ActiveChip
                label={props.filters.required === "required" ? "Required only" : "Optional only"}
                onRemove={() => props.onChange({ required: "all" })}
              />
            ) : null}
            <button
              type="button"
              onClick={props.onClear}
              className="ml-1 text-xs font-medium text-brand-blue transition-colors hover:text-brand-dark"
            >
              Clear all
            </button>
          </>
        ) : null}
        <span className="ml-auto text-xs text-slate-500" aria-live="polite">
          {active ? `${filteredCount} of ${totalCount} shown` : `${totalCount} total`}
        </span>
      </div>
    </div>
  );
}

export { EMPTY_EXTENSION_FILTERS };
export { classifyDomain };
