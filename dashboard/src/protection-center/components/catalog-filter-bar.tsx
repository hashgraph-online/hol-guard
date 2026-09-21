import { useCallback, useId, useMemo, useRef, useState } from "react";
import { HiMiniAdjustmentsHorizontal, HiMiniCheck, HiMiniChevronDown, HiMiniXMark } from "react-icons/hi2";

import type { ExtensionCatalogItem, ExtensionTrustClass } from "../../extension-controls-api";
import type { ProtectionCategoryId } from "../model/protection-categories";
import {
  CATALOG_KIND_FILTERS,
  CATALOG_TRUST_FILTERS,
  catalogFilterChipAriaLabel,
  catalogFilterChipCount,
  catalogFiltersActive,
  catalogKindLabel,
  catalogTrustLabel,
  EMPTY_CATALOG_FILTERS,
  populatedCatalogAreaOptions,
  toggleCatalogFilterValue,
  type CatalogFilterState,
  type CatalogKindFilter,
} from "../model/catalog-filters";

function CatalogFilterOption(props: {
  label: string;
  count: number;
  pressed: boolean;
  disabled: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={props.pressed}
      aria-label={catalogFilterChipAriaLabel(props.label, props.count)}
      disabled={props.disabled}
      onClick={props.onToggle}
      className="group flex min-h-10 w-full items-center justify-between gap-3 rounded-lg border border-[rgba(63,65,116,0.16)] bg-white px-2.5 text-[0.8125rem] font-semibold text-brand-dark/80 transition-colors hover:border-brand-blue/45 hover:text-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:cursor-not-allowed disabled:opacity-45 aria-pressed:border-brand-blue/55 aria-pressed:bg-brand-blue/10 aria-pressed:text-brand-dark motion-reduce:transition-none"
    >
      <span className="flex min-w-0 items-center gap-2">
        <span className="grid size-4 shrink-0 place-items-center text-brand-blue">
          {props.pressed ? <HiMiniCheck className="size-4" aria-hidden="true" /> : null}
        </span>
        <span className="truncate">{props.label}</span>
      </span>
      <span className="tabular-nums text-xs font-medium text-brand-dark/50 group-aria-pressed:text-brand-dark/65">{props.count}</span>
    </button>
  );
}

function ActiveFilterToken(props: {
  groupLabel: string;
  valueLabel: string;
  onRemove: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={`Remove ${props.valueLabel} ${props.groupLabel.toLowerCase()} filter`}
      onClick={props.onRemove}
      className="group inline-flex min-h-8 items-center gap-1.5 rounded-full border border-brand-blue/45 bg-brand-blue/10 py-1 pl-2.5 pr-2 text-xs font-semibold text-brand-dark transition-colors hover:border-brand-blue hover:bg-brand-blue/15 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue motion-reduce:transition-none"
    >
      <span className="text-brand-dark/65">{props.groupLabel}:</span>
      {props.valueLabel}
      <HiMiniXMark className="size-3.5 shrink-0 text-brand-dark/55 group-hover:text-brand-dark" aria-hidden="true" />
    </button>
  );
}

function CatalogFilterGroup(props: {
  legend: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <fieldset className={`min-w-0 ${props.className ?? ""}`}>
      <legend className="text-xs font-semibold text-brand-dark/55">{props.legend}</legend>
      <div className="mt-2 flex flex-col gap-1.5">{props.children}</div>
    </fieldset>
  );
}

function TrustFilterOption(props: {
  value: ExtensionTrustClass;
  count: number;
  pressed: boolean;
  onToggle: (value: ExtensionTrustClass) => void;
}) {
  const handleToggle = useCallback(() => {
    props.onToggle(props.value);
  }, [props]);
  return (
    <CatalogFilterOption
      label={catalogTrustLabel(props.value)}
      count={props.count}
      pressed={props.pressed}
      disabled={props.count === 0 && !props.pressed}
      onToggle={handleToggle}
    />
  );
}

function KindFilterOption(props: {
  value: CatalogKindFilter;
  count: number;
  pressed: boolean;
  onToggle: (value: CatalogKindFilter) => void;
}) {
  const handleToggle = useCallback(() => {
    props.onToggle(props.value);
  }, [props]);
  return (
    <CatalogFilterOption
      label={catalogKindLabel(props.value)}
      count={props.count}
      pressed={props.pressed}
      disabled={props.count === 0 && !props.pressed}
      onToggle={handleToggle}
    />
  );
}

function AreaFilterOption(props: {
  value: ProtectionCategoryId;
  label: string;
  count: number;
  pressed: boolean;
  onToggle: (value: ProtectionCategoryId) => void;
}) {
  const handleToggle = useCallback(() => {
    props.onToggle(props.value);
  }, [props]);
  return (
    <CatalogFilterOption
      label={props.label}
      count={props.count}
      pressed={props.pressed}
      disabled={props.count === 0 && !props.pressed}
      onToggle={handleToggle}
    />
  );
}

/**
 * Compact catalog filter toolbar: one "Filters" trigger with removable active
 * tokens, opening a disclosure panel that groups trust, kind, and area toggles
 * with live counts. Collapsed by default so the catalog starts above the fold.
 */
export function CatalogFilterBar(props: {
  catalog: readonly ExtensionCatalogItem[];
  filters: CatalogFilterState;
  onChange: (next: CatalogFilterState) => void;
}) {
  const [panelOpen, setPanelOpen] = useState(false);
  const panelId = useId();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const areas = useMemo(() => populatedCatalogAreaOptions(props.catalog), [props.catalog]);
  const filtering = catalogFiltersActive(props.filters);
  const activeCount = props.filters.trusts.length + props.filters.kinds.length + props.filters.areas.length;

  const handleToggleTrust = useCallback((value: ExtensionTrustClass) => {
    props.onChange({
      ...props.filters,
      trusts: toggleCatalogFilterValue(props.filters.trusts, value),
    });
  }, [props]);

  const handleToggleKind = useCallback((value: CatalogKindFilter) => {
    props.onChange({
      ...props.filters,
      kinds: toggleCatalogFilterValue(props.filters.kinds, value),
    });
  }, [props]);

  const handleToggleArea = useCallback((value: ProtectionCategoryId) => {
    props.onChange({
      ...props.filters,
      areas: toggleCatalogFilterValue(props.filters.areas, value),
    });
  }, [props]);

  const handleClear = useCallback(() => {
    props.onChange(EMPTY_CATALOG_FILTERS);
  }, [props]);

  const handleKeyDown = useCallback((event: React.KeyboardEvent) => {
    if (event.key !== "Escape" || !panelOpen) return;
    event.stopPropagation();
    setPanelOpen(false);
    triggerRef.current?.focus();
  }, [panelOpen]);

  return (
    <div className="mt-3 scroll-mt-28" data-testid="catalog-filters" onKeyDown={handleKeyDown}>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          ref={triggerRef}
          aria-expanded={panelOpen}
          aria-controls={panelId}
          onClick={() => setPanelOpen((open) => !open)}
          className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-[rgba(63,65,116,0.18)] bg-white px-3 text-xs font-semibold text-brand-dark shadow-sm transition-colors hover:border-brand-blue hover:text-brand-blue focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue aria-expanded:border-brand-blue aria-expanded:text-brand-blue motion-reduce:transition-none"
        >
          <HiMiniAdjustmentsHorizontal className="size-4" aria-hidden="true" />
          Filters
          {activeCount > 0 ? (
            <span className="grid min-w-5 place-items-center rounded-full bg-brand-blue px-1 text-[0.6875rem] font-semibold leading-5 text-white tabular-nums">
              {activeCount}
            </span>
          ) : null}
          <HiMiniChevronDown
            className={`size-4 transition-transform duration-200 motion-reduce:transition-none ${panelOpen ? "rotate-180" : ""}`}
            aria-hidden="true"
          />
        </button>
        {props.filters.trusts.map((trust) => (
          <ActiveFilterToken
            key={`trust-${trust}`}
            groupLabel="Trust"
            valueLabel={catalogTrustLabel(trust)}
            onRemove={() => handleToggleTrust(trust)}
          />
        ))}
        {props.filters.kinds.map((kind) => (
          <ActiveFilterToken
            key={`kind-${kind}`}
            groupLabel="Kind"
            valueLabel={catalogKindLabel(kind)}
            onRemove={() => handleToggleKind(kind)}
          />
        ))}
        {props.filters.areas.map((areaId) => {
          const area = areas.find((option) => option.id === areaId);
          return (
            <ActiveFilterToken
              key={`area-${areaId}`}
              groupLabel="Area"
              valueLabel={area?.label ?? areaId}
              onRemove={() => handleToggleArea(areaId)}
            />
          );
        })}
        {filtering ? (
          <button type="button" className="guard-extensions-chip" onClick={handleClear}>
            <HiMiniXMark className="size-4" aria-hidden="true" />
            Clear filters
          </button>
        ) : (
          <span className="hidden text-xs text-brand-dark/70 sm:inline">Narrow by trust, kind, or area.</span>
        )}
      </div>
      <div
        id={panelId}
        hidden={!panelOpen}
        className="mt-3 rounded-2xl border border-[rgba(63,65,116,0.12)] bg-white p-4 shadow-sm sm:p-5"
      >
        <div className="grid gap-x-8 gap-y-5 sm:grid-cols-2 lg:grid-cols-[minmax(0,14rem)_minmax(0,12rem)_minmax(0,1fr)]">
          <CatalogFilterGroup legend="Trust">
            {CATALOG_TRUST_FILTERS.map((trust) => (
              <TrustFilterOption
                key={trust}
                value={trust}
                count={catalogFilterChipCount(props.catalog, props.filters, { trusts: [trust] })}
                pressed={props.filters.trusts.includes(trust)}
                onToggle={handleToggleTrust}
              />
            ))}
          </CatalogFilterGroup>
          <CatalogFilterGroup legend="Kind">
            {CATALOG_KIND_FILTERS.map((kind) => (
              <KindFilterOption
                key={kind}
                value={kind}
                count={catalogFilterChipCount(props.catalog, props.filters, { kinds: [kind] })}
                pressed={props.filters.kinds.includes(kind)}
                onToggle={handleToggleKind}
              />
            ))}
          </CatalogFilterGroup>
          <CatalogFilterGroup legend="Area" className="sm:col-span-2 lg:col-span-1">
            <div className="grid gap-x-6 gap-y-1.5 sm:grid-cols-2">
              {areas.map((area) => (
                <AreaFilterOption
                  key={area.id}
                  value={area.id}
                  label={area.label}
                  count={catalogFilterChipCount(props.catalog, props.filters, { areas: [area.id] })}
                  pressed={props.filters.areas.includes(area.id)}
                  onToggle={handleToggleArea}
                />
              ))}
            </div>
          </CatalogFilterGroup>
        </div>
      </div>
    </div>
  );
}
