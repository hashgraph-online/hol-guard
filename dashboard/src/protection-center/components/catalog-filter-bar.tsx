import { useCallback, useMemo, type RefObject } from "react";
import { HiMiniAdjustmentsHorizontal, HiMiniCheck, HiMiniChevronDown, HiMiniXMark } from "react-icons/hi2";

import type { ExtensionCatalogSummary, ExtensionTrustClass } from "../../extension-controls-api";
import type { ProtectionCategoryId } from "../model/protection-categories";
import {
  CATALOG_KIND_FILTERS,
  CATALOG_TRUST_FILTERS,
  catalogFilterChipAriaLabel,
  catalogFilterChipCount,
  catalogFilterCountCopy,
  catalogFiltersActive,
  catalogKindLabel,
  catalogTrustLabel,
  EMPTY_CATALOG_FILTERS,
  filterCatalogExtensions,
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
 * Toolbar trigger for the catalog filter popover. Rendered beside the search
 * input; the panel it controls is rendered by CatalogFilterBar.
 */
export function CatalogFilterTrigger(props: {
  open: boolean;
  activeCount: number;
  panelId: string;
  buttonRef?: RefObject<HTMLButtonElement | null>;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      ref={props.buttonRef}
      aria-expanded={props.open}
      aria-controls={props.panelId}
      title="Filters (press f)"
      onClick={props.onToggle}
      className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-[rgba(63,65,116,0.18)] bg-white px-3.5 text-sm font-semibold text-brand-dark shadow-sm transition-colors hover:border-brand-blue hover:text-brand-blue focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue aria-expanded:border-brand-blue aria-expanded:text-brand-blue motion-reduce:transition-none"
    >
      <HiMiniAdjustmentsHorizontal className="size-4" aria-hidden="true" />
      Filters
      {props.activeCount > 0 ? (
        <span className="grid min-w-5 place-items-center rounded-full bg-brand-blue px-1 text-[0.6875rem] font-semibold leading-5 text-white tabular-nums">
          {props.activeCount}
        </span>
      ) : null}
      <HiMiniChevronDown
        className={`size-4 transition-transform duration-200 motion-reduce:transition-none ${props.open ? "rotate-180" : ""}`}
        aria-hidden="true"
      />
    </button>
  );
}

/**
 * Active-filter tokens plus the filter popover panel. The panel overlays the
 * catalog at sm+ (no layout shift) and expands in flow on small screens. The
 * parent owns the open state so the trigger can live beside the search input.
 */
export function CatalogFilterBar(props: {
  catalog: readonly ExtensionCatalogSummary[];
  filters: CatalogFilterState;
  onChange: (next: CatalogFilterState) => void;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  panelId: string;
  /** Called after clearing so the parent can restore focus to the trigger: both clear buttons unmount themselves. */
  onAfterClear?: () => void;
}) {
  const areas = useMemo(() => populatedCatalogAreaOptions(props.catalog), [props.catalog]);
  const filtering = catalogFiltersActive(props.filters);
  const activeCount = props.filters.trusts.length + props.filters.kinds.length + props.filters.areas.length;
  const visibleCount = useMemo(
    () => filterCatalogExtensions(props.catalog, props.filters).length,
    [props.catalog, props.filters],
  );

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
    props.onAfterClear?.();
  }, [props]);

  return (
    <>
      {filtering ? (
        <div className="mt-2 flex flex-wrap items-center gap-2" data-testid="catalog-filter-tokens">
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
          <button type="button" className="guard-extensions-chip" onClick={handleClear}>
            <HiMiniXMark className="size-4" aria-hidden="true" />
            Clear filters
          </button>
        </div>
      ) : null}
      <div
        id={props.panelId}
        hidden={!props.open}
        data-testid="catalog-filter-panel"
        className="mt-2 max-h-[min(70vh,32rem)] overflow-y-auto overscroll-contain rounded-2xl border border-[rgba(63,65,116,0.12)] bg-white p-4 shadow-[0_12px_32px_rgba(63,65,116,0.16)] sm:absolute sm:inset-x-0 sm:top-full sm:z-30 sm:mt-2 sm:p-5"
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
        <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-[rgba(63,65,116,0.12)] pt-3">
          <p className="text-xs text-brand-dark/65" data-testid="catalog-filter-count">
            {catalogFilterCountCopy(visibleCount, props.catalog.length, filtering)}
          </p>
          {filtering ? (
            <button type="button" className="guard-extensions-chip" onClick={handleClear}>
              <HiMiniXMark className="size-4" aria-hidden="true" />
              Clear all {activeCount} {activeCount === 1 ? "filter" : "filters"}
            </button>
          ) : null}
        </div>
      </div>
    </>
  );
}
