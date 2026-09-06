import { useCallback, useMemo } from "react";
import { HiMiniXMark } from "react-icons/hi2";

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

function CatalogFilterChip(props: {
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
      className="group inline-flex min-h-11 items-center gap-1.5 rounded-full border border-[rgba(63,65,116,0.16)] bg-white px-3.5 text-[0.8125rem] font-semibold text-brand-dark/80 transition-colors hover:border-brand-blue/45 hover:text-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:cursor-not-allowed disabled:opacity-45 aria-pressed:border-brand-blue/55 aria-pressed:bg-brand-blue/10 aria-pressed:text-brand-dark motion-reduce:transition-none"
    >
      <span>{props.label}</span>
      <span className="tabular-nums text-xs font-medium text-brand-dark/50 group-aria-pressed:text-brand-dark/65">{props.count}</span>
    </button>
  );
}

function CatalogFilterGroup(props: {
  legend: string;
  children: React.ReactNode;
}) {
  return (
    <fieldset className="min-w-0">
      <legend className="text-xs font-semibold text-brand-dark/55">{props.legend}</legend>
      <div className="mt-2 flex flex-wrap gap-2">{props.children}</div>
    </fieldset>
  );
}

function TrustFilterChip(props: {
  value: ExtensionTrustClass;
  count: number;
  pressed: boolean;
  onToggle: (value: ExtensionTrustClass) => void;
}) {
  const handleToggle = useCallback(() => {
    props.onToggle(props.value);
  }, [props]);
  return (
    <CatalogFilterChip
      label={catalogTrustLabel(props.value)}
      count={props.count}
      pressed={props.pressed}
      disabled={props.count === 0 && !props.pressed}
      onToggle={handleToggle}
    />
  );
}

function KindFilterChip(props: {
  value: CatalogKindFilter;
  count: number;
  pressed: boolean;
  onToggle: (value: CatalogKindFilter) => void;
}) {
  const handleToggle = useCallback(() => {
    props.onToggle(props.value);
  }, [props]);
  return (
    <CatalogFilterChip
      label={catalogKindLabel(props.value)}
      count={props.count}
      pressed={props.pressed}
      disabled={props.count === 0 && !props.pressed}
      onToggle={handleToggle}
    />
  );
}

function AreaFilterChip(props: {
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
    <CatalogFilterChip
      label={props.label}
      count={props.count}
      pressed={props.pressed}
      disabled={props.count === 0 && !props.pressed}
      onToggle={handleToggle}
    />
  );
}

export function CatalogFilterBar(props: {
  catalog: readonly ExtensionCatalogItem[];
  filters: CatalogFilterState;
  onChange: (next: CatalogFilterState) => void;
}) {
  const areas = useMemo(() => populatedCatalogAreaOptions(props.catalog), [props.catalog]);
  const filtering = catalogFiltersActive(props.filters);

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

  return (
    <div className="mt-4 scroll-mt-28" data-testid="catalog-filters">
      <div className="flex flex-col gap-4">
        <CatalogFilterGroup legend="Trust">
          {CATALOG_TRUST_FILTERS.map((trust) => (
            <TrustFilterChip
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
            <KindFilterChip
              key={kind}
              value={kind}
              count={catalogFilterChipCount(props.catalog, props.filters, { kinds: [kind] })}
              pressed={props.filters.kinds.includes(kind)}
              onToggle={handleToggleKind}
            />
          ))}
        </CatalogFilterGroup>
        <CatalogFilterGroup legend="Area">
          {areas.map((area) => (
            <AreaFilterChip
              key={area.id}
              value={area.id}
              label={area.label}
              count={catalogFilterChipCount(props.catalog, props.filters, { areas: [area.id] })}
              pressed={props.filters.areas.includes(area.id)}
              onToggle={handleToggleArea}
            />
          ))}
        </CatalogFilterGroup>
      </div>
      {filtering ? (
        <div className="mt-3">
          <button type="button" className="guard-extensions-chip" onClick={handleClear}>
            <HiMiniXMark className="size-4" aria-hidden="true" />
            Clear filters
          </button>
        </div>
      ) : null}
    </div>
  );
}
