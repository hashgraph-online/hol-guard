import { useCallback, useEffect, useMemo, useState } from "react";

import {
  catalogRowSecondLine,
  extensionDisplayName,
  extensionStateLabel,
} from "../extension-control-center-model";
import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../extension-controls-api";
import { addedCustomExtensions, type LocalCliItem } from "../local-cli-api";
import { WorkspacePageHeader } from "../workspace-page-header";
import {
  AddCustomExtensionButton,
  CustomExtensionsSection,
} from "./local-clis-panel";
import { CatalogFilterBar } from "./components/catalog-filter-bar";
import { PatternSearchConsole } from "./components/pattern-search-console";
import {
  InlineError,
  ProtectionModuleRow,
  ProtectionStatusHero,
} from "./components/protection-primitives";
import { PROTECTION_TERMS } from "./copy/protection-copy";
import {
  catalogFilterCountCopy,
  catalogFiltersActive,
  catalogFiltersEqual,
  customItemMatchesFilters,
  EMPTY_CATALOG_FILTERS,
  filterCatalogExtensions,
  pruneCatalogFilters,
  type CatalogFilterState,
} from "./model/catalog-filters";
import type { ProtectionStatusView } from "./model/protection-presentation";
import { extensionProtectionSource } from "../managed-controls/extension-managed-controls-panel";

function sourceIsManaged(effective: EffectiveExtensionControls, extensionId: string): boolean {
  return effective.layers.some((layer) =>
    layer.kind === "signed-cloud"
    && layer.controls.some((control) =>
      control.target_kind === "extension" && control.target_id === extensionId
    ));
}

function CatalogExtensionRow(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  onOpen: (extension: ExtensionCatalogItem) => void;
}) {
  const handleOpen = useCallback(() => {
    props.onOpen(props.extension);
  }, [props]);
  const source = extensionProtectionSource(props.effective, props.extension);
  const cloudSource = source === "Synced from Guard Cloud" || source.startsWith("Managed by ");
  return (
    <ProtectionModuleRow
      extensionId={props.extension.extension_id}
      name={extensionDisplayName(props.extension.name)}
      description={props.extension.description}
      behavior={catalogRowSecondLine(props.extension, extensionStateLabel(props.effective, props.extension))}
      required={props.extension.required}
      mcp={props.extension.surface === "mcp"}
      external={props.extension.trust_class === "external"}
      managed={cloudSource || sourceIsManaged(props.effective, props.extension.extension_id)}
      managedLabel={cloudSource ? source : undefined}
      executables={props.extension.executables}
      ecosystemIds={props.extension.ecosystem_ids}
      onOpen={handleOpen}
    />
  );
}

function CatalogFilterEmpty(props: { onClear: () => void }) {
  return (
    <div className="mt-6 rounded-2xl border border-[rgba(63,65,116,0.12)] bg-white px-4 py-6">
      <p className="text-sm font-semibold text-brand-dark">No extensions match these filters.</p>
      <p className="mt-1 text-sm leading-6 text-brand-dark/70">Clear a chip or start over to see the full catalog again.</p>
      <button type="button" className="guard-extensions-chip mt-3" onClick={props.onClear}>
        Clear filters
      </button>
    </div>
  );
}

export function ExtensionsOverview(props: {
  catalogExtensions: ExtensionCatalogItem[];
  effective: EffectiveExtensionControls;
  localCliItems: LocalCliItem[];
  localCliError: string | null;
  mutationError: string | null;
  recoveryStatus: string | null;
  healthBroken: boolean;
  status: ProtectionStatusView;
  active: boolean;
  onPrimaryStatusAction?: () => void;
  onRefresh: () => Promise<void> | void;
  onOpenExtension: (extension: ExtensionCatalogItem) => void;
  onOpenLocalCli: (cliId: string) => void;
  onAddCustom: () => void;
}) {
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<CatalogFilterState>(EMPTY_CATALOG_FILTERS);
  useEffect(() => {
    setFilters((current) => {
      const next = pruneCatalogFilters(current, props.catalogExtensions);
      if (catalogFiltersEqual(current, next)) return current;
      return next;
    });
  }, [props.catalogExtensions]);
  // An active search replaces the catalogs below it: results, then the Tools
  // match group. Rendering the full list under the results would force the
  // operator to visually skip fifty-nine unchanged rows.
  const searching = query.trim().length > 0;
  const filtering = catalogFiltersActive(filters);
  const visibleCatalog = useMemo(
    () => filterCatalogExtensions(props.catalogExtensions, filters),
    [filters, props.catalogExtensions],
  );
  const handleClearFilters = useCallback(() => {
    setFilters(EMPTY_CATALOG_FILTERS);
  }, []);
  // Suggestion-only responses (discovered servers, observed CLIs not yet
  // added) render no custom section: the section lists added extensions, and
  // its Add button would otherwise be the section's only content.
  const addedCustomItems = addedCustomExtensions(props.localCliItems).filter((item) =>
    customItemMatchesFilters(item, filters),
  );
  const addedCustomCount = addedCustomItems.length;
  return (
    <div hidden={!props.active} inert={!props.active || undefined}>
      <WorkspacePageHeader
        eyebrow="On this device"
        title={PROTECTION_TERMS.pageTitle}
        description="Choose an Extension to review its permissions and effective protection."
      />
      <div className="mt-6">
        <ProtectionStatusHero
          status={props.status}
          onPrimaryAction={props.status.primaryAction === "review-lockdown" ? props.onPrimaryStatusAction : undefined}
        />
        {props.recoveryStatus && !props.healthBroken ? (
          <p role="status" className="mt-3 text-sm font-medium text-emerald-800">{props.recoveryStatus}</p>
        ) : null}
      </div>
      {props.mutationError ? (
        <div className="mt-4">
          <InlineError message={props.mutationError} />
        </div>
      ) : null}
      {props.localCliError ? (
        <div className="mt-4">
          <InlineError message={props.localCliError} />
        </div>
      ) : null}

      <PatternSearchConsole
        catalog={visibleCatalog}
        effective={props.effective}
        active={props.active}
        query={query}
        onQueryChange={setQuery}
        onRefresh={props.onRefresh}
        onOpenExtension={props.onOpenExtension}
        actionSlot={searching ? <AddCustomExtensionButton onClick={props.onAddCustom} /> : null}
      />
      <CatalogFilterBar
        catalog={props.catalogExtensions}
        filters={filters}
        onChange={setFilters}
      />

      {searching ? null : (
        <>
          {addedCustomCount ? (
            <CustomExtensionsSection
              items={addedCustomItems}
              onOpen={props.onOpenLocalCli}
              onAdd={props.onAddCustom}
            />
          ) : null}

          <section className="mt-10" aria-labelledby="all-tools-heading">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 id="all-tools-heading" className="text-xl font-semibold tracking-tight text-brand-dark">All tools</h2>
                <p className="mt-1 text-sm text-slate-500">
                  {filtering
                    ? "Built-in tools that match the selected trust, kind, and area filters."
                    : "Every built-in tool Guard can watch on this device. Open one to adjust its command patterns."}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                {addedCustomCount ? null : <AddCustomExtensionButton onClick={props.onAddCustom} />}
                <span className="text-sm text-brand-dark/70" data-testid="catalog-tool-count" aria-live="polite">
                  {catalogFilterCountCopy(visibleCatalog.length, props.catalogExtensions.length, filtering)}
                </span>
              </div>
            </div>
            {visibleCatalog.length ? (
              <div className="mt-4">
                {visibleCatalog.map((extension) => (
                  <CatalogExtensionRow
                    key={extension.extension_id}
                    extension={extension}
                    effective={props.effective}
                    onOpen={props.onOpenExtension}
                  />
                ))}
              </div>
            ) : (
              <CatalogFilterEmpty onClear={handleClearFilters} />
            )}
          </section>
        </>
      )}

    </div>
  );
}
