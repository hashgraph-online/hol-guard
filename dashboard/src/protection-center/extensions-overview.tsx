import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import {
  catalogRowSecondLine,
  extensionDisplayName,
  extensionStateLabel,
} from "../extension-control-center-model";
import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../extension-controls-api";
import { connectorWorkspaceItems, refreshCodexHostInventory, refreshMcpInventory, type LocalCliItem } from "../local-cli-api";
import { WorkspacePageHeader } from "../workspace-page-header";
import { LocalSkillsWorkspace } from "./local-skills-workspace";
import { CodexHostConnectors } from "./codex-host-connectors";
import { AddCustomExtensionButton } from "./local-clis-panel";
import { CustomExtensionsSection } from "./custom-extensions-section";
import { CatalogFilterBar, CatalogFilterTrigger } from "./components/catalog-filter-bar";
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

function ConnectorDiscoveryControl(props: {
  discovering: boolean;
  error: string | null;
  onRetry: () => void;
}) {
  if (props.discovering) {
    return (
      <p role="status" className="px-1 text-xs text-brand-dark/60">
        Checking host connections…
      </p>
    );
  }
  return (
    <div className="flex items-center gap-2">
      {props.error ? (
        <p role="status" className="max-w-56 truncate text-xs text-brand-dark/60" title={props.error}>
          {props.error}
        </p>
      ) : null}
      <button type="button" className="guard-extensions-chip" onClick={props.onRetry}>
        {props.error ? "Check for connectors again" : "Check host connections"}
      </button>
    </div>
  );
}

function CatalogFilterEmpty(props: { onClear: () => void }) {
  return (
    <div className="mt-6 rounded-2xl border border-[rgba(63,65,116,0.12)] bg-white px-4 py-6">
      <p className="text-sm font-semibold text-brand-dark">No extensions match these filters.</p>
      <p className="mt-1 text-sm leading-6 text-brand-dark/70">Remove a filter or start over to see the full catalog again.</p>
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
  seededItems?: LocalCliItem[];
  hostInventory?: import("../codex-host-inventory").CodexHostInventory;
  localCliError: string | null;
  localCliNotice: string | null;
  mutationError: string | null;
  recoveryStatus: string | null;
  healthBroken: boolean;
  status: ProtectionStatusView;
  active: boolean;
  onPrimaryStatusAction?: () => void;
  onRefresh: () => Promise<void> | void;
  onReloadConnections: () => Promise<unknown> | void;
  onOpenExtension: (extension: ExtensionCatalogItem) => void;
  onOpenLocalCli: (cliId: string) => void;
  onAddCustom: (command?: string) => void;
}) {
  const [query, setQuery] = useState("");
  const discoveryStarted = useRef(false);
  const reloadConnections = useRef(props.onReloadConnections);
  reloadConnections.current = props.onReloadConnections;
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);
  const [hostDiscoveryError, setHostDiscoveryError] = useState<string | null>(null);
  const [discovering, setDiscovering] = useState(false);
  const [discoveryAttempt, setDiscoveryAttempt] = useState(0);
  useEffect(() => {
    if (!props.active || discoveryStarted.current) return;
    discoveryStarted.current = true;
    const controller = new AbortController();
    setDiscovering(true);
    setDiscoveryError(null);
    setHostDiscoveryError(null);
    const reload = async () => { if (!controller.signal.aborted) await reloadConnections.current(); };
    const configured = refreshMcpInventory("inventory:configured", controller.signal, true, discoveryAttempt > 0)
      .then(reload).catch(() => {
        if (!controller.signal.aborted) setDiscoveryError("Could not check host configuration. Known connections remain available.");
      });
    let hostRunning = false;
    const refreshHost = async (force: boolean) => {
      if (hostRunning || controller.signal.aborted) return;
      hostRunning = true;
      try {
        await refreshCodexHostInventory(controller.signal, force);
        if (!controller.signal.aborted) setHostDiscoveryError(null);
      } catch {
        if (!controller.signal.aborted) setHostDiscoveryError("Could not read Codex app inventory. Known connections remain available.");
      } finally {
        await reload();
        hostRunning = false;
      }
    };
    const host = refreshHost(discoveryAttempt > 0);
    const hostTimer = window.setInterval(() => {
      if (!document.hidden) void refreshHost(true);
    }, 25_000);
    void Promise.all([configured, host]).finally(() => {
      if (!controller.signal.aborted) setDiscovering(false);
    });
    return () => { window.clearInterval(hostTimer); controller.abort(); discoveryStarted.current = false; };
  }, [props.active, discoveryAttempt]);
  const [filters, setFilters] = useState<CatalogFilterState>(EMPTY_CATALOG_FILTERS);
  const [filterPanelOpen, setFilterPanelOpen] = useState(false);
  const filterPanelId = useId();
  const filterTriggerRef = useRef<HTMLButtonElement>(null);
  const filterToolbarRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setFilters((current) => {
      const next = pruneCatalogFilters(current, props.catalogExtensions);
      if (catalogFiltersEqual(current, next)) return current;
      return next;
    });
  }, [props.catalogExtensions]);
  // The filter popover overlays the catalog at sm+, so opening it must not
  // strand the operator's scroll position: dismiss on any outside pointer.
  useEffect(() => {
    if (!filterPanelOpen) return;
    const onPointerDown = (event: PointerEvent) => {
      if (filterToolbarRef.current?.contains(event.target as Node)) return;
      setFilterPanelOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      // A modal dialog (e.g. the policy review sheet) owns Escape while open.
      if (document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      setFilterPanelOpen(false);
      filterTriggerRef.current?.focus();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [filterPanelOpen]);
  // "f" mirrors the existing "/" search shortcut for the filter popover.
  useEffect(() => {
    if (!props.active) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "f" || event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) return;
      // Never move focus out of a modal dialog such as the policy review sheet.
      if (document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) return;
      event.preventDefault();
      setFilterPanelOpen(true);
      filterTriggerRef.current?.focus();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [props.active]);
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
  const onAddCustom = props.onAddCustom;
  const handleAddCustom = useCallback(() => { onAddCustom(); }, [onAddCustom]);
  const allCustomItems = connectorWorkspaceItems(props.localCliItems, "", props.seededItems);
  const addedCustomItems = allCustomItems.filter((item) =>
    customItemMatchesFilters(item, filters),
  );
  const customItemsFilteredOut = filtering && allCustomItems.length > 0 && addedCustomItems.length === 0;
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
      {props.localCliNotice ? (
        <p role="status" className="mt-4 rounded-xl border border-brand-blue/20 bg-brand-blue/5 p-3 text-sm text-brand-dark">
          {props.localCliNotice}
        </p>
      ) : null}

      <div
        ref={filterToolbarRef}
        data-testid="catalog-filters"
      >
        <PatternSearchConsole
          catalog={visibleCatalog}
          effective={props.effective}
          active={props.active}
          query={query}
          onQueryChange={setQuery}
          onRefresh={props.onRefresh}
          onOpenExtension={props.onOpenExtension}
          actionSlot={searching ? <AddCustomExtensionButton onClick={handleAddCustom} /> : null}
          toolbarSlot={
            <>
              <CatalogFilterTrigger
                open={filterPanelOpen}
                activeCount={filters.trusts.length + filters.kinds.length + filters.areas.length}
                panelId={filterPanelId}
                buttonRef={filterTriggerRef}
                onToggle={() => setFilterPanelOpen((open) => !open)}
              />
              {props.active ? (
                <ConnectorDiscoveryControl
                  discovering={discovering}
                  error={[discoveryError, hostDiscoveryError].filter(Boolean).join(" ") || null}
                  onRetry={() => setDiscoveryAttempt((attempt) => attempt + 1)}
                />
              ) : null}
            </>
          }
          subtoolbarSlot={
            <CatalogFilterBar
              catalog={props.catalogExtensions}
              filters={filters}
              onChange={setFilters}
              open={filterPanelOpen}
              onOpenChange={setFilterPanelOpen}
              panelId={filterPanelId}
              onAfterClear={() => filterTriggerRef.current?.focus()}
            />
          }
        />
      </div>

      {searching ? null : (
        <>
          <CustomExtensionsSection
            items={addedCustomItems}
            onOpen={props.onOpenLocalCli}
            seededItems={addedCustomItems.filter((item) => item.seeded === true)}
            onSetUp={props.onAddCustom}
            onAdd={handleAddCustom}
            discovering={discovering}
            filteredOut={customItemsFilteredOut}
            onClearFilters={handleClearFilters}
          />

          <LocalSkillsWorkspace />
          <CodexHostConnectors inventory={props.hostInventory} />
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
