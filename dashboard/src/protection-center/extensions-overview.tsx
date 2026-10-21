import { Fragment, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import { extensionEffectiveState } from "../extension-control-center-model";
import type { CatalogReadModel } from "../extension-catalog-v2";
import type { EffectiveExtensionControls, ExtensionCatalogSummary } from "../extension-controls-api";
import { fetchExtensionDiscoveryApi } from "../guard-api";
import {
  connectorWorkspaceItems,
  customExtensionNeedsReview,
  refreshCodexHostInventory,
  refreshMcpInventory,
  type LocalCliItem,
} from "../local-cli-api";
import { WorkspacePageHeader } from "../workspace-page-header";
import { useDiscoveryFeed, useJoinedDiscovery } from "./extensions-discovery-feed";
import { inFeedSlotIndexes, MIN_ORGANIC_ROWS_BEFORE_IN_FEED, orderFeaturedFirst } from "./extensions-discover-model";
import { CatalogSlotRow, ExtensionsSpotlight } from "./extensions-spotlight";
import {
  CATALOG_SLOT_PRODUCTS,
  slotInventoryLabel,
  slotStartingPrice,
  slotState,
} from "./extensions-spotlight-model";
import { useExtensionPopularity } from "./use-extension-popularity";
import { LocalSkillsWorkspace } from "./local-skills-workspace";
import { CodexHostConnectors } from "./codex-host-connectors";
import { AddCustomExtensionButton } from "./local-clis-panel";
import { CustomExtensionsSection } from "./custom-extensions-section";
import { ExtensionListSwitch, type ExtensionListView } from "./extensions-list-switch";
import { CatalogFilterBar, CatalogFilterTrigger } from "./components/catalog-filter-bar";
import { PatternSearchConsole } from "./components/pattern-search-console";
import { InlineError, ProtectionStatusHero } from "./components/protection-primitives";
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
import {
  CatalogExtensionRow,
  CatalogFilterEmpty,
  CatalogPostureSummary,
  ConnectorDiscoveryControl,
  ConnectorDiscoveryNotice,
  PaidCatalogRow,
} from "./extensions-catalog-rows";

export function ExtensionsOverview(props: {
  catalogExtensions: readonly ExtensionCatalogSummary[];
  readModel: CatalogReadModel;
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
  onOpenExtension: (extension: ExtensionCatalogSummary) => void;
  onOpenLocalCli: (cliId: string) => void;
  onAddCustom: (command?: string) => void;
}) {
  // One surface, one feed. Featured extensions lead the spotlight and the
  // catalog list. A device that turned sponsored discovery off gets nothing
  // back, and the page still works in full.
  const fetchPlacements = useCallback(
    () => fetchExtensionDiscoveryApi("/v1/discovery/extensions/placements"),
    [],
  );
  const discoveryFeed = useDiscoveryFeed(props.active, fetchPlacements);
  const joinedDiscovery = useJoinedDiscovery(discoveryFeed, props.catalogExtensions);
  const discoverySnapshotId = discoveryFeed.projection?.snapshot.snapshotId || null;
  const discoveryOffers = discoveryFeed.projection?.snapshot.offers ?? [];
  const popularity = useExtensionPopularity(props.active);
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
  const [listView, setListView] = useState<ExtensionListView>("builtin");
  const filterPanelId = useId();
  const builtinPanelId = useId();
  const customPanelId = useId();
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
  // The shelf holds three cells; paid placements beyond them must still get
  // their labeled row, or a maker can buy a placement that renders nowhere.
  const paidById = useMemo(
    () => new Map(
      // Featured last so it wins a collision: one extension can hold both a
      // featured and a sponsored placement, and the row must disclose and
      // measure the stronger one it is actually ranked for.
      [...joinedDiscovery.sponsored, ...joinedDiscovery.featured]
        .map((entry) => [entry.placement.extensionId, entry] as const),
    ),
    [joinedDiscovery.featured, joinedDiscovery.sponsored],
  );
  // Featured rows lead in server order (all-day before time windows).
  const orderedCatalog = useMemo(() => {
    const visibleIds = new Set(visibleCatalog.map((extension) => extension.extension_id));
    const featuredVisible = joinedDiscovery.featured
      .map((entry) => entry.catalog)
      .filter((extension) => visibleIds.has(extension.extension_id));
    // Exclude the featured ids by identity rather than by count: slicing
    // assumes the first N reordered entries are the featured ones, which is
    // false as soon as a sponsored id sorts ahead of a featured one - that
    // drops the sponsored row and renders a featured one twice.
    const featuredIds = new Set(joinedDiscovery.featured.map((entry) => entry.placement.extensionId));
    const sponsoredIds = new Set(
      joinedDiscovery.sponsored
        .map((entry) => entry.placement.extensionId)
        .filter((extensionId) => !featuredIds.has(extensionId)),
    );
    const rest = orderFeaturedFirst(
      visibleCatalog.filter((extension) => !featuredIds.has(extension.extension_id)),
      sponsoredIds,
    );
    return [...featuredVisible, ...rest];
  }, [joinedDiscovery.featured, joinedDiscovery.sponsored, visibleCatalog]);
  // Both surfaces ask, because they are different placements with their own
  // availability, and a reader scrolling the list should never have to scroll
  // back up to find the one that sits inside it. Neither waits for the server
  // to confirm a vacancy before asking; an authoritative sold-out is the one
  // answer that withdraws the row.
  const catalogSlot = slotState({
    status: discoveryFeed.status,
    offers: discoveryOffers,
    products: CATALOG_SLOT_PRODUCTS,
  });
  const catalogSlotOpen = !searching
    && !filtering
    && visibleCatalog.length >= MIN_ORGANIC_ROWS_BEFORE_IN_FEED
    && (catalogSlot === "open" || catalogSlot === "unconfirmed");
  const catalogSlotPrice = useMemo(
    () => slotStartingPrice(discoveryOffers, CATALOG_SLOT_PRODUCTS),
    [discoveryOffers],
  );
  const catalogSlotInventory = useMemo(
    () => slotInventoryLabel(discoveryOffers, CATALOG_SLOT_PRODUCTS),
    [discoveryOffers],
  );
  // Like a sponsored post in a feed, the offer recurs down a long list instead
  // of showing once near the top and never again.
  const catalogSlotIndexes = useMemo(() => new Set(inFeedSlotIndexes(orderedCatalog.length)), [orderedCatalog.length]);
  // The shelf states whether each extension is protecting this device right
  // now; it reads the same effective controls the rows below it read, and it
  // only ever reports that state - nothing on the shelf changes protection.
  const effective = props.effective;
  const isExtensionActive = useCallback(
    (extension: ExtensionCatalogSummary) => extensionEffectiveState(effective, extension) === "enabled",
    [effective],
  );

  const handleClearFilters = useCallback(() => {
    setFilters(EMPTY_CATALOG_FILTERS);
  }, []);
  const onAddCustom = props.onAddCustom;
  // The added tool lands in the custom list, so that is the list the reader
  // comes back to from the add flow, whichever list they started it from.
  const handleAddCustom = useCallback(() => {
    setListView("custom");
    onAddCustom();
  }, [onAddCustom]);
  const handleSetUpCustom = useCallback((command: string) => {
    setListView("custom");
    onAddCustom(command);
  }, [onAddCustom]);
  const allCustomItems = connectorWorkspaceItems(props.localCliItems, "", props.seededItems);
  const addedCustomItems = allCustomItems.filter((item) =>
    customItemMatchesFilters(item, filters),
  );
  const customItemsFilteredOut = filtering && allCustomItems.length > 0 && addedCustomItems.length === 0;
  // Filters narrow what the list shows, never what is waiting on a decision.
  const customNeedsReviewCount = allCustomItems.filter(customExtensionNeedsReview).length;
  // There is one Add action on screen at a time. With nothing added yet, the
  // custom list's own empty state carries it while that list is open; a search
  // carries it above the results; otherwise the switch does.
  const customEmptyOwnsAdd = listView === "custom" && allCustomItems.length === 0;
  const switchOffersAdd = !searching && !customEmptyOwnsAdd;
  const searchOffersAdd = searching && !customEmptyOwnsAdd;
  const discoveryMessage = [discoveryError, hostDiscoveryError].filter(Boolean).join(" ") || null;
  const retryDiscovery = useCallback(() => setDiscoveryAttempt((attempt) => attempt + 1), []);
  return (
    <div hidden={!props.active} inert={!props.active || undefined}>
      <WorkspacePageHeader
        eyebrow="On this device"
        title={PROTECTION_TERMS.pageTitle}
        description="Choose an Extension to review its permissions and effective protection."
        actions={
          <a
            className="guard-extensions-chip"
            data-testid="sponsor-extension-action"
            href="https://hol.org/guard/extensions/advertise?source=guard_local&intent=extension-promotion&placement=extensions_header"
            target="_blank"
            rel="noopener noreferrer"
            referrerPolicy="no-referrer"
          >
            Sponsor an extension
          </a>
        }
      />
      <div data-testid="extensions-surface">
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

      {searching ? null : (
        <ExtensionsSpotlight
          catalogExtensions={props.catalogExtensions}
          featured={joinedDiscovery.featured}
          sponsored={joinedDiscovery.sponsored}
          activity={popularity.counts}
          offers={discoveryOffers}
          status={discoveryFeed.status}
          snapshotId={discoverySnapshotId}
          settled={popularity.settled}
          isExtensionActive={isExtensionActive}
          onOpenExtension={props.onOpenExtension}
        />
      )}

      <div
        ref={filterToolbarRef}
        data-testid="catalog-filters"
      >
        <PatternSearchConsole
          catalog={visibleCatalog}
          readModel={props.readModel}
          effective={props.effective}
          active={props.active}
          query={query}
          onQueryChange={setQuery}
          onRefresh={props.onRefresh}
          onOpenExtension={props.onOpenExtension}
          actionSlot={searchOffersAdd ? <AddCustomExtensionButton onClick={handleAddCustom} /> : null}
          toolbarSlot={
            <CatalogFilterTrigger
              open={filterPanelOpen}
              activeCount={filters.trusts.length + filters.kinds.length + filters.areas.length}
              panelId={filterPanelId}
              buttonRef={filterTriggerRef}
              onToggle={() => setFilterPanelOpen((open) => !open)}
              />
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

      <ExtensionListSwitch
        view={listView}
        onViewChange={setListView}
        builtinCount={visibleCatalog.length}
        customCount={addedCustomItems.length}
        customNeedsReviewCount={customNeedsReviewCount}
        builtinPanelId={searching ? undefined : builtinPanelId}
        customPanelId={customPanelId}
        onAddCustom={switchOffersAdd ? handleAddCustom : undefined}
      />
      {props.active && listView === "builtin" ? (
        <ConnectorDiscoveryNotice error={discoveryMessage} onRetry={retryDiscovery} />
      ) : null}

      <div id={customPanelId} hidden={listView !== "custom"}>
        <CustomExtensionsSection
          embedded
          addInEmptyState={customEmptyOwnsAdd}
          items={addedCustomItems}
          onOpen={props.onOpenLocalCli}
          seededItems={addedCustomItems.filter((item) => item.seeded === true)}
          onSetUp={handleSetUpCustom}
          onAdd={handleAddCustom}
          discovering={discovering}
          filteredOut={customItemsFilteredOut}
          onClearFilters={handleClearFilters}
          discoveryControl={props.active && listView === "custom" ? (
            <ConnectorDiscoveryControl
              discovering={discovering}
              showProgress={addedCustomItems.length > 0 || customItemsFilteredOut}
              error={discoveryMessage}
              onRetry={retryDiscovery}
            />
          ) : null}
        />
      </div>

      {searching ? null : (
        <>
          <section id={builtinPanelId} hidden={listView !== "builtin"} className="mt-4" aria-labelledby="all-tools-heading">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 id="all-tools-heading" className="sr-only">All tools</h2>
                <p className="text-sm text-slate-500">
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
            {!filtering ? <CatalogPostureSummary extensions={props.catalogExtensions} effective={props.effective} /> : null}
            {visibleCatalog.length ? (
              <div className="mt-4">
                {orderedCatalog.map((extension, index) => {
                  const paid = paidById.get(extension.extension_id);
                  const row = paid ? (
                    <PaidCatalogRow
                      key={extension.extension_id}
                      entry={paid}
                      snapshotId={discoverySnapshotId}
                      effective={props.effective}
                      onOpen={props.onOpenExtension}
                    />
                  ) : (
                    <CatalogExtensionRow
                      key={extension.extension_id}
                      extension={extension}
                      effective={props.effective}
                      onOpen={props.onOpenExtension}
                    />
                  );
                  if (!catalogSlotOpen || !catalogSlotIndexes.has(index)) return row;
                  return (
                    <Fragment key={extension.extension_id}>
                      <CatalogSlotRow
                        state={catalogSlot === "open" ? "open" : "unconfirmed"}
                        price={catalogSlotPrice}
                        inventory={catalogSlotInventory}
                      />
                      {row}
                    </Fragment>
                  );
                })}
              </div>
            ) : (
              <CatalogFilterEmpty onClear={handleClearFilters} />
            )}
          </section>

          {/* Inspect-only sources sit below the catalog: they inform, they do not change protection. */}
          <CodexHostConnectors inventory={props.hostInventory} />
          <LocalSkillsWorkspace />
        </>
      )}
      </div>
    </div>
  );
}
