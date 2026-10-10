import { type ChangeEvent, useCallback, useId, useMemo, useState } from "react";
import { HiMiniMagnifyingGlass, HiMiniPlus, HiMiniXMark } from "react-icons/hi2";

import {
  connectorWorkspaceItems,
  customExtensionNeedsReview,
  type LocalCliItem,
} from "../local-cli-api";
import { ProtectionModuleRow } from "./components/protection-primitives";
import {
  customExtensionBadge,
  customExtensionDisplayName,
  profileSetupCommand,
} from "./custom-extension-profile";
import {
  continuityCopy,
  customExtensionActionLabel,
  customExtensionRowDescription,
  customExtensionStateLabel,
} from "./local-cli-panel-copy";
import { mcpCatalogCopy } from "./mcp-catalog-state";

const CUSTOM_EXTENSION_PREVIEW_COUNT = 8;
const CUSTOM_EXTENSION_PAGE_SIZE = 25;

function CustomExtensionRow(props: {
  item: LocalCliItem; onOpen: (cliId: string) => void; onSetUp?: (command: string) => void;
}) {
  const { item, onOpen, onSetUp } = props;
  const handleOpen = useCallback(() => {
    const setup = item.seeded === true ? profileSetupCommand(item) : null;
    if (setup !== null && onSetUp) onSetUp(setup);
    else onOpen(item.cli_id);
  }, [item, onOpen, onSetUp]);
  const action = customExtensionActionLabel(item);
  const continuity = continuityCopy(props.item);
  const catalog = mcpCatalogCopy(props.item);
  return (
    <ProtectionModuleRow
      extensionId={props.item.cli_id}
      name={customExtensionDisplayName(props.item)}
      description={customExtensionRowDescription(props.item, catalog?.title ?? null)}
      behavior={continuity ? `${continuity.title}. ${continuity.description}` : customExtensionStateLabel(props.item)}
      brand={props.item.brand}
      badge={customExtensionBadge(props.item) ?? undefined}
      actionLabel={action ?? undefined}
      custom
      executables={[props.item.name]}
      onOpen={handleOpen}
    />
  );
}

function CustomExtensionEmptyState(props: {
  search: string;
  filteredOut: boolean;
  discovering?: boolean;
  onAdd: () => void;
  onClearFilters?: () => void;
  onClearSearch: () => void;
}) {
  let title = "No custom extensions yet.";
  let detail = "Add a tool you run yourself, or connect an MCP server. Guard also detects connectors from your host apps automatically.";
  if (props.search) {
    title = "No custom extensions match this search.";
    detail = "No connectors or custom tools match this search.";
  }
  if (props.filteredOut) {
    title = "No custom extensions match these filters.";
    detail = "Remove a filter or start over to see all custom extensions again.";
  }
  return (
    <div
      className="mt-4 rounded-2xl border border-[rgba(63,65,116,0.12)] bg-white px-4 py-6"
      data-testid={props.filteredOut ? "custom-extensions-filter-empty" : "custom-extensions-empty"}
    >
      <p className="text-sm font-semibold text-brand-dark">{title}</p>
      <p className="mt-1 max-w-xl text-sm leading-6 text-brand-dark/70">{detail}</p>
      {props.filteredOut ? (
        props.onClearFilters ? (
          <button type="button" onClick={props.onClearFilters} className="guard-extensions-chip mt-3">
            <HiMiniXMark className="size-4" aria-hidden="true" />
            Clear filters
          </button>
        ) : null
      ) : props.search ? (
        <button type="button" onClick={props.onClearSearch} className="guard-extensions-chip mt-3">
          <HiMiniXMark className="size-4" aria-hidden="true" />
          Clear search
        </button>
      ) : (
        <>
          <button type="button" onClick={props.onAdd} className="mt-3 inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark">
            <HiMiniPlus className="size-4" aria-hidden="true" />
            Add custom extension
          </button>
          {props.discovering ? (
            <p role="status" className="mt-3 text-sm text-brand-dark/75">Checking host configuration for connectors…</p>
          ) : null}
        </>
      )}
    </div>
  );
}

/**
 * The custom extensions list. Always rendered on the catalog page so the
 * add-your-own entry point never disappears: with nothing to show it renders
 * an empty state instead of unmounting. Rows group into needs-review and
 * reviewed using the same attention signal that orders them, long lists
 * preview their first rows before expanding into bounded pages,
 * and the search appears once the list is long enough to search — and stays
 * while a query is active so it can always be edited or cleared.
 */
interface CustomExtensionsSectionProps {
  items: LocalCliItem[];
  seededItems?: LocalCliItem[];
  onSetUp?: (command: string) => void;
  onOpen: (cliId: string) => void;
  onAdd: () => void;
  discovering?: boolean;
  filteredOut?: boolean;
  onClearFilters?: () => void;
}

export function CustomExtensionsSection(props: CustomExtensionsSectionProps) {
  const [search, setSearch] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [page, setPage] = useState(0);
  const rowsId = useId();
  const all = useMemo(() => connectorWorkspaceItems(props.items, "", props.seededItems), [props.items, props.seededItems]);
  const added = useMemo(() => search ? connectorWorkspaceItems(props.items, search, props.seededItems) : all,
    [props.items, props.seededItems, search, all]);
  const searchable = all.length > CUSTOM_EXTENSION_PREVIEW_COUNT || search !== "";
  const filteredOut = props.filteredOut === true && search === "";
  const needsReview = added.filter(customExtensionNeedsReview);
  const reviewed = added.filter((item) => !customExtensionNeedsReview(item));
  const grouped = needsReview.length > 0 && reviewed.length > 0;
  const pageCount = Math.max(1, Math.ceil(added.length / CUSTOM_EXTENSION_PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearch(event.target.value);
    setShowAll(false);
    setPage(0);
  }, []);
  const handleClearSearch = useCallback(() => { setSearch(""); setPage(0); }, []);
  const handleExpand = useCallback(() => { setShowAll(true); setPage(0); }, []);
  const handleCollapse = useCallback(() => { setShowAll(false); setPage(0); }, []);
  const handlePrevious = useCallback(() => { if (currentPage > 0) setPage(currentPage - 1); }, [currentPage]);
  const handleNext = useCallback(() => {
    if (currentPage < pageCount - 1) setPage(currentPage + 1);
  }, [currentPage, pageCount]);
  const start = showAll ? currentPage * CUSTOM_EXTENSION_PAGE_SIZE : 0;
  const visible = added.slice(start, start + (showAll ? CUSTOM_EXTENSION_PAGE_SIZE : CUSTOM_EXTENSION_PREVIEW_COUNT));
  const visibleNeedsReview = grouped ? visible.filter(customExtensionNeedsReview) : visible;
  const visibleReviewed = grouped ? visible.filter((item) => !customExtensionNeedsReview(item)) : [];
  const unit = added.length === 1 ? "extension" : "extensions";
  return (
    <section className="mt-10" aria-labelledby="custom-extensions-heading" data-testid="custom-extensions-section">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 id="custom-extensions-heading" className="text-xl font-semibold tracking-tight text-brand-dark">Custom extensions</h2>
          <p className="mt-1 max-w-xl text-sm text-slate-500">Connectors Guard detected in your apps, plus tools you add yourself. Open one to choose its permissions.</p>
        </div>
        <button type="button" onClick={props.onAdd} className="inline-flex min-h-11 shrink-0 items-center gap-2 self-start rounded-xl px-3 text-sm font-semibold text-brand-blue sm:self-end">
          <HiMiniPlus className="size-4" aria-hidden="true" />
          Add custom extension
        </button>
      </div>
      {searchable ? (
        <div className="mt-4">
          <label className="relative block w-full max-w-sm">
            <span className="sr-only">Search custom extensions</span>
            <HiMiniMagnifyingGlass className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/55" aria-hidden="true" />
            <input type="search" value={search}
              onChange={handleSearchChange}
              placeholder="Search connectors"
              className="min-h-11 w-full rounded-xl border border-slate-300 bg-white pl-9 pr-3 text-sm font-normal text-brand-dark" />
          </label>
        </div>
      ) : null}
      {added.length === 0 ? (
        <CustomExtensionEmptyState
          search={search}
          filteredOut={filteredOut}
          discovering={props.discovering}
          onAdd={props.onAdd}
          onClearFilters={props.onClearFilters}
          onClearSearch={handleClearSearch}
        />
      ) : (
        <div className="mt-4" id={rowsId}>
          {grouped && visibleNeedsReview.length > 0 ? (
            <p className="text-xs font-semibold text-brand-dark/55">
              Needs review · {needsReview.length}
            </p>
          ) : null}
          {visibleNeedsReview.map((item) => (
            <CustomExtensionRow key={item.cli_id} item={item} onOpen={props.onOpen} onSetUp={props.onSetUp} />
          ))}
          {grouped && visibleReviewed.length > 0 ? (
            <p className="mt-6 text-xs font-semibold text-brand-dark/55">
              Reviewed · {reviewed.length}
            </p>
          ) : null}
          {visibleReviewed.map((item) => (
            <CustomExtensionRow key={item.cli_id} item={item} onOpen={props.onOpen} onSetUp={props.onSetUp} />
          ))}
          {!showAll && added.length > visible.length ? (
            <div className="mt-4 flex flex-wrap items-center gap-3">
                <button type="button" onClick={handleExpand} aria-controls={rowsId}
                  className="min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark">
                  {added.length > CUSTOM_EXTENSION_PAGE_SIZE
                    ? `Browse all ${added.length} ${unit}`
                    : `Show all ${added.length} ${unit}`}
                </button>
              <p className="text-sm text-brand-dark/70">
                Showing {visible.length} of {added.length}. Search to narrow the list.
              </p>
            </div>
          ) : null}
          {showAll && added.length > CUSTOM_EXTENSION_PREVIEW_COUNT ? (
            <div className="mt-4 flex flex-wrap items-center gap-3">
              {pageCount > 1 ? (
                <nav aria-label="Custom extension pages" className="flex flex-wrap items-center gap-3">
                  <button type="button" aria-disabled={currentPage === 0} aria-controls={rowsId}
                    onClick={handlePrevious}
                    className="min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark aria-disabled:opacity-50">
                    Previous page
                  </button>
                  <p role="status" className="text-sm text-brand-dark/70 tabular-nums">
                    Page {currentPage + 1} of {pageCount} · Showing {start + 1}–{start + visible.length} of {added.length}
                  </p>
                  <button type="button" aria-disabled={currentPage === pageCount - 1} aria-controls={rowsId}
                    onClick={handleNext}
                    className="min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark aria-disabled:opacity-50">
                    Next page
                  </button>
                </nav>
              ) : null}
              <button type="button" onClick={handleCollapse} aria-controls={rowsId}
                className="min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark">
                Show fewer
              </button>
            </div>
          ) : null}
        </div>
      )}
    </section>
  );
}
