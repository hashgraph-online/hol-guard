import { useCallback, useState } from "react";
import { HiMiniMagnifyingGlass, HiMiniPlus, HiMiniXMark } from "react-icons/hi2";

import {
  connectorWorkspaceItems,
  customExtensionNeedsReview,
  type LocalCliItem,
} from "../local-cli-api";
import { ProtectionModuleRow } from "./components/protection-primitives";
import {
  continuityCopy,
  customExtensionRowDescription,
  customExtensionStateLabel,
} from "./local-cli-panel-copy";
import { mcpCatalogCopy } from "./mcp-catalog-state";

const CUSTOM_EXTENSION_PREVIEW_COUNT = 8;
const CUSTOM_EXTENSION_RENDER_LIMIT = 100;

function CustomExtensionRow(props: { item: LocalCliItem; onOpen: (cliId: string) => void }) {
  const cliId = props.item.cli_id;
  const onOpen = props.onOpen;
  const handleOpen = useCallback(() => {
    onOpen(cliId);
  }, [cliId, onOpen]);
  const continuity = continuityCopy(props.item);
  const catalog = mcpCatalogCopy(props.item);
  return (
    <ProtectionModuleRow
      extensionId={props.item.cli_id}
      name={props.item.name}
      description={customExtensionRowDescription(props.item, catalog?.title ?? null)}
      behavior={continuity ? `${continuity.title}. ${continuity.description}` : customExtensionStateLabel(props.item)}
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
 * preview their first rows behind a show-all control instead of paginating,
 * and the search appears once the list is long enough to search — and stays
 * while a query is active so it can always be edited or cleared.
 */
export function CustomExtensionsSection(props: {
  items: LocalCliItem[];
  onOpen: (cliId: string) => void;
  onAdd: () => void;
  discovering?: boolean;
  filteredOut?: boolean;
  onClearFilters?: () => void;
}) {
  const [search, setSearch] = useState("");
  const [showAll, setShowAll] = useState(false);
  const all = connectorWorkspaceItems(props.items);
  const added = search ? connectorWorkspaceItems(props.items, search) : all;
  const searchable = all.length > CUSTOM_EXTENSION_PREVIEW_COUNT || search !== "";
  const filteredOut = props.filteredOut === true && search === "";
  const needsReview = added.filter(customExtensionNeedsReview);
  const reviewed = added.filter((item) => !customExtensionNeedsReview(item));
  const grouped = needsReview.length > 0 && reviewed.length > 0;
  const expandedLimit = showAll ? CUSTOM_EXTENSION_RENDER_LIMIT : CUSTOM_EXTENSION_PREVIEW_COUNT;
  const visible = added.length > expandedLimit ? added.slice(0, expandedLimit) : added;
  const visibleNeedsReview = grouped ? visible.filter(customExtensionNeedsReview) : visible;
  const visibleReviewed = grouped ? visible.filter((item) => !customExtensionNeedsReview(item)) : [];
  const unit = added.length === 1 ? "extension" : "extensions";
  return (
    <section className="mt-10" aria-labelledby="custom-extensions-heading" data-testid="custom-extensions-section">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 id="custom-extensions-heading" className="text-xl font-semibold tracking-tight text-brand-dark">Custom extensions</h2>
          <p className="mt-1 text-sm text-slate-500">Connectors Guard detected in your apps, plus tools you add yourself. Open one to choose its permissions.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {searchable ? (
            <div className="relative min-w-0 flex-1 sm:flex-none">
              <label className="relative block">
                <span className="sr-only">Search custom extensions</span>
                <HiMiniMagnifyingGlass className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/55" aria-hidden="true" />
                <input type="search" value={search}
                  onChange={(event) => { setSearch(event.target.value); setShowAll(false); }}
                  placeholder="Search connectors"
                  className="min-h-11 w-full rounded-xl border border-slate-300 bg-white pl-9 pr-3 text-sm font-normal text-brand-dark sm:w-64" />
              </label>
            </div>
          ) : null}
          <button type="button" onClick={props.onAdd} className="inline-flex min-h-11 shrink-0 items-center gap-2 rounded-xl px-3 text-sm font-semibold text-brand-blue">
            <HiMiniPlus className="size-4" aria-hidden="true" />
            Add custom extension
          </button>
        </div>
      </div>
      {added.length === 0 ? (
        <CustomExtensionEmptyState
          search={search}
          filteredOut={filteredOut}
          discovering={props.discovering}
          onAdd={props.onAdd}
          onClearFilters={props.onClearFilters}
          onClearSearch={() => setSearch("")}
        />
      ) : (
        <div className="mt-4">
          {grouped && visibleNeedsReview.length > 0 ? (
            <p className="text-xs font-semibold text-brand-dark/55">
              Needs review · {needsReview.length}
            </p>
          ) : null}
          {visibleNeedsReview.map((item) => (
            <CustomExtensionRow key={item.cli_id} item={item} onOpen={props.onOpen} />
          ))}
          {grouped && visibleReviewed.length > 0 ? (
            <p className="mt-6 text-xs font-semibold text-brand-dark/55">
              Reviewed · {reviewed.length}
            </p>
          ) : null}
          {visibleReviewed.map((item) => (
            <CustomExtensionRow key={item.cli_id} item={item} onOpen={props.onOpen} />
          ))}
          {added.length > visible.length ? (
            <div className="mt-4 flex flex-wrap items-center gap-3">
              {showAll ? null : (
                <button type="button" onClick={() => setShowAll(true)}
                  className="min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark">
                  {added.length > CUSTOM_EXTENSION_RENDER_LIMIT
                    ? `Show first ${CUSTOM_EXTENSION_RENDER_LIMIT}`
                    : `Show all ${added.length} ${unit}`}
                </button>
              )}
              <p className="text-sm text-brand-dark/70">
                Showing {visible.length} of {added.length}. Search to narrow the list.
              </p>
            </div>
          ) : null}
          {showAll && added.length > CUSTOM_EXTENSION_PREVIEW_COUNT ? (
            <button type="button" onClick={() => setShowAll(false)}
              className="mt-4 min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-brand-dark">
              Show fewer
            </button>
          ) : null}
        </div>
      )}
    </section>
  );
}
