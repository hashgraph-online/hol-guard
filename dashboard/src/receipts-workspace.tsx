import { useCallback, useEffect, useMemo, useState, type ChangeEvent } from "react";

import {
  Badge,
  EmptyState,
  KeyValueGrid,
  ListControls,
  PaginationControls,
  SectionLabel,
  Surface,
  Tag
} from "./approval-center-primitives";
import { harnessDisplayName, policyActionLabel } from "./approval-center-utils";
import type { GuardReceipt } from "./guard-types";

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

const receiptPageSize = 8;
const EMPTY_RECEIPTS: GuardReceipt[] = [];

export function ReceiptsWorkspace(props: { receipts: ReceiptsState }) {
  const [searchTerm, setSearchTerm] = useState("");
  const [harnessFilter, setHarnessFilter] = useState("all");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [page, setPage] = useState(1);
  const receiptCount = props.receipts.kind === "ready" ? props.receipts.items.length : 0;

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(event.target.value);
  }, []);

  const handleHarnessFilterChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setHarnessFilter(event.target.value);
  }, []);

  const handleDecisionFilterChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setDecisionFilter(event.target.value);
  }, []);

  const handlePreviousPage = useCallback(() => {
    setPage((value) => Math.max(1, value - 1));
  }, []);

  useEffect(() => {
    setPage(1);
  }, [decisionFilter, harnessFilter, searchTerm, receiptCount]);

  const receiptItems = props.receipts.kind === "ready" ? props.receipts.items : EMPTY_RECEIPTS;

  const harnesses = useMemo(
    () => Array.from(new Set(receiptItems.map((receipt) => receipt.harness))).sort(),
    [receiptItems],
  );

  const decisions = useMemo(
    () => Array.from(new Set(receiptItems.map((receipt) => receipt.policy_decision))).sort(),
    [receiptItems],
  );

  const filteredReceipts = useMemo(() => {
    const normalizedSearchTerm = searchTerm.trim().toLowerCase();
    return receiptItems.filter((receipt) => {
      const matchesHarness = harnessFilter === "all" || receipt.harness === harnessFilter;
      const matchesDecision = decisionFilter === "all" || receipt.policy_decision === decisionFilter;
      if (!matchesHarness || !matchesDecision) {
        return false;
      }
      if (normalizedSearchTerm.length === 0) {
        return true;
      }
      const searchable = [
        receipt.artifact_name ?? "",
        receipt.artifact_id,
        receipt.artifact_hash,
        receipt.harness,
        receipt.policy_decision,
        receipt.capabilities_summary,
        sanitizeReceiptValue(receipt.provenance_summary),
        receipt.changed_capabilities.join(" ")
      ].join(" ").toLowerCase();
      return searchable.includes(normalizedSearchTerm);
    });
  }, [decisionFilter, harnessFilter, receiptItems, searchTerm]);

  const totalPages = Math.max(1, Math.ceil(filteredReceipts.length / receiptPageSize));
  const currentPage = Math.min(page, totalPages);
  const pageStart = (currentPage - 1) * receiptPageSize;
  const visibleReceipts = filteredReceipts.slice(pageStart, pageStart + receiptPageSize);

  const handleNextPage = useCallback(() => {
    setPage((value) => Math.min(totalPages, value + 1));
  }, [totalPages]);

  if (props.receipts.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-8 w-64" />
        <div className="guard-skeleton h-32 w-full" />
      </div>
    );
  }
  if (props.receipts.kind === "error") {
    return (
      <Surface tone="danger">
        <p className="text-sm text-brand-purple">{props.receipts.message}</p>
      </Surface>
    );
  }
  if (receiptItems.length === 0) {
    return (
      <EmptyState
        title="No history yet"
        body="Saved choices appear here after HOL Guard reviews or blocks an action."
      />
    );
  }

  return (
    <div className="space-y-6">
      <section className="guard-surface-in rounded-[2rem] border border-brand-blue/15 bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_62%,rgba(181,108,255,0.08)_100%)] p-5 shadow-[0_20px_60px_rgba(63,65,116,0.08)] sm:p-6 lg:p-7">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-1">
            <SectionLabel>History</SectionLabel>
            <h1 className="mt-2 text-3xl font-semibold tracking-[-0.02em] text-brand-dark">
            History
            </h1>
            <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">
              Search local choices by action, app, decision, or reason.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge tone="info">{props.receipts.items.length} saved</Badge>
            <Tag tone="slate">{filteredReceipts.length} shown</Tag>
          </div>
        </div>
      </section>

      <section className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
        <SectionLabel>Find history</SectionLabel>
        <div className="mt-3 space-y-2">
          <ListControls
            searchLabel="Search history"
            searchValue={searchTerm}
            searchPlaceholder="Search action, app, or reason"
            filterLabel="Filter history by app"
            filterValue={harnessFilter}
            filterOptions={harnesses}
            allLabel="All apps"
            onSearchChange={handleSearchChange}
            onFilterChange={handleHarnessFilterChange}
          />
          <label className="block sm:max-w-[180px]">
            <span className="sr-only">Filter evidence by decision</span>
            <select
              value={decisionFilter}
              onChange={handleDecisionFilterChange}
              className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors duration-150 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            >
              <option value="all">All decisions</option>
              {decisions.map((decision) => (
                <option key={decision} value={decision}>{decision}</option>
              ))}
            </select>
          </label>
        </div>
      </section>

      <section className="overflow-hidden rounded-[1.75rem] border border-slate-200/70 bg-white/80 shadow-sm">
        {visibleReceipts.length > 0 ? (
          <div className="divide-y divide-slate-200/70">
            {visibleReceipts.map((receipt) => (
              <HistoryRow key={receipt.receipt_id} receipt={receipt} />
            ))}
          </div>
        ) : (
          <div className="p-6">
            <EmptyState
              title="No matching history"
              body="Try a different action, app, decision, or reason filter."
            />
          </div>
        )}
      </section>
      <PaginationControls
        page={currentPage}
        totalPages={totalPages}
        totalItems={filteredReceipts.length}
        pageSize={receiptPageSize}
        onPrevious={handlePreviousPage}
        onNext={handleNextPage}
        className="rounded-[1.25rem] border border-slate-200/60 bg-white/80 px-4 py-3 shadow-sm"
      />
    </div>
  );
}

function HistoryRow(props: { receipt: GuardReceipt }) {
  const { receipt } = props;
  const changed = receipt.changed_capabilities.join(", ") || "Nothing recorded";
  const decisionTone = receipt.policy_decision === "allow" ? "green" : receipt.policy_decision === "block" ? "purple" : "blue";
  return (
    <article className="px-4 py-4 transition-colors duration-150 hover:bg-surface-1/70 sm:px-5">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_150px_120px] lg:items-start">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Tag tone={decisionTone}>{policyActionLabel(receipt.policy_decision)}</Tag>
            <span className="text-xs font-medium text-muted-foreground">{harnessDisplayName(receipt.harness)}</span>
          </div>
          <h2 className="mt-2 truncate text-sm font-semibold text-brand-dark">
            {receipt.artifact_name ?? receipt.artifact_id}
          </h2>
          <p className="mt-1 line-clamp-2 text-sm leading-6 text-muted-foreground">
            {receipt.capabilities_summary || sanitizeReceiptValue(receipt.provenance_summary)}
          </p>
        </div>
        <div className="rounded-xl border border-slate-200/70 bg-slate-50 px-3 py-2">
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Changed</p>
          <p className="mt-1 line-clamp-2 text-xs font-medium leading-relaxed text-brand-dark">{changed}</p>
        </div>
        <div className="text-xs font-medium text-muted-foreground lg:text-right">
          {receipt.timestamp}
        </div>
      </div>
      <details className="group mt-3">
        <summary className="inline-flex cursor-pointer select-none items-center gap-2 text-xs font-semibold text-brand-blue [&::-webkit-details-marker]:hidden">
          <span className="transition-transform duration-150 group-open:rotate-90">›</span>
          More details
        </summary>
        <div className="mt-3 rounded-xl border border-slate-200/70 bg-white p-3">
          <KeyValueGrid
            columns={2}
            items={[
              ["Action ID", receipt.artifact_id],
              ["Source", receipt.source_scope ?? "unknown"],
              ["Hash", receipt.artifact_hash],
              ["Saved detail", sanitizeReceiptValue(receipt.provenance_summary)]
            ]}
          />
        </div>
      </details>
    </article>
  );
}

function sanitizeReceiptValue(value: string): string {
  return value.replace(/\/Users\/[^/\s]+/g, "~");
}
