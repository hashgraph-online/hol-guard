import { useState, useMemo, useCallback, useEffect, memo } from "react";
import {
  HiMiniExclamationTriangle,
} from "react-icons/hi2";
import { EmptyState, SectionLabel } from "../approval-center-primitives";
import { formatRelativeTime } from "../approval-center-utils";
import { detectCategory, CATEGORIES } from "../evidence/categories";
import type { GuardReceipt, GuardApprovalRequest } from "../guard-types";
import { ReceiptGroup } from "./app-receipt-components";

type AppActivityTabProps = {
  harness: string;
  pendingItems: GuardApprovalRequest[];
  harnessReceipts: GuardReceipt[];
  onOpenRequest: (requestId: string) => void;
  queueError: string | null;
  onRetry: () => void;
};

export const AppActivityTab = memo(function AppActivityTab(props: AppActivityTabProps) {
  const [filter, setFilter] = useState<"all" | "pending" | "allowed" | "blocked">("all");
  const [timeFilter, setTimeFilter] = useState<"all" | "today" | "week">("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [search, setSearch] = useState("");
  const [showFilters, setShowFilters] = useState(false);

  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value);
  }, []);

  const filteredReceipts = useMemo(() => {
    let items = props.harnessReceipts;
    if (filter === "allowed") items = items.filter((r) => r.policy_decision === "allow");
    if (filter === "blocked") items = items.filter((r) => r.policy_decision === "block");
    if (timeFilter === "today") {
      const start = new Date();
      start.setHours(0, 0, 0, 0);
      items = items.filter((r) => new Date(r.timestamp) >= start);
    }
    if (timeFilter === "week") {
      const start = new Date();
      start.setDate(start.getDate() - 7);
      items = items.filter((r) => new Date(r.timestamp) >= start);
    }
    if (categoryFilter) {
      items = items.filter((r) => detectCategory(r) === categoryFilter);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter((r) =>
        (r.artifact_name ?? r.artifact_id).toLowerCase().includes(q)
      );
    }
    return items;
  }, [props.harnessReceipts, filter, timeFilter, search, categoryFilter]);

  const groups = useMemo(() => {
    const today: GuardReceipt[] = [];
    const yesterday: GuardReceipt[] = [];
    const thisWeek: GuardReceipt[] = [];
    const earlier: GuardReceipt[] = [];
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfYesterday = new Date(startOfToday);
    startOfYesterday.setDate(startOfYesterday.getDate() - 1);
    const startOfWeek = new Date(startOfToday);
    startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());

    filteredReceipts.forEach((r) => {
      const d = new Date(r.timestamp);
      if (d >= startOfToday) today.push(r);
      else if (d >= startOfYesterday) yesterday.push(r);
      else if (d >= startOfWeek) thisWeek.push(r);
      else earlier.push(r);
    });
    return { today, yesterday, thisWeek, earlier };
  }, [filteredReceipts]);

  const hasPending = props.pendingItems.length > 0;

  return (
    <div className="space-y-6">
      {props.queueError && (
        <div className="guard-fade-in rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5">
          <div className="flex items-start gap-3">
            <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
            <div className="flex-1">
              <p className="text-sm font-medium text-brand-dark">Unable to load activity</p>
              <p className="mt-1 text-sm text-muted-foreground">{props.queueError}</p>
              <button
                onClick={props.onRetry}
                className="mt-3 inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
              >
                Retry
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
        <div className="flex flex-wrap items-center gap-2">
          {(
            [
              { key: "all" as const, label: "All" },
              { key: "pending" as const, label: `Pending (${props.pendingItems.length})` },
              { key: "allowed" as const, label: "Allowed" },
              { key: "blocked" as const, label: "Stopped" },
            ] as const
          ).map((c) => (
            <button
              key={c.key}
              onClick={() => setFilter(c.key)}
              className={`rounded-full px-3 py-1.5 text-xs font-medium transition-all ${
                filter === c.key
                  ? "bg-brand-blue text-white shadow-sm"
                  : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
              }`}
            >
              {c.label}
            </button>
          ))}
          <span className="mx-1 h-4 w-px bg-slate-200" />
          <button
            onClick={() => setShowFilters((s) => !s)}
            className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-brand-dark transition-all hover:bg-slate-50"
          >
            {showFilters ? "Hide filters" : "Filters"}
          </button>
        </div>

        {showFilters && (
          <div className="guard-fade-in mt-3 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3">
            {CATEGORIES.slice(0, 5).map((cat) => (
              <button
                key={cat.key}
                onClick={() => setCategoryFilter(categoryFilter === cat.key ? "" : cat.key)}
                className={`rounded-full px-2.5 py-1 text-[10px] font-medium uppercase tracking-wider transition-all ${
                  categoryFilter === cat.key
                    ? `${cat.color} bg-slate-50 shadow-sm`
                    : "border border-slate-200 bg-white text-slate-500 hover:bg-slate-50"
                }`}
              >
                {cat.label}
              </button>
            ))}
            <div className="ml-auto flex gap-2">
              {(
                [
                  { key: "all" as const, label: "All time" },
                  { key: "today" as const, label: "Today" },
                  { key: "week" as const, label: "This week" },
                ] as const
              ).map((c) => (
                <button
                  key={c.key}
                  onClick={() => setTimeFilter(c.key)}
                  className={`rounded-full px-3 py-1.5 text-xs font-medium transition-all ${
                    timeFilter === c.key
                      ? "bg-brand-dark text-white shadow-sm"
                      : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </div>
        )}

        <input
          value={search}
          onChange={handleSearchChange}
          placeholder="Search by name..."
          className="mt-3 w-full rounded-xl border border-slate-200/70 bg-white px-4 py-2.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </div>

      {filter === "pending" && hasPending && (
        <div className="space-y-3">
          {props.pendingItems.map((item) => (
            <button
              key={item.request_id}
              onClick={() => props.onOpenRequest(item.request_id)}
              className="flex w-full items-center justify-between rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-3 text-left transition-shadow hover:shadow-sm"
            >
              <div className="min-w-0">
                <p className="text-sm font-medium text-brand-dark">{item.artifact_name ?? item.artifact_id}</p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {item.artifact_type} · {formatRelativeTime(item.created_at)}
                </p>
              </div>
              <span className="rounded-full bg-brand-blue/10 px-2 py-0.5 text-[10px] font-medium text-brand-blue">
                Pending
              </span>
            </button>
          ))}
        </div>
      )}

      {filter !== "pending" && (
        <div className="space-y-6">
          {filteredReceipts.length === 0 ? (
            <EmptyState
              title="No activity yet"
              body={
                filter === "all"
                  ? "Guard hasn't recorded any decisions for this app yet. Allow or stop an action and it will appear here."
                  : `No ${filter} decisions match your filters.`
              }
              tone="teach"
            />
          ) : (
            <>
              <ReceiptGroup title="Today" items={groups.today} />
              <ReceiptGroup title="Yesterday" items={groups.yesterday} />
              <ReceiptGroup title="This week" items={groups.thisWeek} />
              <ReceiptGroup title="Earlier" items={groups.earlier} />
            </>
          )}
        </div>
      )}
    </div>
  );
});
