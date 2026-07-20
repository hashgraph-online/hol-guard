import { useMemo, useState, memo, useCallback } from "react";
import {
  HiMiniChevronRight,
  HiMiniChevronLeft,
  HiMiniArrowTopRightOnSquare,
  HiMiniFunnel,
} from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import { guardActionDisposition } from "../guard-action";
import { harnessDisplayName, isDisplayableHarness, formatRelativeTime } from "../approval-center-utils";
import { detectCategory, getCategoryInfo } from "./categories";
import { guardAwareHref } from "../guard-api";
import { Sparkline } from "./sparkline";
import { ScopedEvidenceTable } from "./scoped-evidence-table";
import type { EvidenceDecision } from "./evidence-types";
import { filterByDecision } from "./evidence-filters";

interface AppTabProps {
  receipts: GuardReceipt[];
}

type AppDecisionFilter = EvidenceDecision;

function hashString(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return Math.abs(hash);
}

const HUE_PALETTE = [210, 160, 45, 280, 340, 120, 190, 25, 260, 80];

function harnessColor(harness: string): string {
  const hash = hashString(harness);
  const hue = HUE_PALETTE[hash % HUE_PALETTE.length];
  return `hsl(${hue} 70% 45%)`;
}

interface AppListCardProps {
  harness: string;
  items: GuardReceipt[];
  onSelect: (harness: string) => void;
}

function AppListCard({ harness, items, onSelect }: AppListCardProps) {
  const allowed = items.filter((r) => guardActionDisposition(r.policy_decision) === "allowed").length;
  const blocked = items.filter((r) => guardActionDisposition(r.policy_decision) === "blocked").length;
  const reviewed = items.filter((r) => guardActionDisposition(r.policy_decision) === "reviewed").length;
  const lastActive = items[0]?.timestamp;
  const color = harnessColor(harness);
  const handleClick = useCallback(() => onSelect(harness), [harness, onSelect]);

  return (
    <button
      onClick={handleClick}
      className="w-full rounded-2xl border border-slate-100 bg-white p-4 text-left transition-all hover:shadow-md hover:border-slate-200 shadow-sm"
    >
      <div className="flex items-center gap-3">
        <span
          className="inline-flex h-10 w-10 items-center justify-center rounded-full text-sm font-bold text-white shrink-0"
          style={{ backgroundColor: color }}
        >
          {harness[0]?.toUpperCase()}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-brand-dark truncate">{harnessDisplayName(harness)}</p>
          <p className="text-xs text-slate-500">
            {items.length} actions · {allowed} allowed · {reviewed} review · {blocked} stopped
          </p>
          {lastActive && (
            <p className="text-xs text-slate-400">Last active {formatRelativeTime(lastActive)}</p>
          )}
        </div>
        <HiMiniChevronRight className="h-4 w-4 text-slate-300 shrink-0" aria-hidden="true" />
      </div>
    </button>
  );
}

function AppTabRaw({ receipts }: AppTabProps) {
  const [selectedApp, setSelectedApp] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [decisionFilter, setDecisionFilter] = useState<AppDecisionFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("");

  const appReceipts = useMemo(
    () => receipts.filter((receipt) => isDisplayableHarness(receipt.harness)),
    [receipts]
  );

  const apps = useMemo(() => {
    const map = new Map<string, GuardReceipt[]>();
    for (const receipt of appReceipts) {
      if (!map.has(receipt.harness)) map.set(receipt.harness, []);
      map.get(receipt.harness)!.push(receipt);
    }
    for (const [, items] of map) {
      items.sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp));
    }
    return Array.from(map.entries()).sort((a, b) => b[1].length - a[1].length);
  }, [appReceipts]);

  const filteredApps = useMemo(() => {
    if (!searchTerm.trim()) return apps;
    const q = searchTerm.toLowerCase();
    return apps.filter(([harness]) => harnessDisplayName(harness).toLowerCase().includes(q));
  }, [apps, searchTerm]);

  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(e.target.value);
  }, []);

  const handleBack = useCallback(() => {
    setSelectedApp(null);
    setDecisionFilter("all");
    setCategoryFilter("");
  }, []);

  const handleSelectApp = useCallback((h: string) => {
    setSelectedApp(h);
    setDecisionFilter("all");
    setCategoryFilter("");
  }, []);

  const selectedItems = useMemo(() => {
    if (!selectedApp) return [];
    let items = apps.find(([h]) => h === selectedApp)?.[1] ?? [];
    if (decisionFilter !== "all") {
      items = filterByDecision(items, decisionFilter);
    }
    if (categoryFilter) {
      items = items.filter((r) => detectCategory(r) === categoryFilter);
    }
    return items;
  }, [apps, selectedApp, decisionFilter, categoryFilter]);

  const handleCategoryFilter = useCallback((category: string) => {
    setCategoryFilter(category);
  }, []);

  const handleDecisionFilterChange = useCallback((event: React.ChangeEvent<HTMLSelectElement>) => {
    const nextValue = event.target.value;
    if (nextValue === "all" || nextValue === "allow" || nextValue === "ask" || nextValue === "block") {
      setDecisionFilter(nextValue);
    }
  }, []);

  const categories = useMemo(() => {
    if (!selectedApp) return [];
    const allItems = apps.find(([h]) => h === selectedApp)?.[1] ?? [];
    return Array.from(new Set(allItems.map((r) => detectCategory(r))));
  }, [apps, selectedApp]);

  if (appReceipts.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm text-slate-500">No activity yet.</p>
        <p className="mt-1 text-xs text-slate-400">App activity will appear here after Guard makes decisions.</p>
      </div>
    );
  }

  if (selectedApp) {
    const allItems = apps.find(([h]) => h === selectedApp)?.[1] ?? [];
    const allowed = allItems.filter((r) => guardActionDisposition(r.policy_decision) === "allowed").length;
    const blocked = allItems.filter((r) => guardActionDisposition(r.policy_decision) === "blocked").length;
    const reviewed = allItems.filter((r) => guardActionDisposition(r.policy_decision) === "reviewed").length;
    const color = harnessColor(selectedApp);

    return (
      <div className="space-y-5">
        <div className="flex items-center gap-3">
          <button
            onClick={handleBack}
            className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-100"
          >
            <HiMiniChevronLeft className="h-4 w-4" aria-hidden="true" />
            Back
          </button>
          <a
            href={guardAwareHref(`/apps/${encodeURIComponent(selectedApp)}`)}
            className="ml-auto inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
            target="_blank"
            rel="noopener noreferrer"
          >
            Open app detail
            <HiMiniArrowTopRightOnSquare className="h-3 w-3" aria-hidden="true" />
          </a>
        </div>

        <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
          <div className="flex items-center gap-3">
            <span
              className="inline-flex h-12 w-12 items-center justify-center rounded-full text-sm font-bold text-white"
              style={{ backgroundColor: color }}
            >
              {selectedApp[0]?.toUpperCase()}
            </span>
            <div>
              <h2 className="text-base font-semibold text-brand-dark">{harnessDisplayName(selectedApp)}</h2>
              <p className="text-xs text-slate-500">
                {allItems.length} action{allItems.length !== 1 ? "s" : ""} · {allowed} allowed · {reviewed} review · {blocked} stopped
              </p>
            </div>
          </div>

          <Sparkline items={allItems} />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <HiMiniFunnel className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Filter:</span>
          </div>
          <select
            value={decisionFilter}
            onChange={handleDecisionFilterChange}
            className="min-h-7 rounded-lg border border-slate-200 bg-white px-2 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
          >
            <option value="all">All decisions</option>
            <option value="allow">Allowed</option>
            <option value="ask">Review</option>
            <option value="block">Stopped</option>
          </select>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="min-h-7 rounded-lg border border-slate-200 bg-white px-2 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
          >
            <option value="">All categories</option>
            {categories.map((cat) => {
              const info = getCategoryInfo(cat);
              return (
                <option key={cat} value={cat}>{info.label}</option>
              );
            })}
          </select>
          {(decisionFilter !== "all" || categoryFilter) && (
            <button
              type="button"
              onClick={() => { setDecisionFilter("all"); setCategoryFilter(""); }}
              className="text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
            >
              Clear filters
            </button>
          )}
        </div>

        <ScopedEvidenceTable
          receipts={selectedItems}
          exportFilters={{
            harness: selectedApp,
            decision: decisionFilter,
            category: categoryFilter,
          }}
          tableLabel={`${harnessDisplayName(selectedApp)} actions`}
          onFilterCategory={handleCategoryFilter}
        />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <label className="block">
        <span className="sr-only">Search apps</span>
        <input
          type="search"
          value={searchTerm}
          onChange={handleSearchChange}
          placeholder="Search apps..."
          className="min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </label>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {filteredApps.map(([harness, items]) => (
          <AppListCard
            key={harness}
            harness={harness}
            items={items}
            onSelect={handleSelectApp}
          />
        ))}
      </div>

      {filteredApps.length === 0 && (
        <div className="py-8 text-center">
          <p className="text-sm text-slate-500">No apps match your search.</p>
        </div>
      )}
    </div>
  );
}

export const AppTab = memo(AppTabRaw);
