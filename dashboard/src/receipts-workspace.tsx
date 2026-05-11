import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniBookOpen,
  HiMiniTag,
  HiMiniComputerDesktop,
  HiMiniChartBar,
  HiOutlineArrowDownTray,
  HiOutlineListBullet,
  HiOutlineCalendarDays,
  HiMiniChevronDown,
  HiMiniChevronUp,
} from "react-icons/hi2";

import {
  Badge,
  EmptyState,
  SectionLabel,
  GuardHero,
} from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime } from "./approval-center-utils";
import type { GuardReceipt } from "./guard-types";
import { guardAwareHref } from "./guard-api";
import { useKeyboardShortcut } from "./use-keyboard-shortcut";
import { exportReceiptsAsCsv, exportReceiptsAsJson, downloadBlob } from "./history-export";
import { StoryTab, CategoryTab, AppTab, ExploreTab } from "./evidence";

type TabKey = "story" | "category" | "app" | "explore";
type TimeFilter = "all" | "today" | "yesterday" | "week" | "last7d" | "last30d";
type DecisionFilter = "all" | "allow" | "block";

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

const TIME_FILTER_VALUES: TimeFilter[] = ["all", "today", "yesterday", "week", "last7d", "last30d"];
const DECISION_FILTER_VALUES: DecisionFilter[] = ["all", "allow", "block"];

const TAB_CONFIG: { key: TabKey; label: string; icon: React.ElementType }[] = [
  { key: "story", label: "Story", icon: HiMiniBookOpen },
  { key: "category", label: "Category", icon: HiMiniTag },
  { key: "app", label: "App", icon: HiMiniComputerDesktop },
  { key: "explore", label: "Explore", icon: HiMiniChartBar },
];

export function ReceiptsWorkspace(props: { receipts: ReceiptsState }) {
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
      <div className="rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4">
        <p className="text-sm text-brand-dark">{props.receipts.message}</p>
      </div>
    );
  }
  return <ReadyReceiptsWorkspace receiptItems={props.receipts.items} />;
}

function readUrlParams(): {
  search: string;
  time: TimeFilter;
  decision: DecisionFilter;
  harness: string;
  tab: TabKey;
  day: string;
} {
  const params = new URLSearchParams(window.location.search);
  const time = params.get("time") as TimeFilter;
  const decision = params.get("decision") as DecisionFilter;
  const tab = params.get("tab") as TabKey;
  return {
    search: params.get("search") ?? "",
    time: TIME_FILTER_VALUES.includes(time) ? time : "all",
    decision: DECISION_FILTER_VALUES.includes(decision) ? decision : "all",
    harness: params.get("harness") ?? "all",
    tab: TAB_CONFIG.some((t) => t.key === tab) ? tab : "story",
    day: params.get("day") ?? "",
  };
}

function writeUrlParams(params: {
  search: string;
  time: TimeFilter;
  decision: DecisionFilter;
  harness: string;
  tab: TabKey;
  day: string;
}) {
  const url = new URL(window.location.href);
  url.search = "";
  if (params.search) url.searchParams.set("search", params.search);
  if (params.time !== "all") url.searchParams.set("time", params.time);
  if (params.decision !== "all") url.searchParams.set("decision", params.decision);
  if (params.harness !== "all") url.searchParams.set("harness", params.harness);
  if (params.tab !== "story") url.searchParams.set("tab", params.tab);
  if (params.day) url.searchParams.set("day", params.day);
  window.history.replaceState({}, "", url.toString());
}

function timeFilterLabel(filter: TimeFilter): string {
  switch (filter) {
    case "today": return "Today";
    case "yesterday": return "Yesterday";
    case "week": return "This week";
    case "last7d": return "Last 7 days";
    case "last30d": return "Last 30 days";
    default: return "All time";
  }
}

function ReadyReceiptsWorkspace(props: { receiptItems: GuardReceipt[] }) {
  const initial = useMemo(() => readUrlParams(), []);
  const [search, setSearch] = useState(initial.search);
  const [timeFilter, setTimeFilter] = useState<TimeFilter>(initial.time);
  const [decisionFilter, setDecisionFilter] = useState<DecisionFilter>(initial.decision);
  const [activeTab, setActiveTab] = useState<TabKey>(initial.tab);
  const [dayFilter, setDayFilter] = useState<string>(initial.day);
  const [harnessFilter, setHarnessFilter] = useState<string>(initial.harness);

  const harnesses = useMemo(
    () => Array.from(new Set(props.receiptItems.map((r) => r.harness))).sort(),
    [props.receiptItems]
  );

  useEffect(() => {
    if (harnessFilter !== "all" && !harnesses.includes(harnessFilter)) {
      setHarnessFilter("all");
    }
  }, [harnesses, harnessFilter]);

  useEffect(() => {
    writeUrlParams({ search, time: timeFilter, decision: decisionFilter, harness: harnessFilter, tab: activeTab, day: dayFilter });
  }, [search, timeFilter, decisionFilter, harnessFilter, activeTab, dayFilter]);

  const filtered = useMemo(() => {
    let items = props.receiptItems;
    if (decisionFilter !== "all") {
      items = items.filter((r) => r.policy_decision === decisionFilter);
    }
    if (harnessFilter !== "all") {
      items = items.filter((r) => r.harness === harnessFilter);
    }
    if (timeFilter !== "all") {
      const now = new Date();
      const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const startOfYesterday = new Date(startOfToday);
      startOfYesterday.setDate(startOfYesterday.getDate() - 1);
      const startOfWeek = new Date(startOfToday);
      startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());
      const startOfLast7d = new Date(startOfToday);
      startOfLast7d.setDate(startOfLast7d.getDate() - 7);
      const startOfLast30d = new Date(startOfToday);
      startOfLast30d.setDate(startOfLast30d.getDate() - 30);
      items = items.filter((r) => {
        const d = new Date(r.timestamp);
        if (timeFilter === "today") return d >= startOfToday;
        if (timeFilter === "yesterday") return d >= startOfYesterday && d < startOfToday;
        if (timeFilter === "week") return d >= startOfWeek;
        if (timeFilter === "last7d") return d >= startOfLast7d;
        if (timeFilter === "last30d") return d >= startOfLast30d;
        return true;
      });
    }
    if (dayFilter) {
      const dayStart = new Date(dayFilter);
      const dayEnd = new Date(dayStart);
      dayEnd.setDate(dayEnd.getDate() + 1);
      items = items.filter((r) => {
        const d = new Date(r.timestamp);
        return d >= dayStart && d < dayEnd;
      });
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter((r) =>
        (r.artifact_name ?? r.artifact_id).toLowerCase().includes(q) ||
        r.harness.toLowerCase().includes(q)
      );
    }
    return items.sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp));
  }, [props.receiptItems, decisionFilter, harnessFilter, timeFilter, search, dayFilter]);

  const handleFilterDay = useCallback((day: string) => {
    setDayFilter(day);
    setTimeFilter("all");
  }, []);

  const totalCount = props.receiptItems.length;

  if (totalCount === 0) {
    return (
      <EmptyState
        title="No history yet"
        body="Saved choices appear here after HOL Guard reviews or blocks an action."
        tone="teach"
      />
    );
  }

  return (
    <div className="space-y-6">
      <GuardHero
        status="clear"
        headline="History"
        subheadline="What Guard decided."
        cta={<Badge tone="info">{totalCount} saved</Badge>}
      />

      {/* Category filter bar */}
      <div className="flex flex-wrap items-center gap-1.5">
        {(
          [
            { key: "all" as const, label: "All" },
            { key: "secret" as const, label: "Secrets" },
            { key: "network" as const, label: "Network" },
            { key: "destructive" as const, label: "Destructive" },
            { key: "hidden" as const, label: "Hidden" },
            { key: "other" as const, label: "Other" },
          ] as const
        ).map((c) => (
          <button
            key={c.key}
            className={`rounded-full px-3 py-1.5 text-xs font-medium transition-all ${
              search === c.key
                ? "bg-brand-blue text-white shadow-sm"
                : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
            }`}
            onClick={() => setSearch(search === c.key ? "" : c.key)}
          >
            {c.label}
          </button>
        ))}
        <span className="mx-1 h-4 w-px bg-slate-200" />
        <select
          value={harnessFilter}
          onChange={(e) => setHarnessFilter(e.target.value)}
          className="h-8 rounded-md border-0 bg-transparent px-2 py-1 text-xs font-medium text-brand-dark hover:bg-slate-100 focus:bg-slate-100 focus:outline-none"
        >
          <option value="all">All apps</option>
          {harnesses.map((h) => (
            <option key={h} value={h}>{harnessDisplayName(h)}</option>
          ))}
        </select>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 rounded-xl border border-slate-200/70 bg-white/80 p-1 shadow-sm">
        {TAB_CONFIG.map((t) => {
          const Icon = t.icon;
          const isActive = activeTab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className={`flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${
                isActive
                  ? "bg-brand-blue text-white shadow-sm"
                  : "text-brand-dark hover:bg-slate-50"
              }`}
            >
              <Icon className="h-4 w-4" />
              <span className="hidden sm:inline">{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div className="min-h-[300px]">
        {activeTab === "story" && (
          <StoryTab receipts={filtered} selectedDay={dayFilter} onSelectDay={handleFilterDay} />
        )}
        {activeTab === "category" && (
          <CategoryTab receipts={filtered} onFilterCategory={(cat) => setSearch(cat)} />
        )}
        {activeTab === "app" && (
          <AppTab receipts={filtered} onFilterApp={(app) => setHarnessFilter(app)} />
        )}
        {activeTab === "explore" && (
          <ExploreTab
            receipts={props.receiptItems}
            filteredReceipts={filtered}
            filters={{ search, time: timeFilter, decision: decisionFilter, harness: harnessFilter }}
            onFilterDay={handleFilterDay}
          />
        )}
      </div>
    </div>
  );
}

export function filterReceiptItems(
  items: GuardReceipt[],
  searchTerm: string,
  harnessFilter: string,
  decisionFilter: string,
  dateRange: string
): GuardReceipt[] {
  const normalizedSearchTerm = searchTerm.trim().toLowerCase();
  const now = Date.now();
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayStartMs = todayStart.getTime();
  const last7Start = now - 7 * 24 * 60 * 60 * 1000;
  return items.filter((receipt) => {
    const matchesHarness = harnessFilter === "all" || receipt.harness === harnessFilter;
    const matchesDecision = decisionFilter === "all" || receipt.policy_decision === decisionFilter;
    if (!matchesHarness || !matchesDecision) {
      return false;
    }
    if (dateRange === "today" || dateRange === "last7") {
      const ts = new Date(receipt.timestamp).getTime();
      if (dateRange === "today" && ts < todayStartMs) {
        return false;
      } else if (dateRange === "last7" && ts < last7Start) {
        return false;
      }
    }
    if (normalizedSearchTerm.length === 0) {
      return true;
    }
    const name = (receipt.artifact_name ?? receipt.artifact_id).toLowerCase();
    return name.includes(normalizedSearchTerm);
  });
}
