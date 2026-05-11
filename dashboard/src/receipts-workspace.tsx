import { useCallback, useEffect, useMemo, useState, type ChangeEvent } from "react";
import {
  HiMiniChevronDown,
  HiMiniChevronUp,
} from "react-icons/hi2";

import {
  Badge,
  EmptyState,
  SectionLabel,
  Tag,
  GuardHero,
} from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime } from "./approval-center-utils";
import type { GuardReceipt } from "./guard-types";
import { guardAwareHref } from "./guard-api";

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

type TimeFilter = "all" | "today" | "yesterday" | "week";
type DecisionFilter = "all" | "allow" | "block";

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
      <div className="rounded-[1.75rem] border border-brand-attention/15 bg-brand-attention/[0.04] p-6">
        <p className="text-sm text-brand-dark">{props.receipts.message}</p>
      </div>
    );
  }
  return <ReadyReceiptsWorkspace receiptItems={props.receipts.items} />;
}

function readUrlParams(): { search: string; time: TimeFilter; decision: DecisionFilter; harness: string } {
  const params = new URLSearchParams(window.location.search);
  const time = params.get("time") as TimeFilter;
  const decision = params.get("decision") as DecisionFilter;
  return {
    search: params.get("search") ?? "",
    time: ["all", "today", "yesterday", "week"].includes(time) ? time : "all",
    decision: ["all", "allow", "block"].includes(decision) ? decision : "all",
    harness: params.get("harness") ?? "all",
  };
}

function writeUrlParams(params: { search: string; time: TimeFilter; decision: DecisionFilter; harness: string }) {
  const url = new URL(window.location.href);
  url.search = "";
  if (params.search) url.searchParams.set("search", params.search);
  if (params.time !== "all") url.searchParams.set("time", params.time);
  if (params.decision !== "all") url.searchParams.set("decision", params.decision);
  if (params.harness !== "all") url.searchParams.set("harness", params.harness);
  window.history.replaceState({}, "", url.toString());
}

function ReadyReceiptsWorkspace(props: { receiptItems: GuardReceipt[] }) {
  const initial = useMemo(() => readUrlParams(), []);
  const [search, setSearch] = useState(initial.search);
  const [timeFilter, setTimeFilter] = useState<TimeFilter>(initial.time);
  const [decisionFilter, setDecisionFilter] = useState<DecisionFilter>(initial.decision);

  const harnesses = useMemo(
    () => Array.from(new Set(props.receiptItems.map((r) => r.harness))).sort(),
    [props.receiptItems]
  );
  const [harnessFilter, setHarnessFilter] = useState<string>(
    initial.harness !== "all" && harnesses.includes(initial.harness) ? initial.harness : "all"
  );

  useEffect(() => {
    if (harnessFilter !== "all" && !harnesses.includes(harnessFilter)) {
      setHarnessFilter("all");
    }
  }, [harnesses, harnessFilter]);

  useEffect(() => {
    writeUrlParams({ search, time: timeFilter, decision: decisionFilter, harness: harnessFilter });
  }, [search, timeFilter, decisionFilter, harnessFilter]);

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
      items = items.filter((r) => {
        const d = new Date(r.timestamp);
        if (timeFilter === "today") return d >= startOfToday;
        if (timeFilter === "yesterday") return d >= startOfYesterday && d < startOfToday;
        if (timeFilter === "week") return d >= startOfWeek;
        return true;
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
  }, [props.receiptItems, decisionFilter, harnessFilter, timeFilter, search]);

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

    filtered.forEach((r) => {
      const d = new Date(r.timestamp);
      if (d >= startOfToday) today.push(r);
      else if (d >= startOfYesterday) yesterday.push(r);
      else if (d >= startOfWeek) thisWeek.push(r);
      else earlier.push(r);
    });
    return { today, yesterday, thisWeek, earlier };
  }, [filtered]);

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
        subheadline="What Guard decided. Filter by time, app, or decision."
        cta={<Badge tone="info">{totalCount} saved</Badge>}
      />

      <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
        <div className="flex flex-wrap items-center gap-2">
          <FilterChip
            active={decisionFilter === "all"}
            onClick={() => setDecisionFilter("all")}
          >
            All
          </FilterChip>
          <FilterChip
            active={decisionFilter === "allow"}
            onClick={() => setDecisionFilter("allow")}
          >
            Allowed
          </FilterChip>
          <FilterChip
            active={decisionFilter === "block"}
            onClick={() => setDecisionFilter("block")}
          >
            Blocked
          </FilterChip>
          <div className="mx-2 h-5 w-px bg-slate-200" />
          <FilterChip
            active={timeFilter === "all"}
            onClick={() => setTimeFilter("all")}
          >
            All time
          </FilterChip>
          <FilterChip
            active={timeFilter === "today"}
            onClick={() => setTimeFilter("today")}
          >
            Today
          </FilterChip>
          <FilterChip
            active={timeFilter === "yesterday"}
            onClick={() => setTimeFilter("yesterday")}
          >
            Yesterday
          </FilterChip>
          <FilterChip
            active={timeFilter === "week"}
            onClick={() => setTimeFilter("week")}
          >
            This week
          </FilterChip>
          <div className="mx-2 h-5 w-px bg-slate-200" />
          <select
            value={harnessFilter}
            onChange={(e) => setHarnessFilter(e.target.value)}
            className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          >
            <option value="all">All apps</option>
            {harnesses.map((h) => (
              <option key={h} value={h}>{harnessDisplayName(h)}</option>
            ))}
          </select>
        </div>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by name or app..."
          className="mt-3 w-full rounded-xl border border-slate-200/70 bg-white px-4 py-2.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </div>

      {/* Active filter chips */}
      {(search || decisionFilter !== "all" || timeFilter !== "all" || harnessFilter !== "all") && (
        <div className="flex flex-wrap items-center gap-2">
          {search && (
            <ActiveFilterChip onClick={() => setSearch("")}>
              Search: {search}
            </ActiveFilterChip>
          )}
          {decisionFilter !== "all" && (
            <ActiveFilterChip onClick={() => setDecisionFilter("all")}>
              {decisionFilter === "allow" ? "Allowed" : "Blocked"}
            </ActiveFilterChip>
          )}
          {timeFilter !== "all" && (
            <ActiveFilterChip onClick={() => setTimeFilter("all")}>
              {timeFilter === "today" ? "Today" : timeFilter === "yesterday" ? "Yesterday" : "This week"}
            </ActiveFilterChip>
          )}
          {harnessFilter !== "all" && (
            <ActiveFilterChip onClick={() => setHarnessFilter("all")}>
              {harnessDisplayName(harnessFilter)}
            </ActiveFilterChip>
          )}
          <button
            onClick={() => {
              setSearch("");
              setDecisionFilter("all");
              setTimeFilter("all");
              setHarnessFilter("all");
            }}
            className="ml-1 text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
          >
            Clear all
          </button>
        </div>
      )}

      {filtered.length === 0 ? (
        <EmptyState
          title="No matching history"
          body="Try different filters or search terms."
          tone="teach"
        />
      ) : (
        <div className="space-y-6">
          <ReceiptGroup title="Today" items={groups.today} />
          <ReceiptGroup title="Yesterday" items={groups.yesterday} />
          <ReceiptGroup title="This week" items={groups.thisWeek} />
          <ReceiptGroup title="Earlier" items={groups.earlier} />
        </div>
      )}
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full px-3 py-1.5 text-xs font-medium transition-all ${
        active
          ? "bg-brand-blue text-white shadow-sm"
          : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
      }`}
    >
      {children}
    </button>
  );
}

function ActiveFilterChip({
  onClick,
  children,
}: {
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1 rounded-full border border-brand-blue/30 bg-brand-blue/[0.08] px-3 py-1.5 text-xs font-medium text-brand-blue transition-all hover:bg-brand-blue/15"
    >
      {children}
      <span className="ml-0.5 text-brand-blue/70">×</span>
    </button>
  );
}

function getGroupCollapsedKey(title: string): string {
  return `guard-history-group-${title.toLowerCase().replace(/\s+/g, "-")}`;
}

function ReceiptGroup({ title, items }: { title: string; items: GuardReceipt[] }) {
  const storageKey = getGroupCollapsedKey(title);
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(storageKey) === "true";
    } catch {
      return false;
    }
  });
  if (items.length === 0) return null;
  const toggle = () => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(storageKey, String(next));
      } catch {
        // ignore
      }
      return next;
    });
  };
  return (
    <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6 transition-shadow duration-200 hover:shadow-md">
      <button
        onClick={toggle}
        className="flex w-full items-center justify-between text-left"
        aria-expanded={!collapsed}
      >
        <SectionLabel>{title}</SectionLabel>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">{items.length} events</span>
          {collapsed ? (
            <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
          ) : (
            <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
          )}
        </div>
      </button>
      {!collapsed && (
        <div className="mt-4 space-y-3">
          {items.map((receipt) => (
            <HistoryRow key={receipt.receipt_id} receipt={receipt} />
          ))}
        </div>
      )}
    </div>
  );
}

function HistoryRow({ receipt }: { receipt: GuardReceipt }) {
  const [expanded, setExpanded] = useState(false);
  const decisionLabel = receipt.policy_decision === "allow" ? "Allowed" : "Blocked";
  const name = receipt.artifact_name ?? receipt.artifact_id;
  const appHref = guardAwareHref(`/apps/${receipt.harness}`);
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white overflow-hidden">
      <div className="flex items-start justify-between gap-3 px-4 py-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm text-brand-dark">
            <span className="font-medium">{decisionLabel}</span>{" "}
            <span className="font-mono text-xs">{name}</span>
            <span className="mx-1 text-slate-300">·</span>
            <a
              href={appHref}
              className="text-xs text-brand-blue hover:text-brand-dark transition-colors"
            >
              {harnessDisplayName(receipt.harness)}
            </a>
          </p>
          {receipt.capabilities_summary && (
            <p className="mt-1 text-xs text-muted-foreground">{receipt.capabilities_summary}</p>
          )}
          <p className="mt-1 text-[11px] text-muted-foreground">{formatRelativeTime(receipt.timestamp)}</p>
        </div>
        <div className="flex items-center gap-2">
          <Tag tone={receipt.policy_decision === "allow" ? "green" : "attention"}>
            {receipt.policy_decision}
          </Tag>
          <button
            onClick={() => setExpanded(!expanded)}
            className="rounded-lg p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-brand-dark"
            aria-label={expanded ? "Hide details" : "Show details"}
            aria-expanded={expanded}
          >
            {expanded ? (
              <HiMiniChevronUp className="h-4 w-4" aria-hidden="true" />
            ) : (
              <HiMiniChevronDown className="h-4 w-4" aria-hidden="true" />
            )}
          </button>
        </div>
      </div>
      {expanded && (
        <div className="guard-fade-in border-t border-slate-200/70 bg-slate-50/60 px-4 py-3">
          <dl className="grid grid-cols-1 gap-2 text-xs">
            <div>
              <dt className="text-muted-foreground">Action ID</dt>
              <dd className="mt-0.5 font-mono text-brand-dark">{receipt.artifact_id}</dd>
            </div>
            {receipt.artifact_hash && (
              <div>
                <dt className="text-muted-foreground">Hash</dt>
                <dd className="mt-0.5 font-mono text-brand-dark">{receipt.artifact_hash}</dd>
              </div>
            )}
            {receipt.capabilities_summary && (
              <div>
                <dt className="text-muted-foreground">Capabilities</dt>
                <dd className="mt-0.5 text-brand-dark">{receipt.capabilities_summary}</dd>
              </div>
            )}
            {receipt.provenance_summary && (
              <div>
                <dt className="text-muted-foreground">Provenance</dt>
                <dd className="mt-0.5 text-brand-dark">{receipt.provenance_summary}</dd>
              </div>
            )}
            <div>
              <dt className="text-muted-foreground">Time</dt>
              <dd className="mt-0.5 font-mono text-brand-dark">{new Date(receipt.timestamp).toLocaleString()}</dd>
            </div>
          </dl>
        </div>
      )}
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
