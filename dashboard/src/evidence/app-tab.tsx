import { useMemo, useState, memo, useCallback } from "react";
import {
  HiMiniChevronRight,
  HiMiniCheckCircle,
  HiMiniNoSymbol,
} from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import { harnessDisplayName, isDisplayableHarness } from "../approval-center-utils";
import { plainEnglishDescription } from "./plain-english";
import { formatRelativeTime } from "../approval-center-utils";
import { guardAwareHref } from "../guard-api";

interface AppTabProps {
  receipts: GuardReceipt[];
}

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

function AppTabRaw({ receipts }: AppTabProps) {
  const [selectedApp, setSelectedApp] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const appReceipts = useMemo(() => receipts.filter((receipt) => isDisplayableHarness(receipt.harness)), [receipts]);

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

  if (appReceipts.length === 0) {
    return (
      <div className="rounded-2xl border border-slate-100 bg-white/60 p-8 text-center">
        <p className="text-sm text-slate-500">No activity yet.</p>
        <p className="mt-1 text-xs text-slate-400">App activity will appear here after Guard makes decisions.</p>
      </div>
    );
  }

  if (selectedApp) {
    const items = apps.find(([h]) => h === selectedApp)?.[1] ?? [];
    const allowed = items.filter((r) => r.policy_decision === "allow").length;
    const blocked = items.filter((r) => r.policy_decision === "block").length;
    const color = harnessColor(selectedApp);

    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setSelectedApp(null)}
            className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-100"
          >
            ← Back to apps
          </button>
          <a
            href={guardAwareHref(`/apps/${encodeURIComponent(selectedApp)}`)}
            className="ml-auto text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
            target="_blank"
            rel="noopener noreferrer"
          >
            Open app detail →
          </a>
        </div>

        <div className="rounded-2xl border border-slate-100 bg-white/60 p-5">
          <div className="flex items-center gap-3">
            <span
              className="inline-flex h-10 w-10 items-center justify-center rounded-full text-sm font-bold text-white"
              style={{ backgroundColor: color }}
            >
              {selectedApp[0]?.toUpperCase()}
            </span>
            <div>
              <h2 className="text-lg font-semibold text-brand-dark">{harnessDisplayName(selectedApp)}</h2>
              <p className="text-sm text-slate-500">
                {items.length} action{items.length !== 1 ? "s" : ""} · {allowed} allowed · {blocked} stopped
              </p>
            </div>
          </div>
        </div>

        <AppSparkline items={items} />

        <div className="space-y-3">
          {items.map((receipt) => (
            <div
              key={receipt.receipt_id}
              className="rounded-2xl border border-slate-100 bg-white p-4 shadow-sm"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-brand-dark">{plainEnglishDescription(receipt)}</p>
                  <p className="mt-1 text-xs text-slate-400">{formatRelativeTime(receipt.timestamp)}</p>
                </div>
                <span className={`shrink-0 text-xs font-medium ${receipt.policy_decision === "allow" ? "text-brand-green" : "text-brand-attention"}`}>
                  {receipt.policy_decision === "allow" ? "Allowed" : "Stopped"}
                </span>
              </div>
            </div>
          ))}
        </div>
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
          className="min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </label>

      {filteredApps.map(([harness, items]) => {
        const allowed = items.filter((r) => r.policy_decision === "allow").length;
        const blocked = items.filter((r) => r.policy_decision === "block").length;
        const lastActive = items[0]?.timestamp;
        const color = harnessColor(harness);

        return (
          <button
            key={harness}
            onClick={() => {
              setSelectedApp(harness);
            }}
            className="flex w-full items-center justify-between gap-3 rounded-2xl border border-slate-100 bg-white p-4 text-left shadow-sm transition-all hover:shadow-md"
          >
            <div className="flex items-center gap-3">
              <span
                className="inline-flex h-10 w-10 items-center justify-center rounded-full text-sm font-bold text-white"
                style={{ backgroundColor: color }}
              >
                {harness[0]?.toUpperCase()}
              </span>
              <div>
                <p className="text-sm font-medium text-brand-dark">{harnessDisplayName(harness)}</p>
                <p className="text-xs text-slate-500">
                  {items.length} actions · {allowed} allowed · {blocked} stopped
                </p>
                {lastActive && (
                  <p className="text-xs text-slate-400">Last active {formatRelativeTime(lastActive)}</p>
                )}
              </div>
            </div>
            <HiMiniChevronRight className="h-4 w-4 text-slate-300" aria-hidden="true" />
          </button>
        );
      })}

      {filteredApps.length === 0 && (
        <div className="rounded-2xl border border-slate-100 bg-white/60 p-8 text-center">
          <p className="text-sm text-slate-500">No apps match your search.</p>
        </div>
      )}
    </div>
  );
}

function AppSparkline({ items }: { items: GuardReceipt[] }) {
  const buckets = useMemo(() => {
    const days = 7;
    const now = new Date();
    const counts: number[] = new Array(days).fill(0);
    for (const item of items) {
      const d = new Date(item.timestamp);
      const diff = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
      if (diff >= 0 && diff < days) {
        counts[days - 1 - diff] += 1;
      }
    }
    return counts;
  }, [items]);

  const max = Math.max(...buckets, 1);
  const width = 200;
  const height = 40;
  const barWidth = width / buckets.length;

  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-4">
      <p className="text-xs font-medium text-slate-500">Last 7 days</p>
      <svg viewBox={`0 0 ${width} ${height}`} className="mt-2 h-10 w-full" preserveAspectRatio="none">
        {buckets.map((count, i) => {
          const barHeight = (count / max) * height;
          return (
            <rect
              key={i}
              x={i * barWidth + 1}
              y={height - barHeight}
              width={barWidth - 2}
              height={barHeight}
              rx={2}
              fill="currentColor"
              className="text-brand-blue/30"
            />
          );
        })}
      </svg>
    </div>
  );
}

export const AppTab = memo(AppTabRaw);
