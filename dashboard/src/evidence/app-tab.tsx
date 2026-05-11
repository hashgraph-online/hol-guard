import { useMemo, useState } from "react";
import { HiMiniChevronRight, HiMiniCheckCircle, HiMiniMinusCircle, HiMiniExclamationCircle } from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { plainEnglishDescription } from "./plain-english";
import { formatRelativeTime } from "../approval-center-utils";

interface AppTabProps {
  receipts: GuardReceipt[];
}

export function AppTab({ receipts }: AppTabProps) {
  const [selectedApp, setSelectedApp] = useState<string | null>(null);

  const apps = useMemo(() => {
    const map = new Map<string, GuardReceipt[]>();
    for (const receipt of receipts) {
      if (!map.has(receipt.harness)) map.set(receipt.harness, []);
      map.get(receipt.harness)!.push(receipt);
    }
    return Array.from(map.entries()).sort((a, b) => b[1].length - a[1].length);
  }, [receipts]);

  if (selectedApp) {
    const items = apps.find(([h]) => h === selectedApp)?.[1] ?? [];
    const allowed = items.filter((r) => r.policy_decision === "allow").length;
    const blocked = items.filter((r) => r.policy_decision === "block").length;

    return (
      <div className="space-y-6">
        <button
          onClick={() => setSelectedApp(null)}
          className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-100"
        >
          ← Back to apps
        </button>

        <div className="rounded-2xl border border-slate-100 bg-white/60 p-5">
          <h2 className="text-lg font-semibold text-brand-dark">{harnessDisplayName(selectedApp)}</h2>
          <p className="mt-1 text-sm text-slate-500">
            {items.length} action{items.length !== 1 ? "s" : ""} · {allowed} allowed · {blocked} stopped
          </p>
        </div>

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
                <span className={`shrink-0 text-xs font-medium ${receipt.policy_decision === "allow" ? "text-emerald-600" : "text-brand-attention"}`}>
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
      {apps.map(([harness, items]) => {
        const allowed = items.filter((r) => r.policy_decision === "allow").length;
        const blocked = items.filter((r) => r.policy_decision === "block").length;
        const lastActive = items[0]?.timestamp;

        return (
          <button
            key={harness}
            onClick={() => {
              setSelectedApp(harness);
            }}
            className="flex w-full items-center justify-between gap-3 rounded-2xl border border-slate-100 bg-white p-4 text-left shadow-sm transition-all hover:shadow-md"
          >
            <div className="flex items-center gap-3">
              <span className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-slate-50 text-brand-dark">
                {harness[0].toUpperCase()}
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

      {apps.length === 0 && (
        <div className="rounded-2xl border border-slate-100 bg-white/60 p-8 text-center">
          <p className="text-sm text-slate-500">No activity yet.</p>
        </div>
      )}
    </div>
  );
}
