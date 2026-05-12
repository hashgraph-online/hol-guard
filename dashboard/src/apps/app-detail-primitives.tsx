import { useMemo, memo } from "react";
import {
  HiMiniChartBar,
  HiMiniExclamationTriangle,
  HiMiniCloud,
  HiMiniChevronRight,
} from "react-icons/hi2";
import {
  Badge,
  SectionLabel,
  Tag,
} from "../approval-center-primitives";
import { formatRelativeTime } from "../approval-center-utils";
import type { GuardReceipt } from "../guard-types";
import type { AppStatus, TabKey } from "./app-types";

export function AppStatusBadge({ status }: { status: AppStatus }) {
  if (status === "active") return <Badge tone="success">Active</Badge>;
  if (status === "needs_setup") return <Badge tone="attention">Needs setup</Badge>;
  if (status === "observed") return <Badge tone="default">Observed</Badge>;
  return <Badge tone="default">Unknown</Badge>;
}

export function StatCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "green" | "attention" | "blue" | "slate";
}) {
  const toneClass =
    tone === "green"
      ? "text-brand-green"
      : tone === "attention"
      ? "text-brand-attention"
      : tone === "blue"
      ? "text-brand-blue"
      : "text-brand-dark";
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white p-3 text-center">
      <p className={`text-xl font-semibold ${toneClass}`}>{value}</p>
      <p className="mt-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
    </div>
  );
}

export const ActivitySparkline = memo(function ActivitySparkline({
  receipts,
}: {
  receipts: GuardReceipt[];
}) {
  const days = 7;
  const data = useMemo(() => {
    const result: { date: string; allowed: number; blocked: number }[] = [];
    const now = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      const end = new Date(d);
      end.setDate(end.getDate() + 1);
      const dayReceipts = receipts.filter((r) => {
        const rt = new Date(r.timestamp);
        return rt >= d && rt < end;
      });
      result.push({
        date: d.toLocaleDateString("en-US", { weekday: "short" }),
        allowed: dayReceipts.filter((r) => r.policy_decision === "allow").length,
        blocked: dayReceipts.filter((r) => r.policy_decision === "block").length,
      });
    }
    return result;
  }, [receipts]);

  const maxVal = Math.max(...data.map((d) => d.allowed + d.blocked), 1);

  return (
    <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
      <div className="flex items-center justify-between">
        <SectionLabel>Last 7 days</SectionLabel>
        <HiMiniChartBar className="h-4 w-4 text-slate-400" aria-hidden="true" />
      </div>
      <div className="mt-4 flex items-end gap-2">
        {data.map((day) => {
          const total = day.allowed + day.blocked;
          const height = total > 0 ? Math.max(20, (total / maxVal) * 100) : 4;
          return (
            <div key={day.date} className="flex flex-1 flex-col items-center gap-1">
              <div className="flex w-full gap-0.5" style={{ height: `${height}px` }}>
                <div
                  className="flex-1 rounded-t bg-brand-green/60"
                  style={{ height: `${day.allowed > 0 ? (day.allowed / total) * 100 : 0}%` }}
                  title={`${day.allowed} allowed`}
                />
                <div
                  className="flex-1 rounded-t bg-brand-blue/60"
                  style={{ height: `${day.blocked > 0 ? (day.blocked / total) * 100 : 0}%` }}
                  title={`${day.blocked} stopped`}
                />
              </div>
              <span className="text-[10px] text-muted-foreground">{day.date}</span>
            </div>
          );
        })}
      </div>
      <div className="mt-2 flex items-center gap-4">
        <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
          <span className="h-2 w-2 rounded-sm bg-brand-green/60" />
          Allowed
        </span>
        <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
          <span className="h-2 w-2 rounded-sm bg-brand-blue/60" />
          Stopped
        </span>
      </div>
    </div>
  );
});

export function RiskSnapshot({ receipts }: { receipts: GuardReceipt[] }) {
  const analysis = useMemo(() => {
    const blockedCount = receipts.filter((r) => r.policy_decision === "block").length;
    const allowedCount = receipts.filter((r) => r.policy_decision === "allow").length;
    return { blocked: blockedCount, allowed: allowedCount, total: receipts.length };
  }, [receipts]);

  if (analysis.total === 0) return null;

  return (
    <div className="mt-4 rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4">
      <SectionLabel>Activity breakdown</SectionLabel>
      <div className="mt-2 space-y-1.5 text-sm text-brand-dark">
        <p>
          <span className="font-medium">{analysis.allowed}</span>{" "}
          <span className="text-muted-foreground">allowed</span>
        </p>
        {analysis.blocked > 0 && (
          <p>
            <span className="font-medium text-brand-blue">{analysis.blocked}</span>{" "}
            <span className="text-muted-foreground">stopped</span>
          </p>
        )}
      </div>
    </div>
  );
}

export function CloudValueBanner({
  icon,
  title,
  body,
  cta,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
  cta: { label: string; href: string };
}) {
  return (
    <div className="rounded-xl border border-brand-purple/10 bg-brand-purple/[0.03] p-4 sm:p-5">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 shrink-0">{icon}</div>
        <div className="flex-1">
          <p className="text-sm font-semibold text-brand-dark">{title}</p>
          <p className="mt-1 text-sm text-muted-foreground">{body}</p>
          <a
            href={cta.href}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:text-brand-dark transition-colors"
          >
            {cta.label}
            <HiMiniChevronRight className="h-3 w-3" aria-hidden="true" />
          </a>
        </div>
      </div>
    </div>
  );
}

export function TabContent({
  activeTab,
  direction,
  children,
}: {
  activeTab: TabKey;
  direction: "left" | "right";
  children: React.ReactNode;
}) {
  const animationClass = direction === "right" ? "guard-tab-enter" : "guard-tab-enter-reverse";
  return (
    <div key={activeTab} className={`${animationClass}`}>
      {children}
    </div>
  );
}
