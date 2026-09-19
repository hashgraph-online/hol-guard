import { useMemo, useCallback } from "react";
import { HiMiniCheckCircle, HiMiniMinusCircle, HiMiniChevronRight } from "react-icons/hi2";
import { Badge, EmptyState, SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import { buildEmptyStateCopy } from "./home-dashboard-model";
import type { GuardManagedInstall, GuardApprovalRequest } from "./guard-types";

function harnessPriorityScore(
  install: GuardManagedInstall | undefined,
  observed: boolean,
  pendingCount: number,
): number {
  let score = 0;
  if (install?.active) {
    score = 3;
  } else if (install !== undefined) {
    score = 2;
  } else if (observed) {
    score = 1;
  }
  if (pendingCount > 0) score += 4;
  return score;
}

export function AppsAtAGlance(props: {
  managedInstalls: GuardManagedInstall[];
  observedHarnesses: string[];
  queuedItems: GuardApprovalRequest[];
  onOpenAppDetail: (harness: string) => void;
}) {
  const pendingByHarness = useMemo(() => {
    const map = new Map<string, number>();
    for (const item of props.queuedItems) {
      map.set(item.harness, (map.get(item.harness) ?? 0) + 1);
    }
    return map;
  }, [props.queuedItems]);

  const sortedHarnesses = useMemo(() => {
    const all = Array.from(
      new Set([
        ...props.managedInstalls.map((i) => i.harness),
        ...props.observedHarnesses,
      ])
    );
    return all.sort((a, b) => {
      const aInstall = props.managedInstalls.find((i) => i.harness === a);
      const bInstall = props.managedInstalls.find((i) => i.harness === b);
      const aPending = pendingByHarness.get(a) ?? 0;
      const bPending = pendingByHarness.get(b) ?? 0;
      const aScore = harnessPriorityScore(aInstall, props.observedHarnesses.includes(a), aPending);
      const bScore = harnessPriorityScore(bInstall, props.observedHarnesses.includes(b), bPending);
      return bScore - aScore;
    });
  }, [props.managedInstalls, props.observedHarnesses, pendingByHarness]);

  if (sortedHarnesses.length === 0) {
    const emptyCopy = buildEmptyStateCopy();
    return (
      <EmptyState
        title={emptyCopy.title}
        body={emptyCopy.body}
        tone="teach"
      />
    );
  }

  return (
    <div>
      <div className="mb-3">
        <SectionLabel>Apps at a glance</SectionLabel>
        <p className="mt-1 text-sm text-slate-500">
          Guard is watching these apps on this machine.
        </p>
      </div>
      <div className="divide-y divide-slate-100 border-t border-slate-100" role="list" aria-label="Apps at a glance">
        {sortedHarnesses.map((harness, index) => {
          const install = props.managedInstalls.find((i) => i.harness === harness);
          const isObserved = props.observedHarnesses.includes(harness);
          const pending = pendingByHarness.get(harness) ?? 0;
          return (
            <AppGlanceRow
              key={harness}
              harness={harness}
              install={install}
              isObserved={isObserved}
              pending={pending}
              onOpenAppDetail={props.onOpenAppDetail}
            />
          );
        })}
      </div>
    </div>
  );
}

function AppGlanceRow(props: {
  harness: string;
  install: GuardManagedInstall | undefined;
  isObserved: boolean;
  pending: number;
  onOpenAppDetail: (harness: string) => void;
}) {
  const handleOpen = useCallback(() => {
    props.onOpenAppDetail(props.harness);
  }, [props.onOpenAppDetail, props.harness]);

  return (
    <div role="listitem">
      <button
        type="button"
        data-app-item
        onClick={handleOpen}
        className="flex w-full items-center justify-between gap-3 py-2.5 text-left transition-colors hover:bg-slate-50/60 focus:bg-brand-blue/[0.04] focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
      >
        <div className="flex min-w-0 items-center gap-2.5">
          <AppStatusIcon install={props.install} isObserved={props.isObserved} />
          <p className="truncate text-sm font-medium text-brand-dark">
            {harnessDisplayName(props.harness)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {props.pending > 0 && (
            <Badge tone="info">{props.pending} pending</Badge>
          )}
          <AppStatusBadge install={props.install} isObserved={props.isObserved} />
          <HiMiniChevronRight className="h-4 w-4 shrink-0 text-slate-300" aria-hidden="true" />
        </div>
      </button>
    </div>
  );
}

function AppStatusIcon(props: { install: GuardManagedInstall | undefined; isObserved: boolean }) {
  if (props.install?.active === true) {
    return <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />;
  }
  if (props.install !== undefined && !props.install.active) {
    return <HiMiniMinusCircle className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />;
  }
  if (props.isObserved) {
    return <HiMiniMinusCircle className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />;
  }
  return <HiMiniMinusCircle className="h-4 w-4 shrink-0 text-slate-300" aria-hidden="true" />;
}

function AppStatusBadge(props: { install: GuardManagedInstall | undefined; isObserved: boolean }) {
  if (props.install?.active === true) {
    return <Badge tone="success">Active</Badge>;
  }
  if (props.install !== undefined && !props.install.active) {
    return <Badge tone="attention">Needs setup</Badge>;
  }
  if (props.isObserved) {
    return <Badge tone="attention">Needs setup</Badge>;
  }
  return <Badge tone="attention">Needs setup</Badge>;
}
