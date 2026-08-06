import { useCallback, useEffect, useRef } from "react";

import { ActionButton, EmptyState } from "../approval-center-primitives";
import { CommandActivityDetail } from "./command-activity-detail";
import { CommandActivityFiltersPanel } from "./command-activity-filters";
import { commandSummaryIsOutsideTableFilters } from "./command-activity-state";
import { commandExecutionEvidenceCopy } from "./command-activity-presenters";
import { CommandActivitySummary } from "./command-activity-summary";
import { CommandActivityTable } from "./command-activity-table";
import { useCommandActivity } from "./use-command-activity";

function availableData<T>(state: { kind: string; data?: T; previous?: T | null }): T | null {
  if (state.kind === "ready" && state.data) return state.data;
  if ((state.kind === "loading" || state.kind === "error") && state.previous) return state.previous;
  return null;
}

export function CommandActivityWorkspace(props: { harness?: string | null }) {
  const activity = useCommandActivity(props.harness ?? null);
  const detailTriggerRef = useRef<HTMLButtonElement | null>(null);
  const detailRef = useRef<HTMLElement | null>(null);
  const handleClose = useCallback(() => {
    const trigger = detailTriggerRef.current;
    activity.selectActivity(null);
    requestAnimationFrame(() => trigger?.focus());
  }, [activity.selectActivity]);

  useEffect(() => {
    if (activity.selectedId !== null && activity.selectedActivity === null && activity.page.kind === "ready") {
      activity.selectActivity(null);
    }
  }, [activity.page, activity.selectActivity, activity.selectedActivity, activity.selectedId]);

  useEffect(() => {
    if (activity.selectedActivity) detailRef.current?.focus();
  }, [activity.selectedActivity]);

  const extensions = availableData(activity.extensions);
  const analytics = availableData(activity.analytics);
  const loadingWithoutData = (activity.page.kind === "idle" || activity.page.kind === "loading") && activity.pageData === null;
  const failedWithoutData = activity.page.kind === "error" && activity.page.previous === null;
  const refreshFailedWithData = activity.page.kind === "error" && activity.page.previous !== null;
  const hasPostProof = activity.pageData?.items.some((item) => item.proof_level === "post_hook") ?? false;

  return (
    <div className="w-full min-w-0 max-w-full space-y-5 overflow-x-clip">
      <CommandActivitySummary
        state={activity.analytics}
        outsideTableFilters={commandSummaryIsOutsideTableFilters(activity.filters)}
        onRetry={activity.retry}
      />
      <p className="rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600">
        {commandExecutionEvidenceCopy(props.harness ?? null, hasPostProof)}
      </p>
      <CommandActivityFiltersPanel filters={activity.filters} extensions={extensions} analytics={analytics} lockedHarness={props.harness ?? null} resultCount={activity.pageData?.items.length ?? null} onChange={activity.updateFilters} />
      {loadingWithoutData ? <div className="guard-skeleton h-64 w-full" aria-label="Loading command activity" /> : null}
      {failedWithoutData ? (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          <p>Command activity is unavailable.</p>
          <ActionButton variant="outline" onClick={activity.retry}>Try again</ActionButton>
        </div>
      ) : null}
      {refreshFailedWithData ? (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900" role="status">
          <p>Refresh failed. Showing the last loaded command activity page.</p>
          <ActionButton variant="outline" onClick={activity.retry}>Try again</ActionButton>
        </div>
      ) : null}
      {activity.page.kind === "empty" ? (
        <EmptyState title="No command activity" body="No recorded commands match these filters." tone="teach" />
      ) : null}
      {activity.pageData ? (
        <div className={activity.selectedActivity ? "grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_360px]" : "min-w-0"}>
          <CommandActivityTable items={activity.pageData.items} selectedId={activity.selectedId} triggerRef={detailTriggerRef} canGoBack={activity.cursor.back.length > 0} canGoForward={activity.pageData.next_cursor !== null} onSelect={activity.selectActivity} onPrevious={activity.previousPage} onNext={activity.nextPage} />
          {activity.selectedActivity ? (
            <div className="rounded-lg border border-slate-200 bg-white">
              <CommandActivityDetail detailRef={detailRef} activity={activity.selectedActivity} feedback={activity.feedback} onFeedback={activity.recordFeedback} onClose={handleClose} />
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
