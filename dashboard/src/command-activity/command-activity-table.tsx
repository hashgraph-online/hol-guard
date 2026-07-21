import { useCallback, type RefObject } from "react";
import { HiMiniChevronLeft, HiMiniChevronRight } from "react-icons/hi2";

import { Badge, EmptyState, IconActionButton } from "../approval-center-primitives";
import {
  commandDecisionLabel,
  commandExecutionLabel,
  safeEvidenceId,
} from "./command-activity-presenters";
import type { CommandActivityItem } from "./command-activity-types";

function recordedTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Time unavailable" : date.toLocaleString();
}

function CommandRow(props: {
  item: CommandActivityItem;
  selected: boolean;
  triggerRef: RefObject<HTMLButtonElement | null>;
  onSelect: (activityId: string) => void;
}) {
  const handleSelect = useCallback(() => {
    props.onSelect(props.item.activity_id);
  }, [props.item.activity_id, props.onSelect]);
  const firstRule = props.item.matches[0];
  return (
    <tr className={props.selected ? "bg-brand-blue/[0.04]" : "hover:bg-slate-50/70"}>
      <td className="whitespace-nowrap px-3 py-3 text-xs text-slate-600">{recordedTime(props.item.occurred_at)}</td>
      <td className="px-3 py-3 text-sm font-medium text-brand-dark">{safeEvidenceId(props.item.harness)}</td>
      <td className="px-3 py-3 text-sm text-brand-dark">{commandDecisionLabel(props.item.policy_action)}</td>
      <td className="px-3 py-3 text-sm text-brand-dark">{commandExecutionLabel(props.item.execution_status)}</td>
      <td className="px-3 py-3 text-sm text-slate-600">
        {firstRule ? safeEvidenceId(firstRule.rule_id) : "No rule match"}
        {props.item.match_count > 1 ? <Badge tone="info">+{props.item.match_count - 1}</Badge> : null}
      </td>
      <td className="px-3 py-3 text-right">
        <button
          ref={props.selected ? props.triggerRef : undefined}
          type="button"
          onClick={handleSelect}
          aria-expanded={props.selected}
          className="min-h-9 rounded-lg px-3 text-sm font-medium text-brand-blue hover:bg-brand-blue/[0.06]"
        >
          Details
        </button>
      </td>
    </tr>
  );
}

export function CommandActivityTable(props: {
  items: CommandActivityItem[];
  selectedId: string | null;
  triggerRef: RefObject<HTMLButtonElement | null>;
  canGoBack: boolean;
  canGoForward: boolean;
  onSelect: (activityId: string) => void;
  onPrevious: () => void;
  onNext: () => void;
}) {
  if (props.items.length === 0) {
    return <EmptyState title="No command activity" body="No recorded commands match these filters." tone="teach" />;
  }
  return (
    <section aria-label="Command activity records" className="w-full min-w-0 max-w-[calc(100vw-2rem)] overflow-hidden rounded-lg border border-slate-200 bg-white [contain:inline-size]">
      <div className="max-w-full overflow-x-auto [contain:paint]">
        <table className="w-full min-w-[760px] border-collapse text-left">
          <thead className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
            <tr>
              <th className="px-3 py-2.5">Time</th><th className="px-3 py-2.5">App</th>
              <th className="px-3 py-2.5">Decision</th><th className="px-3 py-2.5">Execution proof</th>
              <th className="px-3 py-2.5">Rule evidence</th><th className="px-3 py-2.5"><span className="sr-only">Open detail</span></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {props.items.map((item) => (
              <CommandRow key={item.activity_id} item={item} selected={item.activity_id === props.selectedId} triggerRef={props.triggerRef} onSelect={props.onSelect} />
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-end gap-2 border-t border-slate-100 px-3 py-2">
        <IconActionButton label="Previous page" icon={<HiMiniChevronLeft className="h-4 w-4" />} disabled={!props.canGoBack} onClick={props.onPrevious} />
        <IconActionButton label="Next page" icon={<HiMiniChevronRight className="h-4 w-4" />} disabled={!props.canGoForward} onClick={props.onNext} />
      </div>
    </section>
  );
}
