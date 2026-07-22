import { useCallback, type ChangeEvent, type KeyboardEvent } from "react";
import {
  HiMiniArrowPath,
  HiMiniArrowTopRightOnSquare,
  HiMiniClipboardDocumentCheck,
  HiMiniClock,
  HiMiniCodeBracket,
  HiMiniCog6Tooth,
  HiMiniCommandLine,
  HiMiniCube,
  HiMiniDocumentMagnifyingGlass,
  HiMiniDocumentPlus,
  HiMiniDocumentText,
  HiMiniExclamationTriangle,
  HiMiniGlobeAlt,
  HiMiniInformationCircle,
  HiMiniKey,
  HiMiniNoSymbol,
  HiMiniPencilSquare,
  HiMiniServerStack,
  HiMiniShieldCheck,
} from "react-icons/hi2";
import { FaDocker, FaGitAlt, FaGithub } from "react-icons/fa";
import { harnessDisplayName, resolveStoppedCommandText } from "./approval-center-utils";
import type { GuardApprovalRequest } from "./guard-types";
import {
  formatQueueRequestDate,
  resolveQueueCategory,
  riskScore,
  type QueueCategoryId,
} from "./queue-state";
import type { RequestReadState } from "./request-read-state";

type RiskLevel = "high" | "medium" | "low";

function riskLevelFromScore(score: number): RiskLevel {
  if (score <= 2) return "high";
  if (score <= 4) return "medium";
  return "low";
}

function riskIndicatorClass(level: RiskLevel): string {
  if (level === "high") return "bg-red-400";
  if (level === "medium") return "bg-amber-400";
  return "bg-emerald-400";
}

export function QueueItemRow({ item, active, readState, index, onOpenRequest, selectionMode = false, selectable = false, selected = false, onToggleSelect }: {
  item: GuardApprovalRequest;
  active: boolean;
  readState: RequestReadState;
  index: number;
  onOpenRequest: (requestId: string) => void;
  selectionMode?: boolean;
  selectable?: boolean;
  selected?: boolean;
  onToggleSelect?: (item: GuardApprovalRequest) => void;
}) {
  const risk = riskScore(item);
  const riskLevel = riskLevelFromScore(risk);
  const category = resolveQueueCategory(item);
  const CategoryIcon = iconForQueueCategory(category.id);
  const preview = queueItemPreview(item);
  const isRead = readState.isRead(item.request_id);
  // Checkboxes render whenever bulk selection is active so the affordance is
  // always discoverable. Non-eligible rows show a disabled checkbox with a
  // tooltip instead of silently hiding the control.
  const showCheckbox = selectionMode;
  const canSelect = selectionMode && selectable;

  const handleClick = useCallback(() => {
    onOpenRequest(item.request_id);
  }, [item.request_id, onOpenRequest]);

  const handleCheckboxChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      event.stopPropagation();
      if (!canSelect) return;
      onToggleSelect?.(item);
    },
    [item, onToggleSelect, canSelect],
  );

  const handleKeyDown = useCallback(
    (event: KeyboardEvent<HTMLLabelElement>) => {
      if (!canSelect) return;
      // Space is handled natively by the checkbox itself; only remap Enter
      // here so the wrapping label is also keyboard-activatable.
      if (event.key === "Enter") {
        event.preventDefault();
        event.stopPropagation();
        onToggleSelect?.(item);
      }
    },
    [item, onToggleSelect, canSelect],
  );

  const checkboxLabel = canSelect
    ? `Select ${preview} for bulk approval`
    : `Not eligible for bulk approval: ${category.shortLabel.toLowerCase()}`;

  const rowClassName = (() => {
    if (selected) return "border border-brand-blue/60 bg-brand-blue/[0.08] ring-1 ring-brand-blue/20";
    if (active) return "border border-brand-blue bg-brand-blue/[0.06]";
    if (isRead) return "border border-transparent bg-white hover:bg-slate-50";
    return "border border-transparent bg-slate-50 hover:bg-slate-100";
  })();

  return (
    <div
      role="none"
      className={`group w-full rounded-lg py-2.5 px-2 transition-all ${rowClassName}`}
    >
      <div className="flex items-center justify-between gap-2">
        {showCheckbox ? (
          <label
            className={`flex shrink-0 items-center ${canSelect ? "cursor-pointer" : "cursor-not-allowed"}`}
            title={checkboxLabel}
            onClick={(event) => event.stopPropagation()}
            onKeyDown={handleKeyDown}
          >
            <input
              type="checkbox"
              checked={selected}
              disabled={!canSelect}
              onChange={handleCheckboxChange}
              aria-label={checkboxLabel}
              className="h-4 w-4 rounded border-slate-300 text-brand-blue focus:ring-brand-blue/30 disabled:opacity-40"
            />
          </label>
        ) : null}
        <button
          type="button"
          onClick={handleClick}
          role="option"
          aria-selected={active}
          aria-posinset={index + 1}
          aria-setsize={undefined}
          tabIndex={active ? 0 : -1}
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
        >
          <div className="min-w-0 flex-1">
            <p className={`truncate text-sm ${isRead ? "font-medium text-slate-500" : "font-bold text-brand-dark"}`}>
              {!isRead && <span className="sr-only">Unread request:</span>}
              {preview}
            </p>
            <p className="truncate text-[11px] text-muted-foreground">
              {harnessDisplayName(item.harness)} · {formatQueueRequestDate(item)}
            </p>
          </div>
          <span
            role="img"
            aria-label={`Risk: ${riskLevel}`}
            className="group/icon relative flex h-2 w-2 shrink-0 items-center justify-center"
          >
            <span className={`h-2 w-2 rounded-full ${riskIndicatorClass(riskLevel)}`} />
            <span className="pointer-events-none absolute right-0 top-full z-50 mt-1.5 whitespace-nowrap rounded-md bg-brand-blue px-2 py-1 text-[10px] font-medium text-white opacity-0 shadow-lg transition-opacity duration-150 group-hover/icon:opacity-100">
              {`Risk: ${riskLevel}`}
            </span>
          </span>
          <span
            role="img"
            aria-label={category.label}
            className={`group/icon relative inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg ${
              active ? "bg-brand-blue/10 text-brand-blue" : "bg-slate-50 text-slate-500"
            }`}
          >
            <CategoryIcon className="h-4 w-4" aria-hidden="true" />
            <span className="pointer-events-none absolute right-0 top-full z-50 mt-1.5 whitespace-nowrap rounded-md bg-brand-blue px-2 py-1 text-[10px] font-medium text-white opacity-0 shadow-lg transition-opacity duration-150 group-hover/icon:opacity-100">
              {category.label}
            </span>
          </span>
        </button>
      </div>
    </div>
  );
}

function iconForQueueCategory(categoryId: QueueCategoryId) {
  switch (categoryId) {
    case "credential_output":
      return HiMiniKey;
    case "secret_file_read":
      return HiMiniDocumentMagnifyingGlass;
    case "file_read":
      return HiMiniDocumentMagnifyingGlass;
    case "secret_exfiltration":
      return HiMiniArrowTopRightOnSquare;
    case "system_prompt_access":
      return HiMiniInformationCircle;
    case "prompt_injection":
      return HiMiniExclamationTriangle;
    case "guard_bypass":
      return HiMiniNoSymbol;
    case "generated_inventory_edit":
      return HiMiniClipboardDocumentCheck;
    case "docs_edit":
      return HiMiniDocumentText;
    case "source_edit":
      return HiMiniPencilSquare;
    case "config_change":
      return HiMiniCog6Tooth;
    case "file_upload":
      return HiMiniArrowTopRightOnSquare;
    case "file_delete_cleanup":
      return HiMiniNoSymbol;
    case "git_operation":
      return FaGitAlt;
    case "docker_command":
      return FaDocker;
    case "github_command":
      return FaGithub;
    case "process_control":
      return HiMiniArrowPath;
    case "container_or_deploy":
      return HiMiniServerStack;
    case "persistence_change":
      return HiMiniClock;
    case "package_install":
      return HiMiniCube;
    case "package_script":
      return HiMiniCommandLine;
    case "destructive_shell":
      return HiMiniNoSymbol;
    case "encoded_shell":
      return HiMiniCodeBracket;
    case "network":
      return HiMiniGlobeAlt;
    case "mcp_tool":
      return HiMiniServerStack;
    case "browser_action":
      return HiMiniArrowTopRightOnSquare;
    case "harness_start":
      return HiMiniShieldCheck;
    case "shell_command":
      return HiMiniCommandLine;
    case "other":
      return HiMiniDocumentPlus;
  }
}

export function queueItemPreview(item: GuardApprovalRequest): string {
  const envelope = item.action_envelope_json;
  return (
    envelope?.command ??
    item.raw_command_text ??
    item.queue_preview ??
    envelope?.mcp_tool ??
    (envelope?.prompt_text ?? envelope?.prompt_excerpt) ??
    envelope?.package_name ??
    resolveStoppedCommandText(item)
  );
}
