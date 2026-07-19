import type {
  CommandAnalyticsDimension,
  CommandApprovalReuseStatus,
  CommandExecutionStatus,
  CommandProofLevel,
} from "./command-activity-types";

const EXECUTION_STATUSES: readonly CommandExecutionStatus[] = [
  "attempted",
  "prevented",
  "allowed_unconfirmed",
  "confirmed_success",
  "confirmed_failure",
  "unpaired_post",
];
const PROOF_LEVELS: readonly CommandProofLevel[] = ["pre_hook", "post_hook", "unpaired_post"];
const REUSE_STATUSES: readonly CommandApprovalReuseStatus[] = ["accepted", "rejected", "not-applicable"];
const DIMENSIONS: readonly CommandAnalyticsDimension[] = ["harness", "extension", "rule"];
const STABLE_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export interface CommandActivityFilters {
  limit: number;
  harness: string | null;
  execution_status: CommandExecutionStatus | null;
  proof_level: CommandProofLevel | null;
  prompted: boolean | null;
  approval_reuse_status: CommandApprovalReuseStatus | null;
  extension_id: string | null;
  rule_id: string | null;
  occurred_from: string | null;
  occurred_through: string | null;
}

export interface CommandActivityAnalyticsQuery {
  days: number;
  top_limit: number;
  dimension: CommandAnalyticsDimension | null;
  dimension_value: string | null;
}

export const DEFAULT_COMMAND_ACTIVITY_FILTERS: CommandActivityFilters = {
  limit: 50,
  harness: null,
  execution_status: null,
  proof_level: null,
  prompted: null,
  approval_reuse_status: null,
  extension_id: null,
  rule_id: null,
  occurred_from: null,
  occurred_through: null,
};

export const DEFAULT_COMMAND_ACTIVITY_ANALYTICS_QUERY: CommandActivityAnalyticsQuery = {
  days: 90,
  top_limit: 10,
  dimension: null,
  dimension_value: null,
};

export function commandActivityAnalyticsQueryForFilters(
  filters: CommandActivityFilters,
): CommandActivityAnalyticsQuery {
  if (filters.harness) return { days: 90, top_limit: 10, dimension: "harness", dimension_value: filters.harness };
  if (filters.rule_id) return { days: 90, top_limit: 10, dimension: "rule", dimension_value: filters.rule_id };
  if (filters.extension_id) {
    return { days: 90, top_limit: 10, dimension: "extension", dimension_value: filters.extension_id };
  }
  return { ...DEFAULT_COMMAND_ACTIVITY_ANALYTICS_QUERY };
}

export function commandSummaryIsOutsideTableFilters(filters: CommandActivityFilters): boolean {
  return (
    filters.execution_status !== null ||
    filters.proof_level !== null ||
    filters.prompted !== null ||
    filters.approval_reuse_status !== null ||
    filters.occurred_from !== null ||
    filters.occurred_through !== null
  );
}

export function updateCommandActivityFilters(
  current: CommandActivityFilters,
  patch: Partial<CommandActivityFilters>,
  lockedHarness: string | null,
): CommandActivityFilters {
  const harness = lockedHarness ?? (patch.harness === undefined ? current.harness : patch.harness);
  return { ...current, ...patch, harness };
}

function boundedInteger(value: string | null, fallback: number, minimum: number, maximum: number): number {
  if (value === null || !/^\d+$/.test(value)) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : fallback;
}

function enumParam<T extends string>(value: string | null, allowed: readonly T[]): T | null {
  return value !== null && allowed.includes(value as T) ? (value as T) : null;
}

function stableParam(value: string | null): string | null {
  return value !== null && value.length <= 256 && STABLE_ID.test(value) ? value : null;
}

function dateParam(value: string | null): string | null {
  if (value === null || !ISO_DATE.test(value)) return null;
  const year = Number(value.slice(0, 4));
  if (year < 1) return null;
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(date.valueOf()) || date.toISOString().slice(0, 10) !== value ? null : value;
}

function booleanParam(value: string | null): boolean | null {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

export function parseCommandActivityFilters(params: URLSearchParams): CommandActivityFilters {
  const prompted = params.get("command_prompted");
  return {
    limit: boundedInteger(params.get("command_limit"), 50, 1, 100),
    harness: stableParam(params.get("command_harness")),
    execution_status: enumParam(params.get("command_status"), EXECUTION_STATUSES),
    proof_level: enumParam(params.get("command_proof"), PROOF_LEVELS),
    prompted: booleanParam(prompted),
    approval_reuse_status: enumParam(params.get("command_reuse"), REUSE_STATUSES),
    extension_id: stableParam(params.get("command_extension")),
    rule_id: stableParam(params.get("command_rule")),
    occurred_from: dateParam(params.get("command_from")),
    occurred_through: dateParam(params.get("command_through")),
  };
}

export function serializeCommandActivityFilters(filters: CommandActivityFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.limit !== 50) params.set("command_limit", String(filters.limit));
  if (filters.harness) params.set("command_harness", filters.harness);
  if (filters.execution_status) params.set("command_status", filters.execution_status);
  if (filters.proof_level) params.set("command_proof", filters.proof_level);
  if (filters.prompted !== null) params.set("command_prompted", String(filters.prompted));
  if (filters.approval_reuse_status) params.set("command_reuse", filters.approval_reuse_status);
  if (filters.extension_id) params.set("command_extension", filters.extension_id);
  if (filters.rule_id) params.set("command_rule", filters.rule_id);
  if (filters.occurred_from) params.set("command_from", filters.occurred_from);
  if (filters.occurred_through) params.set("command_through", filters.occurred_through);
  return params;
}

export function buildCommandActivityQuery(filters: CommandActivityFilters, cursor: string | null = null): string {
  const invalidStableValue = [filters.harness, filters.extension_id, filters.rule_id].some(
    (value) => value !== null && stableParam(value) !== value,
  );
  const invalidDateValue = [filters.occurred_from, filters.occurred_through].some(
    (value) => value !== null && dateParam(value) !== value,
  );
  const invalidDateRange =
    filters.occurred_from !== null &&
    filters.occurred_through !== null &&
    (filters.occurred_from > filters.occurred_through ||
      (Date.parse(`${filters.occurred_through}T00:00:00Z`) - Date.parse(`${filters.occurred_from}T00:00:00Z`)) /
        86_400_000 >=
        397);
  if (
    !Number.isInteger(filters.limit) ||
    filters.limit < 1 ||
    filters.limit > 100 ||
    (filters.execution_status !== null && !EXECUTION_STATUSES.includes(filters.execution_status)) ||
    (filters.proof_level !== null && !PROOF_LEVELS.includes(filters.proof_level)) ||
    (filters.approval_reuse_status !== null && !REUSE_STATUSES.includes(filters.approval_reuse_status)) ||
    (filters.prompted !== null && typeof filters.prompted !== "boolean") ||
    invalidStableValue ||
    invalidDateValue ||
    invalidDateRange
  ) {
    throw new Error("Invalid command activity filters");
  }
  const params = new URLSearchParams({ limit: String(filters.limit) });
  for (const [key, value] of [
    ["harness", filters.harness],
    ["execution_status", filters.execution_status],
    ["proof_level", filters.proof_level],
    ["approval_reuse_status", filters.approval_reuse_status],
    ["extension_id", filters.extension_id],
    ["rule_id", filters.rule_id],
    ["occurred_from", filters.occurred_from],
    ["occurred_through", filters.occurred_through],
  ] as const) {
    if (value) params.set(key, value);
  }
  if (filters.prompted !== null) params.set("prompted", String(filters.prompted));
  if (cursor) {
    if (cursor.length > 2_048) throw new Error("Invalid command activity cursor");
    params.set("cursor", cursor);
  }
  return params.toString();
}

export function parseCommandActivityAnalyticsQuery(params: URLSearchParams): CommandActivityAnalyticsQuery {
  const dimension = enumParam(params.get("command_dimension"), DIMENSIONS);
  return {
    days: boundedInteger(params.get("command_days"), 90, 1, 397),
    top_limit: boundedInteger(params.get("command_top"), 10, 1, 50),
    dimension,
    dimension_value: dimension === null ? null : stableParam(params.get("command_dimension_value")),
  };
}

export function buildCommandActivityAnalyticsQuery(query: CommandActivityAnalyticsQuery): string {
  if (
    !Number.isInteger(query.days) ||
    query.days < 1 ||
    query.days > 397 ||
    !Number.isInteger(query.top_limit) ||
    query.top_limit < 1 ||
    query.top_limit > 50 ||
    (query.dimension === null) !== (query.dimension_value === null) ||
    (query.dimension !== null && !DIMENSIONS.includes(query.dimension)) ||
    (query.dimension_value !== null && stableParam(query.dimension_value) !== query.dimension_value)
  ) {
    throw new Error("Invalid command activity analytics query");
  }
  const params = new URLSearchParams({ days: String(query.days), top_limit: String(query.top_limit) });
  if (query.dimension && query.dimension_value) {
    params.set("dimension", query.dimension);
    params.set("dimension_value", query.dimension_value);
  }
  return params.toString();
}

export interface CommandActivityCursorState {
  current: string | null;
  back: (string | null)[];
}

export const INITIAL_COMMAND_ACTIVITY_CURSOR_STATE: CommandActivityCursorState = { current: null, back: [] };

export function advanceCommandActivityCursor(
  state: CommandActivityCursorState,
  nextCursor: string,
): CommandActivityCursorState {
  if (!nextCursor || nextCursor.length > 2_048) throw new Error("Invalid command activity cursor");
  return { current: nextCursor, back: [...state.back, state.current] };
}

export function retreatCommandActivityCursor(state: CommandActivityCursorState): CommandActivityCursorState {
  if (state.back.length === 0) return INITIAL_COMMAND_ACTIVITY_CURSOR_STATE;
  return { current: state.back[state.back.length - 1] ?? null, back: state.back.slice(0, -1) };
}

export type CommandActivityLoadState<T> =
  | { kind: "idle" }
  | { kind: "loading"; request_id: number; previous: T | null }
  | { kind: "ready"; request_id: number; data: T }
  | { kind: "empty"; request_id: number }
  | { kind: "error"; request_id: number; message: string; previous: T | null };

export function commandActivityLoadStarted<T>(requestId: number, previous: T | null = null): CommandActivityLoadState<T> {
  return { kind: "loading", request_id: requestId, previous };
}

export function commandActivityLoadSucceeded<T>(
  current: CommandActivityLoadState<T>,
  requestId: number,
  data: T,
  isEmpty: (value: T) => boolean,
): CommandActivityLoadState<T> {
  if (current.kind !== "loading" || current.request_id !== requestId) return current;
  return isEmpty(data) ? { kind: "empty", request_id: requestId } : { kind: "ready", request_id: requestId, data };
}

export function commandActivityLoadFailed<T>(
  current: CommandActivityLoadState<T>,
  requestId: number,
  _error: unknown,
): CommandActivityLoadState<T> {
  if (current.kind !== "loading" || current.request_id !== requestId) return current;
  return {
    kind: "error",
    request_id: requestId,
    message: "Unable to load command activity.",
    previous: current.previous,
  };
}
