import { requestGuardJson } from "../guard-api";
import {
  COMMAND_ACTIVITY_HARNESSES,
  COMMAND_APPROVAL_REUSE_STATUSES,
  COMMAND_EXECUTION_STATUSES,
  COMMAND_FEEDBACK_LABELS,
  COMMAND_PROOF_LEVELS,
} from "./command-activity-types";
import {
  normalizeCommandActivityAnalytics,
  normalizeCommandActivityFeedback,
  normalizeCommandActivityPage,
  normalizeCommandExtensionsPage,
} from "./command-activity-normalizers";
import type {
  CommandActivityAnalytics,
  CommandActivityFeedbackResult,
  CommandActivityHarness,
  CommandActivityPage,
  CommandApprovalReuseStatus,
  CommandExecutionStatus,
  CommandExtensionsPage,
  CommandFeedbackLabel,
  CommandProofLevel,
} from "./command-activity-types";

const STABLE_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export interface CommandActivityFilters {
  limit: number;
  harness: CommandActivityHarness | null;
  executionStatus: CommandExecutionStatus | null;
  proofLevel: CommandProofLevel | null;
  prompted: boolean | null;
  approvalReuseStatus: CommandApprovalReuseStatus | null;
  extensionId: string | null;
  ruleId: string | null;
  occurredFrom: string | null;
  occurredThrough: string | null;
}

export interface CommandActivityQueryState {
  filters: CommandActivityFilters;
  cursor: string | null;
}

export interface CommandActivityAnalyticsQuery {
  days: number;
  topLimit: number;
  dimension: "harness" | "extension" | "rule" | null;
  dimensionValue: string | null;
}

export const DEFAULT_COMMAND_ACTIVITY_FILTERS: CommandActivityFilters = {
  limit: 50,
  harness: null,
  executionStatus: null,
  proofLevel: null,
  prompted: null,
  approvalReuseStatus: null,
  extensionId: null,
  ruleId: null,
  occurredFrom: null,
  occurredThrough: null,
};
export const DEFAULT_COMMAND_ACTIVITY_QUERY: CommandActivityQueryState = {
  filters: DEFAULT_COMMAND_ACTIVITY_FILTERS,
  cursor: null,
};
export const DEFAULT_COMMAND_ACTIVITY_ANALYTICS_QUERY: CommandActivityAnalyticsQuery = {
  days: 90,
  topLimit: 10,
  dimension: null,
  dimensionValue: null,
};

export class CommandActivityRequestError extends Error {
  constructor(readonly code: "invalid_filters" | "invalid_cursor") {
    super(code === "invalid_cursor" ? "Invalid command activity cursor" : "Invalid command activity filters");
    this.name = "CommandActivityRequestError";
  }
}

function append(params: URLSearchParams, name: string, value: string | number | boolean | null): void {
  if (value !== null) params.set(name, String(value));
}

function validDate(value: string | null): boolean {
  if (value === null) return true;
  if (!ISO_DATE.test(value) || value.startsWith("0000-")) return false;
  const timestamp = Date.parse(`${value}T00:00:00Z`);
  return !Number.isNaN(timestamp) && new Date(timestamp).toISOString().slice(0, 10) === value;
}

function validStableId(value: string | null): boolean {
  return value === null || (value.length <= 256 && STABLE_ID.test(value));
}

function validHarness(value: string | null): boolean {
  return value !== null && COMMAND_ACTIVITY_HARNESSES.some((harness) => harness === value);
}

function validateFilters(filters: CommandActivityFilters): void {
  const rangeDays = filters.occurredFrom !== null && filters.occurredThrough !== null
    ? (Date.parse(`${filters.occurredThrough}T00:00:00Z`) - Date.parse(`${filters.occurredFrom}T00:00:00Z`)) /
      86_400_000
    : null;
  if (
    !Number.isInteger(filters.limit) || filters.limit < 1 || filters.limit > 100 ||
    !validStableId(filters.extensionId) || !validStableId(filters.ruleId) ||
    !validDate(filters.occurredFrom) || !validDate(filters.occurredThrough) ||
    (rangeDays !== null && (rangeDays < 0 || rangeDays >= 397))
  ) {
    throw new CommandActivityRequestError("invalid_filters");
  }
}

function validateCursor(cursor: string | null): void {
  if (cursor !== null && (!cursor || cursor.length > 2_048)) throw new CommandActivityRequestError("invalid_cursor");
}

function enumParam<const T extends readonly string[]>(
  params: URLSearchParams,
  name: string,
  values: T,
): T[number] | null {
  const value = params.get(name);
  return value !== null && values.includes(value) ? value as T[number] : null;
}

function stableIdParam(params: URLSearchParams, name: string): string | null {
  const value = params.get(name);
  return validStableId(value) ? value : null;
}

function dateParam(params: URLSearchParams, name: string): string | null {
  const value = params.get(name);
  return validDate(value) ? value : null;
}

export function commandActivityListPath(query: CommandActivityQueryState): string {
  validateFilters(query.filters);
  validateCursor(query.cursor);
  const params = new URLSearchParams();
  append(params, "limit", query.filters.limit);
  append(params, "harness", query.filters.harness);
  append(params, "execution_status", query.filters.executionStatus);
  append(params, "proof_level", query.filters.proofLevel);
  append(params, "prompted", query.filters.prompted);
  append(params, "approval_reuse_status", query.filters.approvalReuseStatus);
  append(params, "extension_id", query.filters.extensionId);
  append(params, "rule_id", query.filters.ruleId);
  append(params, "occurred_from", query.filters.occurredFrom);
  append(params, "occurred_through", query.filters.occurredThrough);
  append(params, "cursor", query.cursor);
  return `/v1/command-activity?${params.toString()}`;
}

export function commandActivityAnalyticsPath(query: CommandActivityAnalyticsQuery): string {
  if (
    !Number.isInteger(query.days) || query.days < 1 || query.days > 397 ||
    !Number.isInteger(query.topLimit) || query.topLimit < 1 || query.topLimit > 50 ||
    (query.dimension === null) !== (query.dimensionValue === null) || !validStableId(query.dimensionValue) ||
    (query.dimension === "harness" && !validHarness(query.dimensionValue))
  ) {
    throw new CommandActivityRequestError("invalid_filters");
  }
  const params = new URLSearchParams();
  append(params, "days", query.days);
  append(params, "top_limit", query.topLimit);
  append(params, "dimension", query.dimension);
  append(params, "dimension_value", query.dimensionValue);
  return `/v1/command-activity/analytics?${params.toString()}`;
}

export function updateCommandActivityFilters(
  state: CommandActivityQueryState,
  patch: Partial<CommandActivityFilters>,
): CommandActivityQueryState {
  const filters = { ...state.filters, ...patch };
  validateFilters(filters);
  return { filters, cursor: null };
}

export function advanceCommandActivityCursor(
  state: CommandActivityQueryState,
  cursor: string | null,
): CommandActivityQueryState {
  validateCursor(cursor);
  return { filters: state.filters, cursor };
}

export function serializeCommandActivityUrlState(state: CommandActivityQueryState): URLSearchParams {
  validateFilters(state.filters);
  validateCursor(state.cursor);
  const params = new URLSearchParams();
  if (state.filters.limit !== DEFAULT_COMMAND_ACTIVITY_FILTERS.limit) {
    append(params, "commandLimit", state.filters.limit);
  }
  append(params, "commandHarness", state.filters.harness);
  append(params, "commandExecution", state.filters.executionStatus);
  append(params, "commandProof", state.filters.proofLevel);
  append(params, "commandPrompted", state.filters.prompted);
  append(params, "commandReuse", state.filters.approvalReuseStatus);
  append(params, "commandExtension", state.filters.extensionId);
  append(params, "commandRule", state.filters.ruleId);
  append(params, "commandFrom", state.filters.occurredFrom);
  append(params, "commandThrough", state.filters.occurredThrough);
  append(params, "commandCursor", state.cursor);
  return params;
}

export function parseCommandActivityUrlState(params: URLSearchParams): CommandActivityQueryState {
  const rawLimit = Number(params.get("commandLimit"));
  const limit = Number.isInteger(rawLimit) && rawLimit >= 1 && rawLimit <= 100
    ? rawLimit
    : DEFAULT_COMMAND_ACTIVITY_FILTERS.limit;
  const promptedValue = params.get("commandPrompted");
  const prompted = promptedValue === "true" ? true : promptedValue === "false" ? false : null;
  let occurredFrom = dateParam(params, "commandFrom");
  let occurredThrough = dateParam(params, "commandThrough");
  const rangeDays = occurredFrom !== null && occurredThrough !== null
    ? (Date.parse(`${occurredThrough}T00:00:00Z`) - Date.parse(`${occurredFrom}T00:00:00Z`)) / 86_400_000
    : null;
  if (rangeDays !== null && (rangeDays < 0 || rangeDays >= 397)) {
    occurredFrom = null;
    occurredThrough = null;
  }
  const cursorValue = params.get("commandCursor");
  const cursor = cursorValue !== null && cursorValue.length <= 2_048 && cursorValue.length > 0
    ? cursorValue
    : null;
  return {
    filters: {
      limit,
      harness: enumParam(params, "commandHarness", COMMAND_ACTIVITY_HARNESSES),
      executionStatus: enumParam(params, "commandExecution", COMMAND_EXECUTION_STATUSES),
      proofLevel: enumParam(params, "commandProof", COMMAND_PROOF_LEVELS),
      prompted,
      approvalReuseStatus: enumParam(params, "commandReuse", COMMAND_APPROVAL_REUSE_STATUSES),
      extensionId: stableIdParam(params, "commandExtension"),
      ruleId: stableIdParam(params, "commandRule"),
      occurredFrom,
      occurredThrough,
    },
    cursor,
  };
}

export async function fetchCommandActivityPage(
  query: CommandActivityQueryState = DEFAULT_COMMAND_ACTIVITY_QUERY,
): Promise<CommandActivityPage> {
  return normalizeCommandActivityPage(await requestGuardJson<unknown>(commandActivityListPath(query)));
}

export async function fetchCommandActivityAnalytics(
  query: CommandActivityAnalyticsQuery = DEFAULT_COMMAND_ACTIVITY_ANALYTICS_QUERY,
): Promise<CommandActivityAnalytics> {
  return normalizeCommandActivityAnalytics(await requestGuardJson<unknown>(commandActivityAnalyticsPath(query)));
}

export async function fetchCommandExtensions(cursor: string | null = null, limit = 50): Promise<CommandExtensionsPage> {
  validateCursor(cursor);
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new CommandActivityRequestError("invalid_filters");
  }
  const params = new URLSearchParams({ limit: String(limit) });
  append(params, "cursor", cursor);
  return normalizeCommandExtensionsPage(
    await requestGuardJson<unknown>(`/v1/command-extensions?${params.toString()}`),
  );
}

export async function submitCommandActivityFeedback(
  activityId: string,
  label: CommandFeedbackLabel,
): Promise<CommandActivityFeedbackResult> {
  if (!activityId || activityId.length > 256 || !COMMAND_FEEDBACK_LABELS.includes(label)) {
    throw new CommandActivityRequestError("invalid_filters");
  }
  return normalizeCommandActivityFeedback(
    await requestGuardJson<unknown>("/v1/command-activity/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ activity_id: activityId, label }),
    }),
  );
}
