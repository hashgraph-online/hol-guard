import type {
  EvidenceFilterState,
  EvidenceDecision,
  EvidenceTimeFilter,
  EvidenceSortKey,
  EvidenceView,
} from "./evidence-types";

export const DEFAULT_FILTER_STATE: EvidenceFilterState = {
  search: "",
  time: "all",
  decision: "all",
  harness: "all",
  category: "",
  sourceScope: "",
  day: "",
  sort: "newest",
  view: "actions",
  selectedId: "",
};

const VALID_TIME: EvidenceTimeFilter[] = [
  "all",
  "today",
  "yesterday",
  "week",
  "last7d",
  "last30d",
];
const VALID_DECISION: EvidenceDecision[] = ["all", "allow", "block", "ask"];
const VALID_SORT: EvidenceSortKey[] = [
  "newest",
  "oldest",
  "app",
  "decision",
  "category",
  "artifact",
];
const VALID_VIEW: EvidenceView[] = ["actions", "commands", "insights", "apps", "export", "story", "categories"];

const OWNED_PARAMS = ["search", "time", "decision", "harness", "category", "sourceScope", "day", "sort", "view", "selected"];

export function parseEvidenceUrlState(
  params: URLSearchParams
): EvidenceFilterState {
  const time = params.get("time") as EvidenceTimeFilter;
  const decision = params.get("decision") as EvidenceDecision;
  const sort = params.get("sort") as EvidenceSortKey;
  const view = params.get("view") as EvidenceView;
  const day = params.get("day") ?? DEFAULT_FILTER_STATE.day;
  const resolvedView = VALID_VIEW.includes(view) ? view : DEFAULT_FILTER_STATE.view;

  return {
    search: params.get("search") ?? DEFAULT_FILTER_STATE.search,
    time: VALID_TIME.includes(time) ? time : DEFAULT_FILTER_STATE.time,
    decision: VALID_DECISION.includes(decision)
      ? decision
      : DEFAULT_FILTER_STATE.decision,
    harness: params.get("harness") ?? DEFAULT_FILTER_STATE.harness,
    category: params.get("category") ?? DEFAULT_FILTER_STATE.category,
    sourceScope: params.get("sourceScope") ?? DEFAULT_FILTER_STATE.sourceScope,
    day,
    sort: VALID_SORT.includes(sort) ? sort : DEFAULT_FILTER_STATE.sort,
    view: day ? "actions" : resolvedView,
    selectedId: params.get("selected") ?? DEFAULT_FILTER_STATE.selectedId,
  };
}

export function serializeEvidenceUrlState(
  state: EvidenceFilterState
): URLSearchParams {
  const params = new URLSearchParams();
  if (state.search) params.set("search", state.search);
  if (state.time !== DEFAULT_FILTER_STATE.time) params.set("time", state.time);
  if (state.decision !== DEFAULT_FILTER_STATE.decision)
    params.set("decision", state.decision);
  if (state.harness !== DEFAULT_FILTER_STATE.harness)
    params.set("harness", state.harness);
  if (state.category) params.set("category", state.category);
  if (state.sourceScope) params.set("sourceScope", state.sourceScope);
  if (state.day) {
    params.set("day", state.day);
    params.set("view", "actions");
  } else if (state.view !== DEFAULT_FILTER_STATE.view) {
    params.set("view", state.view);
  }
  if (state.sort !== DEFAULT_FILTER_STATE.sort) params.set("sort", state.sort);
  if (state.selectedId) params.set("selected", state.selectedId);
  return params;
}

export function readEvidenceUrlState(params?: URLSearchParams): EvidenceFilterState {
  const p = params ?? new URLSearchParams(window.location.search);
  return parseEvidenceUrlState(p);
}

export function writeEvidenceUrlState(state: EvidenceFilterState): void {
  const url = new URL(window.location.href);
  for (const key of OWNED_PARAMS) url.searchParams.delete(key);
  for (const [key, value] of serializeEvidenceUrlState(state)) url.searchParams.set(key, value);
  window.history.replaceState({}, "", url.toString());
}
