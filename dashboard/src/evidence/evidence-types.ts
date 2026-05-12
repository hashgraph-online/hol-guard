export type EvidenceDecision = "allow" | "block" | "ask" | "all";
export type EvidenceTimeFilter = "all" | "today" | "yesterday" | "week" | "last7d" | "last30d";
export type EvidenceSortKey = "newest" | "oldest" | "app" | "decision" | "category" | "artifact";
export type EvidenceExportFormat = "csv" | "json";
export type EvidenceView = "actions" | "insights" | "apps" | "export";

export interface EvidenceFilterState {
  search: string;
  time: EvidenceTimeFilter;
  decision: EvidenceDecision;
  harness: string;
  category: string;
  sourceScope: string;
  day: string;
  sort: EvidenceSortKey;
  view: EvidenceView;
  selectedId: string;
}

export interface EvidenceInsight {
  id: string;
  label: string;
  value: string;
  tone: "blue" | "green" | "purple" | "attention";
  actionLabel?: string;
  actionFilter?: Partial<EvidenceFilterState>;
}

export type EvidenceSort = {
  key: EvidenceSortKey;
  label: string;
};

export const EVIDENCE_SORT_OPTIONS: EvidenceSort[] = [
  { key: "newest", label: "Newest first" },
  { key: "oldest", label: "Oldest first" },
  { key: "app", label: "App" },
  { key: "decision", label: "Decision" },
  { key: "category", label: "Category" },
  { key: "artifact", label: "Artifact" },
];

export const EVIDENCE_TIME_LABELS: Record<EvidenceTimeFilter, string> = {
  all: "All time",
  today: "Today",
  yesterday: "Yesterday",
  week: "Since Sunday",
  last7d: "Last 7 days",
  last30d: "Last 30 days",
};

export const EVIDENCE_DECISION_LABELS: Record<EvidenceDecision, string> = {
  all: "All decisions",
  allow: "Allowed",
  block: "Stopped",
  ask: "Reviewed",
};
