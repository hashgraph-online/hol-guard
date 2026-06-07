import type { GuardReceiptAnalytics, GuardRuntimeSnapshot } from "../guard-types";
import { EvidenceInsightsSurface } from "./evidence-insights-surface";

interface EvidenceAnalyticsPanelProps {
  analytics: GuardReceiptAnalytics;
  runtime: GuardRuntimeSnapshot | null;
  sampleCount: number;
  onFilterHarness: (harness: string) => void;
  onFilterDay?: (dateKey: string) => void;
  onViewActions: () => void;
}

export function EvidenceAnalyticsPanel(props: EvidenceAnalyticsPanelProps) {
  return <EvidenceInsightsSurface {...props} />;
}
