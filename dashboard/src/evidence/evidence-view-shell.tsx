import type { EvidenceView } from "./evidence-types";

export const VIEW_TABS: { key: EvidenceView; label: string }[] = [
  { key: "actions", label: "All actions" },
  { key: "insights", label: "Insights" },
  { key: "apps", label: "Apps" },
  { key: "categories", label: "Categories" },
  { key: "export", label: "Export" },
];

export function EvidenceLoadingState() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading evidence">
      <div className="guard-skeleton h-8 w-64" />
      <div className="guard-skeleton h-32 w-full" />
    </div>
  );
}

export function EvidenceErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-2xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4">
      <p className="text-sm text-brand-dark">{message}</p>
    </div>
  );
}

export { EvidenceHero, type EvidenceHeroProps } from "./evidence-hero";
