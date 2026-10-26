import { Badge } from "../../approval-center-primitives";
import { BrandMark } from "../../brand-hero";

export function AboutFooter() {
  return (
    <footer className="border-t border-brand-dark/10 pt-8">
      <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <BrandMark color="currentColor" className="size-6 text-brand-dark" />
          <span className="text-sm font-semibold text-brand-dark">HOL Guard</span>
          <Badge tone="success">Local-first</Badge>
        </div>
        <p className="text-xs text-brand-dark/75">
          Built by HOL. Open standards for the agent internet.
        </p>
      </div>
    </footer>
  );
}
