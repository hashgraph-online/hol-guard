import { Badge } from "../../approval-center-primitives";
import { HiMiniCheckBadge } from "react-icons/hi2";

export function AboutFooter() {
  return (
    <footer className="border-t border-slate-100 pt-8">
      <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <HiMiniCheckBadge className="h-5 w-5 text-brand-blue" aria-hidden="true" />
          <span className="text-sm font-semibold text-brand-dark">HOL Guard</span>
          <Badge tone="success">Local-first</Badge>
        </div>
        <p className="text-xs text-slate-400">
          Built by Hashgraph Online. Open standards for the agent internet.
        </p>
      </div>
    </footer>
  );
}
