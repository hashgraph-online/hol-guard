import { Badge } from "../approval-center-primitives";
import { HiMiniDocumentText } from "react-icons/hi2";

export interface EvidenceHeroProps {
  totalCount: number;
  lastActivityAt: string | null;
}

export function EvidenceHero({ totalCount, lastActivityAt }: EvidenceHeroProps) {
  const lastActivityLabel = lastActivityAt
    ? new Date(lastActivityAt).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
      })
    : null;

  const hasEvidence = totalCount > 0;

  return (
    <section
      className="guard-surface-in relative overflow-hidden rounded-2xl border border-brand-blue/10 bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(72,223,123,0.10)_100%)] p-5 sm:p-6"
      role="region"
      aria-label="Evidence summary"
    >
      <div className="relative">
        <div className="flex min-w-0 items-start gap-3">
          <span className="mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-green/10">
            <HiMiniDocumentText className="h-4 w-4 text-brand-green" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              {hasEvidence ? (
                <Badge tone="success">{totalCount.toLocaleString()} actions recorded</Badge>
              ) : (
                <Badge tone="default">No actions yet</Badge>
              )}
            </div>
            <p className="mt-2 text-sm leading-relaxed text-brand-dark/70">
              Every action Guard reviewed on this machine.
              {lastActivityLabel && (
                <>
                  {" "}
                  Last activity on <span className="font-medium text-brand-dark">{lastActivityLabel}</span>.
                </>
              )}
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
