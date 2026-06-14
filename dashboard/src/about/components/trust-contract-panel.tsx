import { Surface, Badge } from "../../approval-center-primitives";
import { ABOUT_TRUST_CONTRACT_CLAIMS } from "../about-content";
import type { AboutRuntimeSummary } from "../about-types";
import { AboutRuntimeProofStrip } from "./about-runtime-proof-strip";

const toneClasses: Record<string, string> = {
  blue: "border-brand-blue/30 bg-brand-blue/[0.04]",
  green: "border-brand-green/30 bg-brand-green-bg/20",
  purple: "border-brand-purple/20 bg-brand-purple/[0.03]",
  slate: "border-slate-200 bg-slate-50/60",
};

const badgeTones: Record<string, "info" | "success" | "attention" | "default"> = {
  blue: "info",
  green: "success",
  purple: "attention",
  slate: "default",
};

export function TrustContractPanel({
  runtimeSummary,
}: {
  runtimeSummary: AboutRuntimeSummary | null;
}) {
  return (
    <Surface className="h-full" tone="accent">
      <div className="flex items-center justify-between mb-5">
        <h2 className="text-sm font-bold tracking-tight text-brand-dark">
          Trust Contract
        </h2>
        <Badge tone="success">Local-first</Badge>
      </div>
      <div className="space-y-3">
        {ABOUT_TRUST_CONTRACT_CLAIMS.map((claim) => (
          <div
            key={claim.id}
            className={`rounded-lg border p-3 ${toneClasses[claim.tone] ?? toneClasses.slate}`}
          >
            <div className="flex items-center justify-between gap-2 mb-1">
              <h3 className="text-sm font-semibold text-brand-dark">
                {claim.title}
              </h3>
              <Badge tone={badgeTones[claim.tone] ?? "default"}>{claim.proofLabel}</Badge>
            </div>
            <p className="text-xs leading-relaxed text-brand-dark/60">
              {claim.body}
            </p>
          </div>
        ))}
      </div>
      <AboutRuntimeProofStrip summary={runtimeSummary} />
    </Surface>
  );
}
