import { SectionLabel } from "../../approval-center-primitives";
import { TrustContractPanel } from "./trust-contract-panel";
import { TrackedExternalButton } from "./tracked-action-button";
import type { AboutRuntimeSummary } from "../about-types";

export function AboutHero({
  runtimeSummary,
}: {
  runtimeSummary: AboutRuntimeSummary | null;
}) {
  return (
    <section className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_420px] lg:items-center">
      <div className="max-w-3xl">
        <SectionLabel>Open standards. Local protection.</SectionLabel>
        <h1 className="mt-4 text-4xl font-black tracking-tight text-brand-dark sm:text-5xl lg:text-6xl">
          About HOL Guard
        </h1>
        <p className="mt-5 max-w-2xl text-lg leading-8 text-brand-dark/75">
          A local-first safety layer for AI harnesses, built by HOL as part of open trust infrastructure for the agent internet.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          <TrackedExternalButton linkId="guard_docs" href="https://hol.org/guard/docs" variant="primary">
            Read Guard docs
          </TrackedExternalButton>
          <TrackedExternalButton linkId="hol_guard_source" href="https://github.com/hashgraph-online/hol-guard" variant="outline">
            View source
          </TrackedExternalButton>
        </div>
      </div>
      <TrustContractPanel runtimeSummary={runtimeSummary} />
    </section>
  );
}
