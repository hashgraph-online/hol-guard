import { useEffect } from "react";
import { AboutHero } from "./components/about-hero";
import { DataBoundaryPanel } from "./components/data-boundary-panel";
import { OpenStandardsMap } from "./components/open-standards-map";
import { PathwayGrid } from "./components/pathway-grid";
import { EcosystemPrograms } from "./components/ecosystem-programs";
import { AboutFooter } from "./components/about-footer";
import { SectionShell } from "./components/section-shell";
import { trackAboutEvent } from "./about-analytics";
import type { AboutRuntimeSummary } from "./about-types";

export function AboutWorkspace({
  runtimeSummary,
}: {
  runtimeSummary?: AboutRuntimeSummary | null;
}) {
  useEffect(() => {
    trackAboutEvent({ type: "about_page_viewed" });
  }, []);

  return (
    <div className="space-y-20 pb-10">
      <SectionShell id="hero">
        <AboutHero runtimeSummary={runtimeSummary ?? null} />
      </SectionShell>

      <SectionShell id="data-boundary">
        <DataBoundaryPanel />
      </SectionShell>

      <SectionShell id="open-standards">
        <OpenStandardsMap />
      </SectionShell>

      <SectionShell id="pathways">
        <PathwayGrid />
      </SectionShell>

      <SectionShell id="ecosystem">
        <EcosystemPrograms />
      </SectionShell>

      <SectionShell id="trust-footer">
        <AboutFooter />
      </SectionShell>
    </div>
  );
}
