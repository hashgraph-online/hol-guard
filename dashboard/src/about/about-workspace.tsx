/*
 * THESIS: The About page proves Guard's local-first promise by drawing the
 *   boundary it describes, with this install's live state on it.
 * OWN-WORLD: Guard dashboard system as committed (DESIGN.md): brand-dark ink,
 *   brand-blue for the one active path, light borders for depth, system type.
 *   The page opens on Home's branded hero (brand-hero.tsx): the gradient
 *   surface and the HOL particle mark, tinted by this install's state.
 * STORY: See the device and what can cross its edge, read the four claims the
 *   figure numbers, check the data table, then choose where to go next.
 * FIRST VIEWPORT: The branded hero with title, one line, the two outbound
 *   actions and this install's facts, then Fig. 1, the labeled diagram of
 *   agents, Guard, decisions, records, the sync gate and hol.org.
 * FORM: c1031d85, structure "Fig. 1: This Machine".
 * FINISH: unreviewed and undocumented is unfinished; this build ends with the
 *   finish review, the verdict, and DESIGN.md.
 */
import { useEffect } from "react";
import "./about-page.css";
import { AboutHero } from "./components/about-hero";
import { TrustContractPanel } from "./components/trust-contract-panel";
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
    <div className="about-page space-y-16 pb-10 lg:space-y-20">
      <SectionShell id="hero" labelledBy="about-hero-heading">
        <AboutHero runtimeSummary={runtimeSummary ?? null} />
      </SectionShell>

      <SectionShell id="trust-contract" labelledBy="about-trust-heading">
        <TrustContractPanel />
      </SectionShell>

      <SectionShell id="data-boundary" labelledBy="about-data-boundary-heading">
        <DataBoundaryPanel />
      </SectionShell>

      <SectionShell id="open-standards" labelledBy="about-open-standards-heading">
        <OpenStandardsMap />
      </SectionShell>

      <SectionShell id="pathways" labelledBy="about-pathways-heading">
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
