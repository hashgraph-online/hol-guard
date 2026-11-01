import {
  HiMiniArrowRight,
  HiMiniCheck,
  HiMiniCheckCircle,
  HiMiniCommandLine,
  HiMiniDocumentMagnifyingGlass,
  HiMiniLink,
  HiMiniLockClosed,
} from "react-icons/hi2";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import { cigarSetupSteps, type CigarTab } from "./workspace-model";

type Props = {
  status: ContextAssistanceStatus | null;
  installations: ContextInstallation[] | null;
  loading: boolean;
  onSelect: (tab: CigarTab) => void;
};

export function CigarOverview({ status, installations, loading, onSelect }: Props) {
  const steps = cigarSetupSteps(status, installations);
  const completed = steps.filter((step) => step.complete).length;
  const current = steps.findIndex((step) => !step.complete);
  const features = [
    { icon: HiMiniDocumentMagnifyingGlass, title: "Understand a review", description: "Read a cited brief from the context you allow before deciding what a command can do.", preference: status?.preferences.features.review_briefs },
    { icon: HiMiniLink, title: "Give AI apps useful context", description: "Pair an app with a workspace so it can request scoped context. You choose each connection's access.", preference: status?.preferences.features.agent_context },
    { icon: HiMiniCommandLine, title: "Connect context to execution", description: "Add native facts to supported captured-Bash actions. Availability and access checks still apply.", preference: status?.preferences.features.execution_context },
  ];
  return <div className="cigar-overview">
    <div className="cigar-benefits">
      {features.map(({ icon: Icon, title, description, preference }) => <article className="cigar-card cigar-benefit" key={title}>
        <span className="cigar-icon"><Icon aria-hidden="true" /></span>
        <h3>{title}</h3><p>{description}</p>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("runtime")}>
          {preference ? "Preference on" : "Choose this feature"}<HiMiniArrowRight aria-hidden="true" />
        </button>
      </article>)}
    </div>
    <div className="cigar-overview-grid">
      <section className="cigar-card cigar-setup" aria-labelledby="cigar-setup-heading">
        <div className="cigar-section-heading">
          <div><span className="cigar-eyebrow">Get started</span><h2 id="cigar-setup-heading">Your path to useful context</h2></div>
          <span className="cigar-count">{loading || !status ? "Checking setup" : String(completed) + " of 3 complete"}</span>
        </div>
        <ol className="cigar-steps">
          {steps.map((step, index) => <li key={step.title} data-complete={step.complete} aria-current={index === current && status ? "step" : undefined}>
            <span className="cigar-step-number">{step.complete ? <><HiMiniCheck aria-hidden="true" /><span className="sr-only">Complete: </span></> : index + 1}</span>
            <div><h3>{step.title}</h3><p>{step.description}</p>
              <button type="button" className="cigar-text-button" onClick={() => onSelect(step.tab)}>{step.action}<HiMiniArrowRight aria-hidden="true" /></button>
            </div>
          </li>)}
        </ol>
        <div className="cigar-next-step">
          <HiMiniLink aria-hidden="true" />
          <div><h3>Next, choose sources and app access</h3><p>Workspace files, AI app connections, and sharing each need your permission.</p>
            <button type="button" className="cigar-text-button" onClick={() => onSelect("access")}>Manage sources & AI apps<HiMiniArrowRight aria-hidden="true" /></button>
          </div>
        </div>
      </section>
      <aside className="cigar-card cigar-boundaries" aria-labelledby="cigar-boundaries-heading">
        <span className="cigar-icon"><HiMiniLockClosed aria-hidden="true" /></span>
        <h2 id="cigar-boundaries-heading">You choose the context.</h2>
        <p>Start with native Guard facts. Add workspace files and app access when they help your work.</p>
        <ul>
          <li><HiMiniCheckCircle aria-hidden="true" />Optional, with a visible off switch</li>
          <li><HiMiniCheckCircle aria-hidden="true" />Memory storage by default</li>
          <li><HiMiniCheckCircle aria-hidden="true" />Separate choices for app sharing and saved evidence</li>
          <li><HiMiniCheckCircle aria-hidden="true" />Guard keeps authority over approvals and execution</li>
        </ul>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("guide")}>See how CIGAR works<HiMiniArrowRight aria-hidden="true" /></button>
      </aside>
    </div>
  </div>;
}
