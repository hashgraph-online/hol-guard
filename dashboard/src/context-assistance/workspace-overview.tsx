import { HiMiniArrowRight, HiMiniCheck, HiMiniCheckCircle, HiMiniLockClosed } from "react-icons/hi2";
import { CigarWhy } from "./one-click-setup";
import type { ContextAssistanceStatus } from "./types";
import { cigarSetupSteps, type CigarTab } from "./workspace-model";

type Props = {
  status: ContextAssistanceStatus | null;
  onSelect: (tab: CigarTab) => void;
};

export function CigarOverview({ status, onSelect }: Props) {
  const steps = cigarSetupSteps(status);
  const current = steps.findIndex((step) => !step.complete);
  return <div className="cigar-overview">
    <section aria-labelledby="cigar-why-heading">
      <h2 id="cigar-why-heading" className="cigar-overview-title">What CIGAR does for you</h2>
      <CigarWhy />
    </section>
    <div className="cigar-overview-grid">
      <section className="cigar-card cigar-setup" aria-labelledby="cigar-setup-heading">
        <h2 id="cigar-setup-heading">Three steps, and only the first is needed</h2>
        <ol className="cigar-steps">
          {steps.map((step, index) => <li key={step.title} data-complete={step.complete} aria-current={index === current && status ? "step" : undefined}>
            <span className="cigar-step-number">{step.complete ? <><HiMiniCheck aria-hidden="true" /><span className="sr-only">Done: </span></> : index + 1}</span>
            <div><h3>{step.title}</h3><p>{step.description}</p>
              {step.action ? <button type="button" className="cigar-text-button" onClick={() => onSelect(step.tab)}>{step.action}<HiMiniArrowRight aria-hidden="true" /></button> : null}
            </div>
          </li>)}
        </ol>
      </section>
      <aside className="cigar-card cigar-boundaries" aria-labelledby="cigar-boundaries-heading">
        <span className="cigar-icon"><HiMiniLockClosed aria-hidden="true" /></span>
        <h2 id="cigar-boundaries-heading">You stay in charge.</h2>
        <ul>
          <li><HiMiniCheckCircle aria-hidden="true" />Off until you turn it on, and off again with one click</li>
          <li><HiMiniCheckCircle aria-hidden="true" />Reads only the folders you pick</li>
          <li><HiMiniCheckCircle aria-hidden="true" />Keeps notes in memory unless you choose to save them</li>
          <li><HiMiniCheckCircle aria-hidden="true" />Guard still decides what your AI may do</li>
        </ul>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("guide")}>See how CIGAR works<HiMiniArrowRight aria-hidden="true" /></button>
      </aside>
    </div>
  </div>;
}
