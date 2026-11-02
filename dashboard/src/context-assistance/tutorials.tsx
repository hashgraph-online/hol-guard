import { useEffect, useId, useState } from "react";
import { HiMiniArrowLeft, HiMiniArrowRight, HiMiniClipboardDocument, HiMiniXMark } from "react-icons/hi2";
import { contextStatusCopy } from "./status";
import { CIGAR_TUTORIALS, type CigarTutorial, type CigarTutorialId } from "./tutorial-content";
import type { CigarTutorialProgress } from "./tutorial-progress";
import type { ContextAssistanceStatus } from "./types";

export function CigarTutorials(props: {
  progress: CigarTutorialProgress;
  onBegin: (id: CigarTutorialId, resume?: boolean) => void;
}) {
  return <section className="cigar-walkthroughs" aria-labelledby="cigar-tutorials-heading">
    <div className="cigar-section-intro"><h2 id="cigar-tutorials-heading">Guided walkthroughs</h2>
      <p>Short step-by-step lessons. They only explain; you choose every setting, start and access grant.</p></div>
    <div className="cigar-benefits">
      {CIGAR_TUTORIALS.map((tutorial) => <article className="cigar-card cigar-benefit" key={tutorial.id}>
        <span className="cigar-eyebrow">{tutorial.level}</span><h3>{tutorial.title}</h3><p>{tutorial.description}</p>
        <p className="cigar-learning-caption">{tutorial.steps.length} guided steps</p>
        <div className="cigar-lesson-outcome"><strong>What you will learn</strong><p>{tutorial.outcome}</p></div>
        <button type="button" className="cigar-text-button" onClick={() => props.onBegin(tutorial.id, props.progress.tutorial === tutorial.id && props.progress.step > 0)}>
          {props.progress.tutorial === tutorial.id && props.progress.step > 0 ? "Resume walkthrough" : "Start walkthrough"}<HiMiniArrowRight aria-hidden="true" />
          <span className="sr-only">: {tutorial.title}</span>
        </button>
      </article>)}
    </div>
  </section>;
}

export function CigarWalkthrough(props: {
  tutorial: CigarTutorial;
  step: number;
  status: ContextAssistanceStatus | null;
  dirty: boolean;
  onMove: (step: number) => void;
  onOpen: () => void;
  onExit: () => void;
}) {
  const id = useId();
  const [copyMessage, setCopyMessage] = useState("");
  const step = props.tutorial.steps[props.step];
  const last = props.step === props.tutorial.steps.length - 1;
  const liveStatus = props.status ? contextStatusCopy(props.status).label : "Status unavailable";
  useEffect(() => { setCopyMessage(""); }, [props.step, props.tutorial.id]);

  async function copyQuestion() {
    if (!step.question) return;
    try {
      if (!navigator.clipboard) throw new Error("clipboard_unavailable");
      await navigator.clipboard.writeText(step.question);
      setCopyMessage("Question copied. Paste it into the context question field or your authorized app.");
    } catch {
      setCopyMessage("Select the example text and copy it with your usual keyboard or touch controls.");
    }
  }

  return <aside className="cigar-card cigar-walkthrough" aria-labelledby={id + "-title"}>
    <div className="flex justify-end">
      <button type="button" className="cigar-walkthrough-close" onClick={props.onExit} aria-label="Exit walkthrough"><HiMiniXMark aria-hidden="true" /></button>
    </div>
    <h2 id={id + "-title"}>{props.tutorial.title}</h2>
    <p className="cigar-learning-caption">Step {props.step + 1} of {props.tutorial.steps.length} · learning progress</p>
    <details className="cigar-lesson-index"><summary>All {props.tutorial.steps.length} steps</summary>
    <ol className="cigar-lesson-steps" aria-label="Walkthrough steps">
      {props.tutorial.steps.map((item, index) => <li key={item.title}>
        <button type="button" aria-current={props.step === index ? "step" : undefined} onClick={() => props.onMove(index)}>
          <span>{index + 1}</span><span>{item.title}</span>
        </button>
      </li>)}
    </ol>
    </details>
    <div className="cigar-lesson-body" aria-live="polite" aria-atomic="false">
      <h3>{step.title}</h3><p>{step.description}</p>
      <ol className="cigar-simple-list">{step.instructions.map((instruction) => <li key={instruction}>{instruction}</li>)}</ol>
      {step.question ? <div className="cigar-example-question"><strong>Example question</strong><p>{step.question}</p>
        <button type="button" className="cigar-text-button" onClick={() => void copyQuestion()}><HiMiniClipboardDocument aria-hidden="true" />Copy question</button>
        <span role="status" className="cigar-learning-caption">{copyMessage}</span>
      </div> : null}
      <div className="cigar-lesson-outcome"><strong>What to look for</strong><p>{step.expect}</p></div>
      {step.tip ? <p className="cigar-learning-tip">{step.tip}</p> : null}
      <button type="button" className="cigar-text-button" onClick={props.onOpen}>{step.action}<HiMiniArrowRight aria-hidden="true" /></button>
    </div>
    <div className="cigar-lesson-navigation">
      <button type="button" className="cigar-button" disabled={props.step === 0} onClick={() => props.onMove(props.step - 1)}><HiMiniArrowLeft aria-hidden="true" />Back</button>
      <button type="button" className="cigar-button" onClick={() => last ? props.onExit() : props.onMove(props.step + 1)}>{last ? "Finish walkthrough" : "Next step"}<HiMiniArrowRight aria-hidden="true" /></button>
    </div>
    <p className="cigar-learning-caption">Live runtime: <strong>{liveStatus}</strong>{props.dirty ? " · unsaved preferences" : ""}. Reading ahead does not complete setup or grant access.</p>
    <button type="button" className="cigar-text-button" onClick={() => props.onMove(0)}>Restart this walkthrough</button>
  </aside>;
}
