import { useId, useState } from "react";
import { HiMiniArrowRight, HiMiniCheckCircle, HiMiniCircleStack, HiMiniDocumentText, HiMiniShieldCheck, HiMiniSquares2X2 } from "react-icons/hi2";
import type { CigarTab } from "./workspace-model";
import { CIGAR_FULL_NAME } from "./tutorial-content";

const flow = [
  { icon: HiMiniDocumentText, title: "Choose the sources", detail: "Start with evidence you have deliberately admitted.",
    explanation: "Guard admits the enabled native facts, sanitized receipt facts, and individual workspace documents you authorize before they reach CIGAR.",
    points: ["A workspace grant names its consumer and selected sources.", "Document preferences and source grants are separate choices.", "Starting a runtime grants no files, app connections, or command permissions."] },
  { icon: HiMiniCircleStack, title: "Build a scoped graph", detail: "Keep reusable context bounded to a workspace and its access.",
    explanation: "CIGAR's graph holds admitted source material and facts. Guard gives each workspace and consumer a bounded view of the evidence it may use, and the running runtime can reuse that graph for later questions.",
    points: ["A graph is an organized context store; it is not permission to read more files.", "Different workspaces and app grants retain their own scope.", "Source or policy changes can invalidate an earlier view or prepared brief."] },
  { icon: HiMiniSquares2X2, title: "Compile a cited brief", detail: "Prepare evidence for a concrete question within your budget.",
    explanation: "Your question and allowed sources guide context preparation. The result contains selected excerpts and citations, bounded by the context limits you choose.",
    points: ["Sources and revisions identifies source names, line ranges, and document revisions.", "A smaller budget limits the context prepared here; it does not change an AI model's own context window.", "Missing evidence calls for a better source or question. Increasing a budget cannot add facts that were never admitted."] },
  { icon: HiMiniShieldCheck, title: "Use it with Guard and apps", detail: "Bring the evidence to a review, an authorized app, or a supported native route.",
    explanation: "Read a cited brief in the dashboard, let a paired Guard MCP connection request scoped context, or use optional execution associations on a supported native route.",
    points: ["Guard makes and enforces command decisions and approvals.", "Each app connection needs its own explicit workspace access.", "Shared notes and saved evidence are separate opt-ins. Neither restores an expired permission."] },
];

export function CigarGuide({ onSelect }: { onSelect: (tab: CigarTab) => void }) {
  const [active, setActive] = useState(0);
  const id = useId();
  const stage = flow[active];
  return <div className="cigar-guide">
    <section className="cigar-card" aria-labelledby="cigar-explained-heading">
      <h2 id="cigar-explained-heading">{CIGAR_FULL_NAME}</h2>
      <p><strong>CIGAR</strong> prepares reusable, scoped evidence for Guard and the AI apps you authorize. Think of it as the context layer behind a task: you choose what it can use, ask a focused question, and inspect the sources behind the prepared brief.</p>
      <button type="button" className="cigar-text-button" onClick={() => onSelect("tutorials")}>Try a guided walkthrough<HiMiniArrowRight aria-hidden="true" /></button>
    </section>
    <section className="cigar-card" aria-labelledby="cigar-flow-heading">
      <h2 id="cigar-flow-heading">From your folders to a better answer</h2>
      <p className="cigar-section-description">Select a stage to explore this conceptual flow. These examples explain the process; they do not represent a graph or source grant from your workspace.</p>
      <ol className="cigar-concept-flow">
        {flow.map(({ icon: Icon, title, detail }, index) => <li key={title}>
          <button type="button" id={id + "-stage-" + index} aria-expanded={active === index} aria-controls={id + "-detail"}
            onClick={() => setActive(index)} title={detail}>
            <span className="cigar-icon"><Icon aria-hidden="true" /></span><span className="cigar-eyebrow">Stage {index + 1}</span>
            <strong>{title}</strong>
          </button>
        </li>)}
      </ol>
      <div className="cigar-concept-detail" id={id + "-detail"} role="region" aria-labelledby={id + "-stage-" + active}>
        <h3>{stage.title}</h3><p>{stage.explanation}</p>
        <ul className="cigar-simple-list">{stage.points.map((point) => <li key={point}>{point}</li>)}</ul>
      </div>
    </section>
    <div className="cigar-overview-grid">
      <section className="cigar-card" aria-labelledby="cigar-runtime-guide-heading">
        <h2 id="cigar-runtime-guide-heading">Do I need to install anything?</h2>
        <p>No. When you click Turn on CIGAR, Guard gets its own copy of Python 3.14 ready, downloads the CIGAR version it approved for this computer, checks its fingerprint and starts it. The Python you already use stays as it is.</p>
        <div className="cigar-note"><strong>If the button says it is waiting for Guard's safety check</strong><p>A CIGAR version exists for your computer, but Guard has not approved it yet. Guard never installs a version it has not checked.</p></div>
        <p>Want to pick a specific version, roll back, or see what is installed? Use Updates.</p>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("versions")}>Choose a version in Updates<HiMiniArrowRight aria-hidden="true" /></button>
      </section>
      <section className="cigar-card" aria-labelledby="cigar-first-use-heading">
        <h2 id="cigar-first-use-heading">Start with one workspace.</h2>
        <ol className="cigar-simple-list">
          <li>Click Turn on CIGAR at the top of this page.</li>
          <li>Open Projects & AI apps and grant context access for one workspace. Add individual files only if you want document context.</li>
          <li>For an available Guard review, request its context brief and inspect the cited evidence.</li>
          <li>When you want app context, enable that feature, save, and explicitly authorize a paired connection.</li>
        </ol>
        <p className="cigar-caption"><HiMiniCheckCircle aria-hidden="true" />You can keep app sharing and saved evidence off while trying review briefs.</p>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("access")}>Open Projects & AI apps<HiMiniArrowRight aria-hidden="true" /></button>
      </section>
    </div>
    <section className="cigar-card" aria-labelledby="cigar-tuning-heading">
      <h2 id="cigar-tuning-heading">Start focused, then adjust what you need</h2>
      <div className="cigar-effective-grid">
        <article><h3>Use a small source set</h3><p>Choose documents that describe the task, such as the project's release guide. Keep unrelated files out of the grant and add sources when evidence is missing.</p></article>
        <article><h3>Tune the context size</h3><p>Smaller context is a useful starting point for one workspace. Balanced allows more workspace capacity and a longer idle interval. These are resource preferences, not measured savings.</p></article>
        <article><h3>Choose storage deliberately</h3><p>Memory ends with the runtime. Optional saved evidence can outlive it, has retention controls, and uses private local files without Guard encryption. Restored evidence still needs fresh access grants.</p></article>
      </div>
      <button type="button" className="cigar-text-button" onClick={() => onSelect("runtime")}>Review context preferences<HiMiniArrowRight aria-hidden="true" /></button>
    </section>
    <section className="cigar-card cigar-faq" aria-labelledby="cigar-faq-heading">
      <h2 id="cigar-faq-heading">Common questions</h2>
      <details><summary>Does turning on CIGAR give it access to all my files?</summary><p>No. Workspace documents require the document preference and explicit access to selected sources. Starting a runtime grants no document access.</p></details>
      <details><summary>Does CIGAR save me tokens or make my AI faster?</summary><p>CIGAR does not promise either. It hands over the few pieces that answer a question, inside a size limit you set, instead of whole files, and shows where each piece came from.</p></details>
      <details><summary>Why did I get an empty or unhelpful brief?</summary><p>Check that the intended workspace and consumer have a current grant, that the right files are selected, and that the question is specific. Native facts alone do not contain your project's release guide. Refresh selected files after edits and prepare context again.</p></details>
      <details><summary>What should I do after a source or connection changes?</summary><p>Refresh changed files and prepare a new brief. For a runtime restart, revoked workspace, or expired connection, grant or pair access again as appropriate. An earlier citation describes the evidence checked at preparation time.</p></details>
      <details><summary>What happens when CIGAR is stopped or unavailable?</summary><p>Guard continues protecting commands under its existing policy and approvals. Turn off CIGAR to cancel context work. Memory context and active access end when the runtime stops.</p></details>
      <details><summary>Can two AI apps share context?</summary><p>Sharing is a separate opt-in for supported paired connections in the same app and workspace. Each connection requires access, and shared notes require your review.</p></details>
      <details><summary>What is saved on disk?</summary><p>Memory is the default. Optional saved evidence uses private local SQLite files without Guard encryption and can outlive a runtime. Privacy provides retention, diagnostics, and removal controls. Restoring evidence never restores app access or approvals.</p></details>
    </section>
  </div>;
}
