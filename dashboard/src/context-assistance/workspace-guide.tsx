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
      <span className="cigar-eyebrow">Meet CIGAR</span><h2 id="cigar-explained-heading">{CIGAR_FULL_NAME}</h2>
      <p><strong>CIGAR</strong> prepares reusable, scoped evidence for Guard and the AI apps you authorize. Think of it as the context layer behind a task: you choose what it can use, ask a focused question, and inspect the sources behind the prepared brief.</p>
      <button type="button" className="cigar-text-button" onClick={() => onSelect("tutorials")}>Try a guided walkthrough<HiMiniArrowRight aria-hidden="true" /></button>
    </section>
    <section className="cigar-card" aria-labelledby="cigar-flow-heading">
      <div className="cigar-section-heading"><div><span className="cigar-eyebrow">How it works</span><h2 id="cigar-flow-heading">From your sources to a better informed action</h2></div></div>
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
        <span className="cigar-eyebrow">Runtime setup</span><h2 id="cigar-runtime-guide-heading">Python installed? Here is what comes next.</h2>
        <p>Final CPython 3.14 is required for the selected CIGAR runtime. Python 3.14.7 qualifies. Guard itself can use another supported Python version.</p>
        <p>A registered runtime includes the CIGAR package and its matching worker as well as Python. Guard checks their identities and runs a compilation check before activation.</p>
        <div className="cigar-note"><strong>An empty list means no bundle is registered.</strong><p>It does not establish which Python versions are installed. Refreshing the list reads registrations; it does not scan your machine or install packages.</p></div>
        <p>Use Versions & updates to inspect registered installations and catalog builds. Preparation requires a qualified artifact for this Guard host; a listed upstream release alone does not authorize installation.</p>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("versions")}>Choose a runtime in Versions & updates<HiMiniArrowRight aria-hidden="true" /></button>
      </section>
      <section className="cigar-card" aria-labelledby="cigar-first-use-heading">
        <span className="cigar-eyebrow">Try it first</span><h2 id="cigar-first-use-heading">Start with one workspace.</h2>
        <ol className="cigar-simple-list">
          <li>Prepare and select a runtime in Versions & updates. Then enable review briefs in Runtime & preferences, save, and start CIGAR.</li>
          <li>Open Sources & AI apps and grant context access for one workspace. Add individual files only if you want document context.</li>
          <li>For an available Guard review, request its context brief and inspect the cited evidence.</li>
          <li>When you want app context, enable that feature, save, and explicitly authorize a paired connection.</li>
        </ol>
        <p className="cigar-caption"><HiMiniCheckCircle aria-hidden="true" />You can keep app sharing and saved evidence off while trying review briefs.</p>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("access")}>Open sources & AI apps<HiMiniArrowRight aria-hidden="true" /></button>
      </section>
    </div>
    <section className="cigar-card" aria-labelledby="cigar-tuning-heading">
      <span className="cigar-eyebrow">Build a useful habit</span><h2 id="cigar-tuning-heading">Start focused, then adjust what you need</h2>
      <div className="cigar-effective-grid">
        <article><h3>Use a small source set</h3><p>Choose documents that describe the task, such as the project's release guide. Keep unrelated files out of the grant and add sources when evidence is missing.</p></article>
        <article><h3>Tune the context size</h3><p>Smaller context is a useful starting point for one workspace. Balanced allows more workspace capacity and a longer idle interval. These are resource preferences, not measured savings.</p></article>
        <article><h3>Choose storage deliberately</h3><p>Memory ends with the runtime. Optional saved evidence can outlive it, has retention controls, and uses private local files without Guard encryption. Restored evidence still needs fresh access grants.</p></article>
      </div>
      <button type="button" className="cigar-text-button" onClick={() => onSelect("runtime")}>Review context preferences<HiMiniArrowRight aria-hidden="true" /></button>
    </section>
    <section className="cigar-card cigar-faq" aria-labelledby="cigar-faq-heading">
      <span className="cigar-eyebrow">Good to know</span><h2 id="cigar-faq-heading">Common questions</h2>
      <details><summary>Does turning on CIGAR give it access to all my files?</summary><p>No. Workspace documents require the document preference and explicit access to selected sources. Starting a runtime grants no document access.</p></details>
      <details><summary>What is the difference between saving and starting?</summary><p>Saving records your preferences. Starting verifies and activates the selected runtime. A saved on preference can still be unavailable; use the live status to confirm Ready.</p></details>
      <details><summary>Why did I get an empty or unhelpful brief?</summary><p>Check that the intended workspace and consumer have a current grant, that the right files are selected, and that the question is specific. Native facts alone do not contain your project's release guide. Refresh selected files after edits and prepare context again.</p></details>
      <details><summary>What should I do after a source or connection changes?</summary><p>Refresh changed files and prepare a new brief. For a runtime restart, revoked workspace, or expired connection, grant or pair access again as appropriate. An earlier citation describes the evidence checked at preparation time.</p></details>
      <details><summary>What happens when CIGAR is stopped or unavailable?</summary><p>Guard continues protecting commands under its existing policy and approvals. Turn off CIGAR to cancel context work. Memory context and active access end when the runtime stops.</p></details>
      <details><summary>Can two AI apps share context?</summary><p>Sharing is a separate opt-in for supported paired connections in the same app and workspace. Each connection requires access, and shared notes require your review.</p></details>
      <details><summary>What is saved on disk?</summary><p>Memory is the default. Optional saved evidence uses private local SQLite files without Guard encryption and can outlive a runtime. Data & privacy provides retention, diagnostics, and removal controls. Restoring evidence never restores app access or approvals.</p></details>
    </section>
  </div>;
}
