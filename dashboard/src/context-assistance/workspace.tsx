import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { HiMiniArrowPath, HiMiniArrowRight, HiMiniCircleStack, HiMiniShieldCheck } from "react-icons/hi2";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import { CigarSetupAction, CigarSetupProgress, type CigarOneClick } from "./one-click-setup";
import { CigarGuide } from "./workspace-guide";
import { CigarOverview } from "./workspace-overview";
import { CIGAR_TABS, cigarTabFromSearch, type CigarTab } from "./workspace-model";
import { cigarTutorial, type CigarTutorialId } from "./tutorial-content";
import { useCigarTutorial } from "./tutorial-progress";
import { CigarTutorials, CigarWalkthrough } from "./tutorials";
import { subscribeDashboardLocation } from "../dashboard-location";

export type CigarWorkspaceProps = {
  status: ContextAssistanceStatus | null;
  installations: ContextInstallation[] | null;
  loading: boolean;
  busy: boolean;
  disabled: boolean;
  dirty: boolean;
  stopAvailable?: boolean;
  error: string | null;
  setup: CigarOneClick;
  versions?: ReactNode;
  controls: ReactNode;
  access: ReactNode;
  data: ReactNode;
  onRefresh: () => void;
  onStop: () => void;
};

export function CigarWorkspace(props: CigarWorkspaceProps) {
  const [tab, setTab] = useState<CigarTab>(() => cigarTabFromSearch(typeof window === "undefined" ? "" : window.location.search));
  const id = useId();
  const panel = useRef<HTMLDivElement>(null);
  const walkthroughAnchor = useRef<HTMLDivElement>(null);
  const lesson = useCigarTutorial();
  const status = props.status;
  const canStop = props.stopAvailable ?? Boolean(status?.requested_enabled || status?.effective_enabled || status?.job);
  const actionDisabled = props.disabled || props.busy || props.loading;

  useEffect(() => {
    const sync = () => setTab(cigarTabFromSearch(window.location.search));
    return subscribeDashboardLocation(sync);
  }, []);

  function select(next: CigarTab, focusPanel = true) {
    setTab(next);
    const url = new URL(window.location.href);
    url.searchParams.set("section", next);
    window.history.replaceState({}, "", url.pathname + url.search + url.hash);
    if (focusPanel) window.requestAnimationFrame(() => panel.current?.focus());
  }

  function moveTab(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    let next: number;
    if (event.key === "ArrowRight") next = (index + 1) % CIGAR_TABS.length;
    else if (event.key === "ArrowLeft") next = (index + CIGAR_TABS.length - 1) % CIGAR_TABS.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = CIGAR_TABS.length - 1;
    else return;
    event.preventDefault();
    select(CIGAR_TABS[next].value, false);
    document.getElementById(id + "-tab-" + CIGAR_TABS[next].value)?.focus();
  }

  function focusWalkthrough() {
    window.requestAnimationFrame(() => {
      walkthroughAnchor.current?.focus({ preventScroll: true });
      walkthroughAnchor.current?.scrollIntoView({ block: "start" });
    });
  }

  function beginTutorial(tutorial: CigarTutorialId, resume = false) {
    const progress = lesson.begin(tutorial, resume);
    select(cigarTutorial(progress.tutorial).steps[progress.step].target, false);
    focusWalkthrough();
  }

  function moveTutorial(step: number) {
    const progress = lesson.move(step);
    select(cigarTutorial(progress.tutorial).steps[progress.step].target, false);
    focusWalkthrough();
  }

  return <div className="cigar-workspace" data-testid="cigar-workspace">
    <header className="cigar-heading">
      <div><h1><HiMiniCircleStack aria-hidden="true" />CIGAR</h1><p>A context helper for your AI that runs on your computer.</p></div>
      <div className="cigar-heading-actions">
        {canStop ? <button type="button" className="cigar-button" disabled={props.disabled || props.busy} onClick={props.onStop}>Turn off CIGAR</button> : null}
        <button type="button" className="cigar-button" disabled={props.disabled || props.busy || props.loading} onClick={props.onRefresh}><HiMiniArrowPath aria-hidden="true" />Refresh status</button>
      </div>
    </header>
    <aside className="cigar-beta-note" aria-label="CIGAR beta status">
      <span className="cigar-beta-note__chip">Beta</span>
      <p>CIGAR is still being iterated on. Screens and settings may change between releases.</p>
      <a href="https://github.com/hashgraph-online/hol-cigar/issues" target="_blank" rel="noopener noreferrer">Share feedback</a>
    </aside>
    <section className="cigar-hero" aria-labelledby="cigar-hero-heading">
      <div className="cigar-hero-copy">
        <h2 id="cigar-hero-heading">Give your AI the right pages,<br className="hidden sm:block" /> not the whole book.</h2>
        <p>Think of CIGAR as a librarian on your computer. You choose the books. When your AI or Guard has a question, CIGAR finds the few pages that answer it and shows where each one came from.</p>
        <CigarSetupAction setup={props.setup} status={status} disabled={actionDisabled} tone="hero" onOpen={select} />
        <div className="cigar-hero-actions">
          <button type="button" className="cigar-hero-link" onClick={() => select("guide")}>How it works<HiMiniArrowRight aria-hidden="true" /></button>
          <button type="button" className="cigar-hero-link" onClick={() => select("tutorials")}>Take a walkthrough<HiMiniArrowRight aria-hidden="true" /></button>
        </div>
      </div>
      <CigarSetupProgress setup={props.setup} status={status} loading={props.loading} />
    </section>
    {props.error ? <div className="cigar-note" role="alert"><strong>CIGAR needs attention</strong><p>{props.error}</p></div> : null}
    <nav className="cigar-tabs" role="tablist" aria-label="CIGAR sections">
      {CIGAR_TABS.map((item, index) => <button key={item.value} id={id + "-tab-" + item.value} type="button" role="tab"
        aria-selected={tab === item.value} aria-controls={id + "-panel"} tabIndex={tab === item.value ? 0 : -1}
        onKeyDown={(event) => moveTab(event, index)} onClick={() => select(item.value, false)}>{item.label}</button>)}
    </nav>
    <div className={"cigar-learning-layout" + (lesson.active ? " has-walkthrough" : "")}>
      {lesson.active ? <div ref={walkthroughAnchor} tabIndex={-1} className="cigar-walkthrough-anchor">
        <CigarWalkthrough tutorial={lesson.tutorial} step={lesson.progress.step} status={status} dirty={props.dirty}
          onMove={moveTutorial} onOpen={() => select(lesson.tutorial.steps[lesson.progress.step].target)}
          onExit={() => { lesson.exit(); select("tutorials"); }} />
      </div> : null}
    <div ref={panel} id={id + "-panel"} role="tabpanel" aria-labelledby={id + "-tab-" + tab} tabIndex={-1} className="cigar-panel">
      {tab === "overview" ? <CigarOverview status={status} onSelect={select} /> : null}
      <div hidden={tab !== "runtime"}>
        <div className="cigar-section-intro"><h2>Settings</h2><p>CIGAR works well with the recommended settings. Change these only if you want to.</p></div>
        {!props.loading && !status?.effective_enabled && props.setup.run.phase !== "running" ? <div className="cigar-note"><strong>CIGAR is off</strong><p>Turn it on first. Guard sets everything up for you.</p><CigarSetupAction setup={props.setup} status={status} disabled={actionDisabled} onOpen={select} /></div> : null}
        {props.controls}
      </div>
      {tab === "versions" ? props.versions : null}
      {tab === "access" ? <div><div className="cigar-section-intro"><h2>Projects & AI apps</h2><p>Pick the project folders CIGAR may read, one at a time. Then connect an AI app if you want. Each step asks you first.</p></div>{!status?.effective_enabled ? <div className="cigar-note"><strong>Turn on CIGAR first</strong><p>Projects and AI apps open up as soon as CIGAR is on.</p><CigarSetupAction setup={props.setup} status={status} disabled={actionDisabled} onOpen={select} /></div> : null}{props.access}</div> : null}
      {tab === "data" ? <div><div className="cigar-section-intro"><h2>Privacy</h2><p>By default, CIGAR keeps its notes in memory only, so they disappear when you turn it off. Here you can see what it keeps, take back access, or delete saved notes.</p></div>{props.data}</div> : null}
      {tab === "tutorials" ? <CigarTutorials progress={lesson.progress} onBegin={beginTutorial} /> : null}
      {tab === "guide" ? <CigarGuide onSelect={select} /> : null}
    </div>
    </div>
    <footer className="cigar-footer"><HiMiniShieldCheck aria-hidden="true" /><span>Guard still decides what your AI may do. CIGAR only helps explain, using the folders you pick.</span>{props.dirty ? <strong>Unsaved changes</strong> : null}</footer>
  </div>;
}
