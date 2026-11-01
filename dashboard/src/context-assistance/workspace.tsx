import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { HiMiniArrowPath, HiMiniArrowRight, HiMiniCircleStack, HiMiniCpuChip, HiMiniShieldCheck } from "react-icons/hi2";
import { contextStatusCopy } from "./status";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import { CigarGuide } from "./workspace-guide";
import { CigarOverview } from "./workspace-overview";
import { CIGAR_TABS, canStartCigar, cigarRuntimeSummary, cigarTabFromSearch, type CigarTab } from "./workspace-model";
import { CIGAR_FULL_NAME, cigarTutorial, type CigarTutorialId } from "./tutorial-content";
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
  versions?: ReactNode;
  controls: ReactNode;
  access: ReactNode;
  data: ReactNode;
  onRefresh: () => void;
  onStart: () => void;
  onStop: () => void;
};

export function CigarWorkspace(props: CigarWorkspaceProps) {
  const [tab, setTab] = useState<CigarTab>(() => cigarTabFromSearch(typeof window === "undefined" ? "" : window.location.search));
  const id = useId();
  const panel = useRef<HTMLDivElement>(null);
  const walkthroughAnchor = useRef<HTMLDivElement>(null);
  const lesson = useCigarTutorial();
  const status = props.status;
  const copy = props.loading ? { label: "Checking status", detail: "Reading the local runtime registration and availability." }
    : status ? contextStatusCopy(status) : { label: "Status unavailable", detail: "Reconnect to the local Guard service, then refresh. Your Python version has not been checked here." };
  const runtime = cigarRuntimeSummary(status, props.installations);
  const canStop = props.stopAvailable ?? Boolean(status?.requested_enabled || status?.effective_enabled || status?.job);
  const startRequested = status?.requested_enabled === true && !status.effective_enabled;
  const primaryLabel = status?.job ? status.job.phase === "cancelling" ? "Stopping…" : "Checking runtime…"
    : props.dirty ? "Save preferences first" : status?.effective_enabled ? "Use CIGAR"
    : startRequested ? "Start CIGAR" : "Get started";
  const primaryDisabled = props.disabled || props.busy || props.loading || Boolean(status?.job)
    || (!props.dirty && startRequested && !canStartCigar(status, props.dirty));

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
      <div><span className="cigar-eyebrow">Local context assistance</span><h1><HiMiniCircleStack aria-hidden="true" />CIGAR</h1><p>{CIGAR_FULL_NAME}</p></div>
      <div className="cigar-heading-actions">
        {canStop ? <button type="button" className="cigar-button" disabled={props.disabled || props.busy} onClick={props.onStop}>Turn off CIGAR</button> : null}
        <button type="button" className="cigar-button" disabled={props.disabled || props.busy || props.loading} onClick={props.onRefresh}><HiMiniArrowPath aria-hidden="true" />Refresh status</button>
      </div>
    </header>
    <section className="cigar-hero" aria-labelledby="cigar-hero-heading">
      <div className="cigar-hero-copy">
        <span className="cigar-hero-kicker"><span aria-hidden="true" />Optional. Local. Yours to control.</span>
        <h2 id="cigar-hero-heading">Bring the right context<br className="hidden sm:block" /> to your next action.</h2>
        <p>Turn the sources you trust into useful context for command reviews, connected AI apps, and supported execution flows.</p>
        <div className="cigar-hero-actions">
          <button type="button" className="cigar-button cigar-button-primary" disabled={primaryDisabled}
            onClick={() => {
              if (canStartCigar(status, props.dirty)) props.onStart();
              else select(!props.dirty && status?.effective_enabled ? "access" : "runtime");
            }}>{primaryLabel}<HiMiniArrowRight aria-hidden="true" /></button>
          <button type="button" className="cigar-hero-link" onClick={() => select("guide")}>How it works<HiMiniArrowRight aria-hidden="true" /></button>
          <button type="button" className="cigar-hero-link" onClick={() => select("tutorials")}>Take a walkthrough<HiMiniArrowRight aria-hidden="true" /></button>
        </div>
        {props.dirty ? <p className="mt-3 text-xs text-slate-200">Save your changes before starting CIGAR or granting context access.</p> : null}
      </div>
      <div className="cigar-runtime-card">
        <div className="cigar-runtime-top"><span className="cigar-eyebrow">On this machine</span><span className="cigar-status" data-ready={status?.effective_enabled === true} role="status"><span aria-hidden="true" />{copy.label}</span></div>
        <HiMiniCpuChip className="cigar-runtime-symbol" aria-hidden="true" />
        <h3>{props.loading ? "Reading runtime…" : runtime.label}</h3><p>{props.loading ? "No runtime is started by opening this page." : runtime.detail}</p>
        <div className="cigar-runtime-note">{copy.detail}</div>
      </div>
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
      {tab === "overview" ? <CigarOverview status={status} installations={props.installations} loading={props.loading} onSelect={select} /> : null}
      <div hidden={tab !== "runtime"}>
        <div className="cigar-section-intro"><span className="cigar-eyebrow">Make it yours</span><h2>Runtime & preferences</h2><p>Manage runtime selection in Versions & updates, choose the features you want here, and save. Start the runtime when you are ready to use context.</p></div>
        {props.installations?.length === 0 ? <div className="cigar-note"><strong>No CIGAR bundle is registered in this Guard profile.</strong><p>Python 3.14 may already be installed. Guard also needs the approved CIGAR package and worker registered together; an empty list does not mean your Python is incompatible.</p><button type="button" className="cigar-text-button" onClick={() => select("guide")}>Read the runtime setup guide<HiMiniArrowRight aria-hidden="true" /></button></div> : null}
        {props.controls}
      </div>
      {tab === "versions" ? props.versions : null}
      {tab === "access" ? <div><div className="cigar-section-intro"><span className="cigar-eyebrow">Give context a scope</span><h2>Sources & AI apps</h2><p>Grant access to one workspace at a time. Choose documents and app connections explicitly; sharing requires its own preference.</p></div>{!status?.effective_enabled ? <div className="cigar-note"><strong>Start CIGAR before granting context access.</strong><p>Save your runtime and feature preferences, then start context assistance. Sources and app access become available when the runtime is Ready.</p><button type="button" className="cigar-text-button" onClick={() => select("runtime")}>Open runtime & preferences<HiMiniArrowRight aria-hidden="true" /></button></div> : null}{props.access}</div> : null}
      {tab === "data" ? <div><div className="cigar-section-intro"><span className="cigar-eyebrow">Stay in control</span><h2>Data & privacy</h2><p>Review context storage, revoke access, clear saved evidence, or stop the runtime. Storage and retention preferences live in Runtime & preferences.</p></div>{props.data}</div> : null}
      {tab === "tutorials" ? <CigarTutorials progress={lesson.progress} onBegin={beginTutorial} /> : null}
      {tab === "guide" ? <CigarGuide onSelect={select} /> : null}
    </div>
    </div>
    <footer className="cigar-footer"><HiMiniShieldCheck aria-hidden="true" /><span>Guard makes and enforces security decisions. CIGAR supplies context from the sources you authorize.</span>{props.dirty ? <strong>Unsaved preferences</strong> : null}</footer>
  </div>;
}
