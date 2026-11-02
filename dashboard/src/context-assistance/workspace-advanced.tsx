import { useId, type KeyboardEvent, type ReactNode, type RefObject } from "react";
import { HiMiniChevronRight } from "react-icons/hi2";
import { CigarGuide } from "./workspace-guide";
import { CIGAR_TABS, cigarWaking, type CigarAdvancedTab, type CigarTab } from "./workspace-model";
import type { ContextAssistanceStatus } from "./types";
import type { CigarTutorialId } from "./tutorial-content";
import type { useCigarTutorial } from "./tutorial-progress";
import { CigarTutorials, CigarWalkthrough } from "./tutorials";

export type CigarAdvancedProps = {
  tab: CigarTab;
  status: ContextAssistanceStatus | null;
  dirty: boolean;
  lesson: ReturnType<typeof useCigarTutorial>;
  versions?: ReactNode;
  controls: ReactNode;
  access: ReactNode;
  data: ReactNode;
  panelRef: RefObject<HTMLDivElement | null>;
  walkthroughRef: RefObject<HTMLDivElement | null>;
  onToggle: () => void;
  onSelect: (tab: CigarTab, focusPanel?: boolean) => void;
  onBegin: (id: CigarTutorialId, resume?: boolean) => void;
  onMove: (step: number) => void;
  onExitLesson: () => void;
};

function Intro({ title, children }: { title: string; children: ReactNode }) {
  return <div className="cigar-section-intro"><h2>{title}</h2><p>{children}</p></div>;
}

/** Everything beyond the on/off switch, closed until someone asks for it. */
export function CigarAdvanced(props: CigarAdvancedProps) {
  const { tab, status, lesson } = props;
  const id = useId();
  const open = tab !== "overview";

  function moveTab(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    let next: number;
    if (event.key === "ArrowRight") next = (index + 1) % CIGAR_TABS.length;
    else if (event.key === "ArrowLeft") next = (index + CIGAR_TABS.length - 1) % CIGAR_TABS.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = CIGAR_TABS.length - 1;
    else return;
    event.preventDefault();
    props.onSelect(CIGAR_TABS[next].value, false);
    document.getElementById(id + "-tab-" + CIGAR_TABS[next].value)?.focus();
  }

  const active: CigarAdvancedTab | null = open ? tab as CigarAdvancedTab : null;
  const walkthroughs = <CigarTutorials progress={lesson.progress} onBegin={props.onBegin} />;
  return <section className="cigar-advanced" data-open={open} aria-label="Advanced">
    <button type="button" className="cigar-advanced-toggle" aria-expanded={open} aria-controls={id + "-body"} onClick={props.onToggle}>
      <HiMiniChevronRight aria-hidden="true" />
      <span><strong>Advanced</strong><small>Projects, AI apps, settings, updates and privacy</small></span>
    </button>
    {open ? <div id={id + "-body"} className="cigar-advanced-body">
      <nav className="cigar-tabs" role="tablist" aria-label="CIGAR sections">
        {CIGAR_TABS.map((item, index) => <button key={item.value} id={id + "-tab-" + item.value} type="button" role="tab"
          aria-selected={tab === item.value} aria-controls={id + "-panel"} tabIndex={tab === item.value ? 0 : -1}
          onKeyDown={(event) => moveTab(event, index)} onClick={() => props.onSelect(item.value, false)}>{item.label}</button>)}
      </nav>
      <div className={"cigar-learning-layout" + (lesson.active ? " has-walkthrough" : "")}>
        {lesson.active ? <div ref={props.walkthroughRef} tabIndex={-1} className="cigar-walkthrough-anchor">
          <CigarWalkthrough tutorial={lesson.tutorial} step={lesson.progress.step} status={status} dirty={props.dirty}
            onMove={props.onMove} onOpen={() => props.onSelect(lesson.tutorial.steps[lesson.progress.step].target)}
            onExit={props.onExitLesson} />
        </div> : null}
        <div ref={props.panelRef} id={id + "-panel"} role="tabpanel" aria-labelledby={id + "-tab-" + tab} tabIndex={-1} className="cigar-panel">
          <div hidden={active !== "runtime"}>
            <Intro title="Settings">CIGAR works well with the recommended settings. Change these only if you want to.</Intro>
            {props.controls}
          </div>
          {active === "versions" ? props.versions : null}
          {active === "access" ? <div>
            <Intro title="Projects & AI apps">Optional. Pick a project folder to choose exactly which files CIGAR uses for it, or connect an AI app. Each step asks you first.</Intro>
            {!status?.effective_enabled ? <div className="cigar-note">
              {cigarWaking(status)
                ? <><strong>Waking up CIGAR</strong><p>Your projects and AI apps come back in a moment.</p></>
                : <><strong>Turn on CIGAR first</strong><p>Projects and AI apps open up as soon as CIGAR is on. Use the button at the top of this page.</p></>}
            </div> : null}
            {props.access}
          </div> : null}
          {active === "data" ? <div>
            <Intro title="Privacy">CIGAR keeps its notes in memory only, so they disappear when you turn it off. Here you can see what it keeps, take back access, or delete saved notes.</Intro>
            {props.data}
          </div> : null}
          {active === "guide" ? <CigarGuide onSelect={props.onSelect} walkthroughs={walkthroughs} /> : null}
        </div>
      </div>
    </div> : null}
  </section>;
}
