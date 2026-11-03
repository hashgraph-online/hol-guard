import { useId, type KeyboardEvent, type ReactNode, type RefObject } from "react";
import { CigarGuide } from "./workspace-guide";
import { CigarStory } from "./workspace-story";
import { CIGAR_TABS, cigarWaking, type CigarTab } from "./workspace-model";
import type { ContextAssistanceStatus } from "./types";
import type { CigarTutorialId } from "./tutorial-content";
import type { useCigarTutorial } from "./tutorial-progress";
import { CigarTutorials, CigarWalkthrough } from "./tutorials";

export type CigarSectionsProps = {
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
  onSelect: (tab: CigarTab, focusPanel?: boolean) => void;
  onBegin: (id: CigarTutorialId, resume?: boolean) => void;
  onMove: (step: number) => void;
  onExitLesson: () => void;
};

function Intro({ title, children }: { title: string; children: ReactNode }) {
  return <div className="cigar-section-intro"><h2>{title}</h2><p>{children}</p></div>;
}

/** Home explains CIGAR; every other tab is one place to change something. */
export function CigarSections(props: CigarSectionsProps) {
  const { tab, status, lesson } = props;
  const id = useId();

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

  const walkthroughs = <CigarTutorials progress={lesson.progress} onBegin={props.onBegin} />;
  return <section className="cigar-sections" aria-label="CIGAR sections">
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
        {tab === "overview" ? <CigarStory onSelect={props.onSelect} /> : null}
        <div hidden={tab !== "runtime"}>
          <Intro title="Settings">The recommended settings work for most people. Change them only if you want to.</Intro>
          {props.controls}
        </div>
        {tab === "versions" ? props.versions : null}
        {tab === "access" ? <div>
          <Intro title="Projects">CIGAR already finds the project each AI app is open in. Add a project here only to choose exactly which files it reads. Your choice counts for every app.</Intro>
          {!status?.effective_enabled ? <div className="cigar-note">
            {cigarWaking(status)
              ? <><strong>Waking up CIGAR</strong><p>Your projects come back in a moment.</p></>
              : <><strong>Turn on CIGAR first</strong><p>Projects open up as soon as CIGAR is on. Use the button at the top of this page.</p></>}
          </div> : null}
          {/* While CIGAR is off the one note above says what to do; the empty panels would only repeat it. */}
          {status?.effective_enabled || cigarWaking(status) ? props.access : null}
        </div> : null}
        {tab === "data" ? <div>
          <Intro title="Privacy">By default, CIGAR keeps its notes in memory only, so they disappear when you turn it off. Here you can see what it keeps, take back access, or delete saved notes.</Intro>
          {props.data}
        </div> : null}
        {tab === "guide" ? <CigarGuide onSelect={props.onSelect} walkthroughs={walkthroughs} /> : null}
      </div>
    </div>
  </section>;
}
