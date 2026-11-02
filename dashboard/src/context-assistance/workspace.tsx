import { useEffect, useRef, useState, type ReactNode } from "react";
import { HiMiniCircleStack, HiMiniShieldCheck } from "react-icons/hi2";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import type { CigarOneClick } from "./one-click-setup";
import { CigarAdvanced } from "./workspace-advanced";
import { CigarHome } from "./workspace-home";
import { cigarTabFromSearch, type CigarAdvancedTab, type CigarTab } from "./workspace-model";
import { cigarTutorial, type CigarTutorialId } from "./tutorial-content";
import { useCigarTutorial } from "./tutorial-progress";
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
  const lastAdvanced = useRef<CigarAdvancedTab>(tab === "overview" ? "runtime" : tab);
  const panel = useRef<HTMLDivElement>(null);
  const walkthroughAnchor = useRef<HTMLDivElement>(null);
  const lesson = useCigarTutorial();
  const status = props.status;
  const canStop = props.stopAvailable ?? Boolean(status?.requested_enabled || status?.effective_enabled || status?.job);

  useEffect(() => {
    const sync = () => {
      const next = cigarTabFromSearch(window.location.search);
      if (next !== "overview") lastAdvanced.current = next;
      setTab(next);
    };
    return subscribeDashboardLocation(sync);
  }, []);

  function select(next: CigarTab, focusPanel = true) {
    if (next !== "overview") lastAdvanced.current = next;
    setTab(next);
    const url = new URL(window.location.href);
    url.searchParams.set("section", next);
    window.history.replaceState({}, "", url.pathname + url.search + url.hash);
    if (focusPanel && next !== "overview") window.requestAnimationFrame(() => panel.current?.focus());
  }

  function toggleAdvanced() {
    if (tab === "overview") {
      select(lastAdvanced.current, false);
      return;
    }
    if (lesson.active) lesson.exit();
    select("overview", false);
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
      <h1><HiMiniCircleStack aria-hidden="true" />CIGAR</h1>
      <p>Gives your AI app the project files that match what you ask.</p>
    </header>
    <CigarHome status={status} setup={props.setup} loading={props.loading}
      actionDisabled={props.disabled || props.busy || props.loading} canStop={canStop} stopDisabled={props.disabled || props.busy}
      refreshDisabled={props.disabled || props.busy || props.loading} onStop={props.onStop} onRefresh={props.onRefresh} onOpen={select} />
    {props.error ? <div className="cigar-note" role="alert"><strong>CIGAR needs attention</strong><p>{props.error}</p></div> : null}
    <CigarAdvanced tab={tab} status={status} dirty={props.dirty} lesson={lesson} versions={props.versions} controls={props.controls}
      access={props.access} data={props.data} panelRef={panel} walkthroughRef={walkthroughAnchor} onToggle={toggleAdvanced}
      onSelect={select} onBegin={beginTutorial} onMove={moveTutorial}
      onExitLesson={() => { lesson.exit(); select("guide"); }} />
    <footer className="cigar-footer">
      <HiMiniShieldCheck aria-hidden="true" />
      <span>Guard still decides what your AI may do. CIGAR only adds context. CIGAR is in beta:{" "}
        <a href="https://github.com/hashgraph-online/hol-cigar/issues" target="_blank" rel="noopener noreferrer">share feedback</a>.</span>
      {props.dirty ? <strong>Unsaved changes</strong> : null}
    </footer>
  </div>;
}
