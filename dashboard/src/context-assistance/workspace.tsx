import { useEffect, useRef, useState, type ReactNode } from "react";
import { HiMiniCircleStack, HiMiniChatBubbleLeftRight } from "react-icons/hi2";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import type { CigarOneClick } from "./one-click-setup";
import type { CigarAllowFiles } from "./allow-files";
import { CigarSections } from "./workspace-sections";
import { CigarHome } from "./workspace-home";
import { cigarTabFromSearch, type CigarTab } from "./workspace-model";
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
  allowFiles: CigarAllowFiles;
  versions?: ReactNode;
  controls: ReactNode;
  access: ReactNode;
  data: ReactNode;
  onRefresh: () => void;
  onStop: () => void;
};

export function CigarWorkspace(props: CigarWorkspaceProps) {
  const [tab, setTab] = useState<CigarTab>(() => cigarTabFromSearch(typeof window === "undefined" ? "" : window.location.search));
  const panel = useRef<HTMLDivElement>(null);
  const walkthroughAnchor = useRef<HTMLDivElement>(null);
  const lesson = useCigarTutorial();
  const status = props.status;
  const canStop = props.stopAvailable ?? Boolean(status?.requested_enabled || status?.effective_enabled || status?.job);

  useEffect(() => {
    return subscribeDashboardLocation(() => setTab(cigarTabFromSearch(window.location.search)));
  }, []);

  function select(next: CigarTab, focusPanel = true) {
    setTab(next);
    const url = new URL(window.location.href);
    url.searchParams.set("section", next);
    window.history.replaceState({}, "", url.pathname + url.search + url.hash);
    if (focusPanel) window.requestAnimationFrame(() => panel.current?.focus());
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
      <p>Hands your AI app the few project files that match what you ask.</p>
    </header>
    <CigarHome status={status} setup={props.setup} allowFiles={props.allowFiles} loading={props.loading}
      actionDisabled={props.disabled || props.busy || props.loading} canStop={canStop} stopDisabled={props.disabled || props.busy}
      refreshDisabled={props.disabled || props.busy || props.loading} onStop={props.onStop} onRefresh={props.onRefresh} onOpen={select} />
    {props.error ? <div className="cigar-note" role="alert"><strong>CIGAR needs attention</strong><p>{props.error}</p></div> : null}
    <CigarSections tab={tab} status={status} dirty={props.dirty} lesson={lesson} versions={props.versions} controls={props.controls}
      access={props.access} data={props.data} panelRef={panel} walkthroughRef={walkthroughAnchor}
      onSelect={select} onBegin={beginTutorial} onMove={moveTutorial}
      onExitLesson={() => { lesson.exit(); select("guide"); }} />
    <footer className="cigar-footer">
      <HiMiniChatBubbleLeftRight aria-hidden="true" />
      <span>CIGAR is in beta. Something odd or something you love?{" "}
        <a href="https://github.com/hashgraph-online/hol-cigar/issues" target="_blank" rel="noopener noreferrer">Tell us</a>.</span>
      {props.dirty ? <strong>Unsaved changes</strong> : null}
    </footer>
  </div>;
}
