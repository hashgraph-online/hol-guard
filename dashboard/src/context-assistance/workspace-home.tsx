import { useId } from "react";
import { HiMiniArrowPath, HiMiniArrowRight, HiMiniCheckCircle } from "react-icons/hi2";
import { CigarSetupAction, CigarSetupProgress, type CigarOneClick } from "./one-click-setup";
import { contextStatusCopy } from "./status";
import type { ContextAssistanceStatus } from "./types";
import { cigarHomeCopy, type CigarTab } from "./workspace-model";

const FACTS = [
  "Finds your project from the folder your AI app runs in.",
  "Skips secrets, keys, hidden files and anything your .gitignore leaves out.",
  "Adds nothing when nothing matches.",
] as const;

type Props = {
  status: ContextAssistanceStatus | null;
  setup: CigarOneClick;
  loading: boolean;
  actionDisabled: boolean;
  canStop: boolean;
  stopDisabled: boolean;
  refreshDisabled: boolean;
  onStop: () => void;
  onRefresh: () => void;
  onOpen: (tab: CigarTab) => void;
};

/** The whole default experience: is CIGAR on, one switch, one sentence. */
export function CigarHome(props: Props) {
  const id = useId();
  const { status, setup } = props;
  const running = setup.run.phase === "running";
  const copy = cigarHomeCopy(status, props.loading, running);
  let label = props.loading ? "Checking" : "Status unavailable";
  if (status) label = contextStatusCopy(status).label;
  if (running) label = "Working";
  return <section className="cigar-home" aria-labelledby={id + "-title"}>
    <div className="cigar-home-main">
      <div className="cigar-home-top">
        <span className="cigar-status" data-ready={status?.effective_enabled === true}><span aria-hidden="true" />{label}</span>
        <button type="button" className="cigar-icon-button" aria-label="Refresh status" title="Refresh status"
          disabled={props.refreshDisabled} onClick={props.onRefresh}><HiMiniArrowPath aria-hidden="true" /></button>
      </div>
      <h2 id={id + "-title"}>{copy.headline}</h2>
      <p className="cigar-home-detail">{copy.detail}</p>
      {copy.setupHint ? <button type="button" className="cigar-text-button" onClick={() => props.onOpen("runtime")}>Open Settings<HiMiniArrowRight aria-hidden="true" /></button> : null}
      <CigarSetupAction setup={setup} status={status} disabled={props.actionDisabled} canStop={props.canStop}
        stopDisabled={props.stopDisabled} onStop={props.onStop} onOpen={props.onOpen} />
      <CigarSetupProgress setup={setup} />
    </div>
    <ul className="cigar-facts" aria-label="What CIGAR does">
      {FACTS.map((fact) => <li key={fact}><HiMiniCheckCircle aria-hidden="true" />{fact}</li>)}
    </ul>
  </section>;
}
