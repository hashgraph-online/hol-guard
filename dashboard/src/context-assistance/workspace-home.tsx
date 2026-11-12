import { useId, type CSSProperties } from "react";
import { HiMiniArrowPath, HiMiniDocumentText, HiMiniLockClosed, HiMiniSparkles } from "react-icons/hi2";
import { CigarAllowFilesButton, type CigarAllowFiles } from "./allow-files";
import { CigarSetupAction, CigarSetupProgress, type CigarOneClick } from "./one-click-setup";
import { contextStatusCopy } from "./status";
import type { ContextAssistanceStatus } from "./types";
import { cigarHomeCopy, type CigarTab } from "./workspace-model";

type Props = {
  status: ContextAssistanceStatus | null;
  setup: CigarOneClick;
  allowFiles: CigarAllowFiles;
  loading: boolean;
  actionDisabled: boolean;
  canStop: boolean;
  stopDisabled: boolean;
  refreshDisabled: boolean;
  onStop: () => void;
  onRefresh: () => void;
  onOpen: (tab: CigarTab) => void;
};

/** The top of every CIGAR section: what it does, whether it is on, and the one button that matters. */
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
      <h2 id={id + "-title"}>Give your AI the right pages, not the whole book.</h2>
      <p className="cigar-home-detail"><strong>{copy.headline}.</strong> {copy.detail}</p>
      {copy.setupHint ? <CigarAllowFilesButton allow={props.allowFiles} className="cigar-button cigar-button-solid cigar-allow-hero"
        caption="Secrets, keys, hidden files and anything your .gitignore leaves out stay skipped." /> : null}
      <CigarSetupAction setup={setup} status={status} disabled={props.actionDisabled} canStop={props.canStop}
        stopDisabled={props.stopDisabled} onStop={props.onStop} onOpen={props.onOpen} />
      <CigarSetupProgress setup={setup} />
    </div>
    <CigarPromptDemo />
  </section>;
}

const DEMO_FILES = [
  { path: "src/components/Header.tsx", match: "lines 12–40" },
  { path: "src/api/orders.ts" },
  { path: "src/styles/header.css", match: "lines 1–18" },
  { path: "README.md" },
  { path: ".env", locked: true },
  { path: "tests/checkout.test.ts" },
] as const;

/** A worked example of one prompt: two files match, a secret file is never read. */
export function CigarPromptDemo() {
  return <figure className="cigar-demo" aria-label="Example: for the prompt Make the header blue, CIGAR picks the header component and its styles, and never reads the .env file.">
    <div className="cigar-demo-prompt" aria-hidden="true">
      <span className="cigar-demo-you">You</span>
      <span className="cigar-demo-ask">Make the header blue</span>
    </div>
    <ul className="cigar-demo-files" aria-hidden="true">
      {DEMO_FILES.map((file, index) => <li key={file.path} style={{ "--cigar-demo-row": index } as CSSProperties}
        data-match={"match" in file ? "true" : undefined} data-locked={"locked" in file ? "true" : undefined}>
        {"locked" in file ? <HiMiniLockClosed aria-hidden="true" /> : <HiMiniDocumentText aria-hidden="true" />}
        <code>{file.path}</code>
        {"match" in file ? <span className="cigar-demo-tag">{file.match}</span> : null}
        {"locked" in file ? <span className="cigar-demo-tag">never read</span> : null}
      </li>)}
    </ul>
    <figcaption className="cigar-demo-result">
      <HiMiniSparkles aria-hidden="true" />
      <span>Your AI gets those two pieces, each with the file and lines it came from.</span>
    </figcaption>
  </figure>;
}
