import {
  HiMiniArrowPath, HiMiniArrowRight, HiMiniBookOpen, HiMiniCheck, HiMiniHandRaised, HiMiniLockClosed, HiMiniXMark,
} from "react-icons/hi2";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal } from "../settings-save-proof-modal";
import { CIGAR_SETUP_STAGE_LABELS, type CigarSetupStage } from "./one-click";
import { contextStatusCopy } from "./status";
import type { ContextAssistanceStatus } from "./types";
import type { useCigarOneClick } from "./use-one-click";
import type { CigarTab } from "./workspace-model";

export type CigarOneClick = ReturnType<typeof useCigarOneClick>;
const ALL_STAGES: CigarSetupStage[] = ["python", "download", "check", "start"];
const STAGE_DETAIL: Record<CigarSetupStage, string> = {
  python: "A private copy, kept apart from any Python you already use.",
  download: "Only the version Guard approved for this computer.",
  check: "Guard compares its fingerprint before trusting it.",
  start: "CIGAR runs here. It reads no files until you pick a project.",
};

export const CIGAR_WHY = [
  { icon: HiMiniHandRaised, title: "Know why Guard paused",
    body: "When Guard stops your AI, you get a short note explaining why, with links to the exact lines it read." },
  { icon: HiMiniBookOpen, title: "Just the parts that matter",
    body: "Instead of whole files, your AI gets the few pieces that answer the question, inside a size limit you set." },
  { icon: HiMiniLockClosed, title: "Private by default",
    body: "It runs on your computer, reads only the folders you pick, and forgets everything when you turn it off." },
] as const;

export function CigarWhy() {
  return <ul className="cigar-why" aria-label="What CIGAR does for you">
    {CIGAR_WHY.map(({ icon: Icon, title, body }) => <li key={title}>
      <Icon aria-hidden="true" /><div><h3>{title}</h3><p>{body}</p></div>
    </li>)}
  </ul>;
}

type ActionProps = {
  setup: CigarOneClick;
  status: ContextAssistanceStatus | null;
  disabled: boolean;
  tone?: "hero" | "plain";
  onOpen: (tab: CigarTab) => void;
};

/** The single entry point. Blocked states explain themselves instead of hiding the button. */
export function CigarSetupAction({ setup, status, disabled, tone = "plain", onOpen }: ActionProps) {
  const primary = "cigar-button cigar-button-primary" + (tone === "plain" ? " cigar-button-solid" : "");
  if (status?.effective_enabled) {
    return <div className="cigar-setup-action">
      <button type="button" className={primary} onClick={() => onOpen("access")}>Pick a project folder<HiMiniArrowRight aria-hidden="true" /></button>
      <p className="cigar-setup-caption">CIGAR is on. It reads nothing until you choose what it may use.</p>
    </div>;
  }
  if (setup.run.phase === "running") {
    return <div className="cigar-setup-action">
      <button type="button" className="cigar-button" onClick={setup.stop}>Stop setup</button>
      <p className="cigar-setup-caption" role="status">{CIGAR_SETUP_STAGE_LABELS[setup.run.stage]}…</p>
    </div>;
  }
  const plan = setup.plan;
  const block = plan?.kind === "blocked" ? plan.block : null;
  const checking = plan === null && setup.loadError === null;
  const failed = setup.run.phase === "failed" ? setup.run : null;
  return <div className="cigar-setup-action">
    <button type="button" className={primary} disabled={disabled || checking || block !== null || setup.run.phase === "proof"}
      onClick={setup.start}>{failed ? "Try again" : "Turn on CIGAR"}<HiMiniArrowRight aria-hidden="true" /></button>
    {block ? <div className="cigar-setup-block" role="status"><strong>{block.title}</strong><p>{block.detail}</p>
      {block.tab ? <button type="button" className="cigar-text-button" onClick={() => onOpen(block.tab!)}>Open {block.tab === "versions" ? "Updates" : "details"}<HiMiniArrowRight aria-hidden="true" /></button> : null}
    </div> : failed ? <div className="cigar-setup-block" role="alert"><strong>CIGAR did not turn on</strong><p>{failed.message}</p></div>
      : setup.loadError ? <div className="cigar-setup-block" role="alert"><strong>Guard did not answer</strong><p>{setup.loadError}</p></div>
      : <p className="cigar-setup-caption">{checking ? "Checking this computer…" : "About a minute · Runs on this computer · Off with one click"}</p>}
  </div>;
}

type ProgressProps = { setup: CigarOneClick; status: ContextAssistanceStatus | null; loading: boolean };

/** One list shows the plan before the click and the live progress after it. */
export function CigarSetupProgress({ setup, status, loading }: ProgressProps) {
  const run = setup.run;
  const on = status?.effective_enabled === true;
  const stages = run.phase === "running" || run.phase === "failed" ? run.stages
    : setup.plan?.kind === "run" ? setup.plan.stages : ALL_STAGES;
  const current = run.phase === "running" ? run.stage : run.phase === "failed" ? run.stage : null;
  const at = current ? stages.indexOf(current) : -1;
  const heading = on ? "CIGAR is on" : run.phase === "running" ? "Turning on CIGAR" : run.phase === "failed" ? "Setup stopped"
    : loading ? "Checking…" : "What happens when you click";
  return <div className="cigar-runtime-card cigar-setup-progress" aria-live="polite">
    <div className="cigar-runtime-top"><h3>{heading}</h3>
      <span className="cigar-status" data-ready={on}><span aria-hidden="true" />{run.phase === "running" ? "Working" : status ? contextStatusCopy(status).label : "Checking"}</span></div>
    {on && status?.runtime ? <p>Python {status.runtime.interpreter.version.join(".")} · CIGAR {status.runtime.package_version} · on this computer</p> : null}
    {!on ? <ol className="cigar-setup-stages">
      {stages.map((stage, index) => {
        const state = run.phase === "running" ? index < at ? "done" : index === at ? "active" : "next"
          : run.phase === "failed" ? index < at ? "done" : index === at ? "failed" : "next" : "next";
        return <li key={stage} data-state={state}>
          <span className="cigar-setup-mark" aria-hidden="true">
            {state === "done" ? <HiMiniCheck /> : state === "active" ? <HiMiniArrowPath className="motion-safe:animate-spin" />
              : state === "failed" ? <HiMiniXMark /> : index + 1}
          </span>
          <div><strong>{CIGAR_SETUP_STAGE_LABELS[stage]}<span className="sr-only">{state === "done" ? " (done)" : state === "active" ? " (in progress)" : state === "failed" ? " (stopped)" : ""}</span></strong>
            <p>{STAGE_DETAIL[stage]}</p></div>
        </li>;
      })}
    </ol> : <p className="cigar-runtime-note">Next: pick a project folder, then connect an AI app if you want. Each one asks you first.</p>}
  </div>;
}

type ProofProps = { setup: CigarOneClick; gate: GuardApprovalGatePublicConfig | null };

export function CigarSetupProof({ setup, gate }: ProofProps) {
  const run = setup.run;
  return <SettingsSaveProofModal open={run.phase === "proof"} mode="verify-save" gate={gate}
    title="Approve turning on CIGAR"
    detail="Guard will get Python ready if needed, download the approved CIGAR copy, check it and start it. One approval covers every step."
    confirmLabel="Turn on CIGAR" error={run.phase === "proof" ? run.error : null} pending={false}
    onCancel={setup.cancelProof} onConfirm={(proof) => setup.confirm({ currentPassword: proof.currentPassword, totpCode: proof.totpCode })} />;
}
