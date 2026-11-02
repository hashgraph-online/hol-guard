import { HiMiniArrowRight } from "react-icons/hi2";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal } from "../settings-save-proof-modal";
import { CIGAR_SETUP_STAGE_LABELS, type CigarSetupStage } from "./one-click";
import type { ContextAssistanceStatus } from "./types";
import type { useCigarOneClick } from "./use-one-click";
import { cigarWaking, type CigarTab } from "./workspace-model";

export type CigarOneClick = ReturnType<typeof useCigarOneClick>;
const ALL_STAGES: CigarSetupStage[] = ["python", "download", "check", "start"];

type ActionProps = {
  setup: CigarOneClick;
  status: ContextAssistanceStatus | null;
  disabled: boolean;
  canStop: boolean;
  stopDisabled: boolean;
  onStop: () => void;
  onOpen: (tab: CigarTab) => void;
};

function blockTabLabel(tab: CigarTab): string {
  if (tab === "versions") return "Updates";
  return "details";
}

/** The one switch. Blocked states explain themselves instead of hiding the button. */
export function CigarSetupAction({ setup, status, disabled, canStop, stopDisabled, onStop, onOpen }: ActionProps) {
  const off = canStop
    ? <button type="button" className="cigar-button" disabled={stopDisabled} onClick={onStop}>Turn off CIGAR</button>
    : null;
  if (status?.effective_enabled) return off ? <div className="cigar-setup-action">{off}</div> : null;
  if (setup.run.phase === "running") {
    return <div className="cigar-setup-action">
      <div className="cigar-setup-buttons">
        <button type="button" className="cigar-button" onClick={setup.stop}>Stop setup</button>
        {off}
      </div>
      <p className="cigar-setup-caption" role="status">{CIGAR_SETUP_STAGE_LABELS[setup.run.stage]}…</p>
    </div>;
  }
  if (cigarWaking(status)) {
    return <div className="cigar-setup-action">
      {off}
      <p className="cigar-setup-caption" role="status">CIGAR is on and waking up…</p>
    </div>;
  }
  const plan = setup.plan;
  const block = plan?.kind === "blocked" ? plan.block : null;
  const checking = plan === null && setup.loadError === null;
  const failed = setup.run.phase === "failed" ? setup.run : null;
  let note = <p className="cigar-setup-caption">{checking ? "Checking this computer…" : "About a minute · Runs on this computer · Off with one click"}</p>;
  if (block) {
    note = <div className="cigar-setup-block" role="status"><strong>{block.title}</strong><p>{block.detail}</p>
      {block.tab ? <button type="button" className="cigar-text-button" onClick={() => onOpen(block.tab!)}>Open {blockTabLabel(block.tab)}<HiMiniArrowRight aria-hidden="true" /></button> : null}
    </div>;
  } else if (failed) {
    note = <div className="cigar-setup-block" role="alert"><strong>CIGAR did not turn on</strong><p>{failed.message}</p></div>;
  } else if (setup.loadError) {
    note = <div className="cigar-setup-block" role="alert"><strong>Guard did not answer</strong><p>{setup.loadError}</p></div>;
  }
  return <div className="cigar-setup-action">
    <div className="cigar-setup-buttons">
      <button type="button" className="cigar-button cigar-button-primary cigar-button-solid" disabled={disabled || checking || block !== null || setup.run.phase === "proof"}
        onClick={setup.start}>{failed ? "Try again" : "Turn on CIGAR"}<HiMiniArrowRight aria-hidden="true" /></button>
      {off}
    </div>
    {note}
  </div>;
}

type StageState = "done" | "active" | "failed" | "next";

function stageState(index: number, at: number, phase: CigarOneClick["run"]["phase"]): StageState {
  if (phase !== "running" && phase !== "failed") return "next";
  if (index < at) return "done";
  if (index > at) return "next";
  return phase === "running" ? "active" : "failed";
}
const STAGE_SUFFIX: Record<StageState, string> = { done: " (done)", active: " (in progress)", failed: " (stopped)", next: "" };

/** Plain progress while setup runs: what is happening now, never how it works inside. */
export function CigarSetupProgress({ setup }: { setup: CigarOneClick }) {
  const run = setup.run;
  const live = run.phase === "running" || run.phase === "failed" ? run : null;
  if (!live) return null;
  let stages = live.stages;
  if (stages.length === 0) stages = setup.plan?.kind === "run" ? setup.plan.stages : ALL_STAGES;
  const at = live.stage ? stages.indexOf(live.stage) : -1;
  let body = "Getting ready…";
  if (live.stage && run.phase === "running") body = `${CIGAR_SETUP_STAGE_LABELS[live.stage]}… step ${at + 1} of ${stages.length}.`;
  else if (live.stage) body = `Setup stopped at step ${at + 1} of ${stages.length}.`;
  return <div className="cigar-setup-progress" aria-live="polite">
    <p className="cigar-setup-body">{body}</p>
    <ol className="cigar-setup-track" aria-label="Setup progress">
      {stages.map((stage, index) => {
        const state = stageState(index, at, run.phase);
        return <li key={stage} data-state={state}><span className="sr-only">{CIGAR_SETUP_STAGE_LABELS[stage]}{STAGE_SUFFIX[state]}</span></li>;
      })}
    </ol>
  </div>;
}

type ProofProps = { setup: CigarOneClick; gate: GuardApprovalGatePublicConfig | null };

export function CigarSetupProof({ setup, gate }: ProofProps) {
  const run = setup.run;
  return <SettingsSaveProofModal open={run.phase === "proof"} mode="verify-save" gate={gate}
    title="Approve turning on CIGAR"
    detail="Guard will download CIGAR, make sure it is the approved copy and start it on this computer. After that, each prompt you send in Claude Code or Codex gets the few files from that project that match it. CIGAR skips secrets, keys, generated folders and anything the project's .gitignore files leave out. Turn off Context for AI apps in Settings to stop it. One approval covers everything."
    confirmLabel="Turn on CIGAR" error={run.phase === "proof" ? run.error : null} pending={false}
    onCancel={setup.cancelProof} onConfirm={(proof) => setup.confirm({ currentPassword: proof.currentPassword, totpCode: proof.totpCode })} />;
}
