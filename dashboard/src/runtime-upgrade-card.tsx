import { useState } from "react";
import {
  HiMiniArrowTopRightOnSquare,
  HiMiniCheckCircle,
  HiMiniClipboard,
  HiMiniClipboardDocumentCheck,
  HiMiniShieldExclamation,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import {
  currentRuntimeUpgradeAdvice,
  finishedSwitchVersion,
  type GuardRuntimeUpgradeAdvice,
  runtimeUpgradeTarget,
} from "./runtime-upgrade-advice";
import { switchRuntimeDefault } from "./runtime-upgrade-api";

type SwitchState =
  | { readonly kind: "idle" }
  | { readonly kind: "switching" }
  | { readonly kind: "done"; readonly version: string; readonly answered: GuardRuntimeUpgradeAdvice | undefined }
  | { readonly kind: "failed"; readonly message: string };

const RESTART_NOTE =
  "Agent sessions that are already running keep the Node.js they started with. Restart the agent so its next command uses the new version.";

/** Recommends moving off a Node.js build an advisory affects, when that is
 * why this command is paused. For nvm with a clean version installed, one
 * button makes it nvm's default; otherwise the card gives the command or the
 * download page. It never approves the paused command. */
export function RuntimeUpgradeCard(props: {
  requestId: string;
  advice: GuardRuntimeUpgradeAdvice | undefined;
  switchDefault?: typeof switchRuntimeDefault;
}) {
  const [reply, setReply] = useState<{
    readonly answered: GuardRuntimeUpgradeAdvice | undefined;
    readonly advice: GuardRuntimeUpgradeAdvice;
  } | null>(null);
  const [state, setState] = useState<SwitchState>({ kind: "idle" });
  // A queue refresh replaces the review's advice; the switch's reply stands
  // only until then.
  const advice = currentRuntimeUpgradeAdvice(props.advice, reply);
  if (!advice) return null;
  const switchDefault = props.switchDefault ?? switchRuntimeDefault;
  const target = runtimeUpgradeTarget(advice);
  const exploited = advice.known_exploited ? " It is known to be exploited." : "";

  const runSwitch = async (version: string) => {
    setState({ kind: "switching" });
    try {
      const answered = props.advice;
      const next = await switchDefault(props.requestId, version);
      if (next) setReply({ answered, advice: next });
      setState({ kind: "done", version, answered });
    } catch (error) {
      setState({ kind: "failed", message: error instanceof Error ? error.message : "Guard could not switch the Node.js version." });
    }
  };

  // A finished switch counts only while the review shows the advice it answered.
  const doneVersion = finishedSwitchVersion(props.advice, state.kind === "done" ? state : null);
  const switched = doneVersion !== null || advice.switched;
  const switchVersion = doneVersion !== null ? null : advice.switch_version;

  return (
    <section
      className="mt-5 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.04] p-4"
      aria-labelledby="runtime-upgrade-title"
      data-testid="runtime-upgrade"
    >
      <div className="flex items-start gap-3">
        <HiMiniShieldExclamation className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-wide text-brand-dark/75">Why this is paused</p>
          <h3 id="runtime-upgrade-title" className="mt-1 text-sm font-semibold text-brand-dark">
            Update Node.js to stop these reviews
          </h3>
          <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">
            This command runs Node.js {advice.current_version}, which {advice.advisory_id} ({advice.severity}) affects.
            {exploited} Guard pauses every command that starts it. {target}
          </p>
          {switched ? (
            <SwitchedNote version={doneVersion ?? advice.installed_version} />
          ) : (
            switchVersion !== null && (
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <ActionButton
                  variant="primary"
                  onClick={() => void runSwitch(switchVersion)}
                  disabled={state.kind === "switching"}
                  aria-busy={state.kind === "switching"}
                >
                  {state.kind === "switching" ? "Switching…" : `Use Node.js ${switchVersion}`}
                </ActionButton>
                <span className="text-xs text-brand-dark/70">Sets nvm&apos;s default version. New terminals start it.</span>
              </div>
            )
          )}
          {state.kind === "failed" && (
            <p className="mt-2 text-sm text-red-700" role="alert">
              {state.message}
            </p>
          )}
          {!switched && advice.command !== null && <CopyCommand command={advice.command} />}
          {!switched && <p className="mt-2 text-xs text-brand-dark/70">After you update, {RESTART_NOTE.charAt(0).toLowerCase()}{RESTART_NOTE.slice(1)}</p>}
          {!switched && (
            <a
              href={advice.download_url}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-brand-blue underline-offset-2 hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            >
              Download Node.js
              <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5" aria-hidden="true" />
            </a>
          )}
        </div>
      </div>
    </section>
  );
}

function SwitchedNote(props: { version: string | null }) {
  return (
    <div className="mt-3 flex items-start gap-2 text-sm text-brand-dark" role="status">
      <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" aria-hidden="true" />
      <p>
        {props.version !== null ? `nvm now defaults to Node.js ${props.version}. ` : "nvm now defaults to a clean version. "}
        {RESTART_NOTE}
      </p>
    </div>
  );
}

function CopyCommand(props: { command: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.command);
      setState("copied");
    } catch {
      setState("failed");
    }
  };
  return (
    <div className="mt-3">
      <p className="text-xs text-brand-dark/70">Or run this in a terminal:</p>
      <div className="mt-1 flex flex-col gap-2 sm:flex-row sm:items-center">
        <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded-lg border border-slate-200 bg-white px-3 py-2.5 font-mono text-xs text-brand-dark">
          {props.command}
        </code>
        <button
          type="button"
          onClick={() => void copy()}
          aria-label={state === "copied" ? "Command copied" : "Copy the update command"}
          className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-blue hover:border-brand-blue/40 focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        >
          {state === "copied" ? (
            <HiMiniClipboardDocumentCheck className="size-4" aria-hidden="true" />
          ) : (
            <HiMiniClipboard className="size-4" aria-hidden="true" />
          )}
          {state === "copied" ? "Copied" : "Copy"}
        </button>
      </div>
      {state === "failed" && (
        <p className="mt-1 text-xs text-brand-dark/70" role="status">
          Copy is unavailable here. Select the command and copy it.
        </p>
      )}
    </div>
  );
}
