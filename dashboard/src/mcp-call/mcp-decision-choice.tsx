import { useCallback, type ReactNode } from "react";
import { SectionLabel } from "../approval-center-primitives";
import { retryCannotReuseApproval, retryWindowText } from "../approval-retry-guidance";
import { requestSupportsScope } from "../approval-scopes";
import { isWatchOnlyObservation } from "../approval-center-utils";
import type { DecisionScope, GuardApprovalRequest } from "../guard-types";
import { explainMcpCall } from "./explain-mcp-call";

/**
 * True when an MCP review can use the two-choice control: the exact call is a
 * supported scope, and Always allow can be saved for it. Any other shape keeps
 * the full scope controls, so no supported choice is ever hidden.
 */
export function simpleMcpChoiceApplies(item: GuardApprovalRequest): boolean {
  return (
    explainMcpCall(item) !== null &&
    !isWatchOnlyObservation(item) &&
    item.artifact_type !== "native_bash_request" &&
    !retryCannotReuseApproval(item) &&
    item.exact_action_persistence_eligible === true &&
    requestSupportsScope(item, "allow", "artifact")
  );
}

type McpDecisionChoiceProps = {
  allowScope: DecisionScope;
  rememberExactAction: boolean;
  retryWindowMinutes: number;
  onAllowScopeChange: (scope: DecisionScope) => void;
  onRememberExactActionChange: (checked: boolean) => void;
  /** The broader and blocking choices, kept one click away. */
  moreChoices: ReactNode;
};

/** Once or always, in two plain cards. Wider scopes and blocking rules sit under "More choices". */
export function McpDecisionChoice(props: McpDecisionChoiceProps) {
  const exact = props.allowScope === "artifact";
  const { onAllowScopeChange, onRememberExactActionChange } = props;
  const chooseOnce = useCallback(() => {
    onAllowScopeChange("artifact");
    onRememberExactActionChange(false);
  }, [onAllowScopeChange, onRememberExactActionChange]);
  const chooseAlways = useCallback(() => {
    onAllowScopeChange("artifact");
    onRememberExactActionChange(true);
  }, [onAllowScopeChange, onRememberExactActionChange]);

  return (
    <div className="mt-6 space-y-3">
      <SectionLabel>How long should Guard allow it?</SectionLabel>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2" role="radiogroup" aria-label="How long to allow this call">
        <ChoiceCard
          checked={exact && !props.rememberExactAction}
          title="Just this once"
          body={`Lets the agent retry this call within ${retryWindowText(props.retryWindowMinutes)}. After that, Guard asks again.`}
          onChoose={chooseOnce}
        />
        <ChoiceCard
          checked={exact && props.rememberExactAction}
          title="Always allow this call"
          body="Lets the agent make exactly this call whenever it asks. A different call still asks you first."
          onChoose={chooseAlways}
        />
      </div>
      <details className="rounded-xl border border-slate-200/70 bg-slate-50/60 p-3">
        <summary className="cursor-pointer select-none text-sm font-medium text-brand-dark/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30">
          More choices
        </summary>
        <div className="mt-3">{props.moreChoices}</div>
      </details>
    </div>
  );
}

function ChoiceCard(props: { checked: boolean; title: string; body: string; onChoose: () => void }) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={props.checked}
      onClick={props.onChoose}
      className={`rounded-xl border px-4 py-3 text-left transition-all focus:outline-none focus:ring-2 focus:ring-brand-blue/20 ${
        props.checked ? "border-brand-blue bg-brand-blue/[0.06] ring-1 ring-brand-blue/20" : "border-slate-200/70 bg-white hover:bg-slate-50"
      }`}
    >
      <p className="text-sm font-semibold text-brand-dark">{props.title}</p>
      <p className="mt-0.5 text-xs leading-snug text-muted-foreground">{props.body}</p>
    </button>
  );
}
