import { McpDecisionChoice } from "./mcp-call/mcp-decision-choice";
import { ReviewScopeControls, type ReviewScopeControlsProps } from "./review-scope-controls";

/**
 * The scope controls for a review. A simple MCP review gets the two-card
 * choice, with the wider scopes and the block rules under "More choices".
 * Every other review keeps the full controls.
 */
export function ReviewDecisionControls({ simpleMcp, ...props }: ReviewScopeControlsProps & { simpleMcp: boolean }) {
  if (!simpleMcp) return <ReviewScopeControls {...props} />;
  const workspaceOnly = props.commonScopeOptions.filter((choice) => choice.value !== "artifact");
  return (
    <McpDecisionChoice
      allowScope={props.allowScope}
      rememberExactAction={props.rememberExactAction}
      retryWindowMinutes={props.retryWindowMinutes ?? 15}
      onAllowScopeChange={props.onAllowScopeChange}
      onRememberExactActionChange={props.onRememberExactActionChange}
      moreChoices={
        <ReviewScopeControls
          {...props}
          bare
          commonScopeOptions={workspaceOnly}
          exactActionPersistenceEligible={false}
        />
      }
    />
  );
}
