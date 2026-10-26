import {
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniQuestionMarkCircle,
  HiMiniExclamationTriangle,
} from "react-icons/hi2";
import { Badge } from "../approval-center-primitives";
import { guardActionPresentation } from "../guard-action";
import { APPROVAL_LEFT_STOPPED_LABEL, approvalLeftActionStopped } from "./approval-outcome";

interface DecisionBadgeProps {
  decision: string;
  /** The receipt's user_override; an approval that left the action stopped is labelled as such. */
  userOverride?: string | null;
}

export function DecisionBadge({ decision, userOverride = null }: DecisionBadgeProps) {
  if (approvalLeftActionStopped({ user_override: userOverride })) {
    return (
      <Badge tone="attention">
        <HiMiniNoSymbol className="h-3 w-3" aria-hidden="true" />
        {APPROVAL_LEFT_STOPPED_LABEL}
      </Badge>
    );
  }
  const presentation = guardActionPresentation(decision);
  if (presentation.action === "allow") {
    return (
      <Badge tone={presentation.tone}>
        <HiMiniShieldCheck className="h-3 w-3" aria-hidden="true" />
        {presentation.label}
      </Badge>
    );
  }
  if (presentation.action === "warn") {
    return (
      <Badge tone={presentation.tone}>
        <HiMiniExclamationTriangle className="h-3 w-3" aria-hidden="true" />
        {presentation.label}
      </Badge>
    );
  }
  if (presentation.action === "block") {
    return (
      <Badge tone={presentation.tone}>
        <HiMiniNoSymbol className="h-3 w-3" aria-hidden="true" />
        {presentation.label}
      </Badge>
    );
  }
  return (
    <Badge tone={presentation.tone}>
      <HiMiniQuestionMarkCircle className="h-3 w-3" aria-hidden="true" />
      {presentation.label}
    </Badge>
  );
}
