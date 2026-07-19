import {
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniQuestionMarkCircle,
  HiMiniExclamationTriangle,
} from "react-icons/hi2";
import { Badge } from "../approval-center-primitives";
import { guardActionPresentation } from "../guard-action";

interface DecisionBadgeProps {
  decision: string;
}

export function DecisionBadge({ decision }: DecisionBadgeProps) {
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
