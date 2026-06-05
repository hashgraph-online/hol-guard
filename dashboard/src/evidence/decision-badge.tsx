import {
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniQuestionMarkCircle,
} from "react-icons/hi2";
import { Badge } from "../approval-center-primitives";

interface DecisionBadgeProps {
  decision: string;
}

export function DecisionBadge({ decision }: DecisionBadgeProps) {
  if (decision === "allow") {
    return (
      <Badge tone="success">
        <HiMiniShieldCheck className="h-3 w-3" aria-hidden="true" />
        Allowed
      </Badge>
    );
  }
  if (decision === "block") {
    return (
      <Badge tone="attention">
        <HiMiniNoSymbol className="h-3 w-3" aria-hidden="true" />
        Stopped
      </Badge>
    );
  }
  return (
    <Badge tone="info">
      <HiMiniQuestionMarkCircle className="h-3 w-3" aria-hidden="true" />
      Reviewed
    </Badge>
  );
}
