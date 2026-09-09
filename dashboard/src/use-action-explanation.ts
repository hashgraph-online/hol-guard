import { useEffect, useMemo, useState } from "react";
import type { GuardApprovalRequest } from "./guard-types";
import { opaqueExplanationIdentity, parseActionExplanation } from "./action-explanation-validation";

export function useActionExplanation(item: Pick<GuardApprovalRequest, "action_identity" | "action_explanation">) {
  const identity = item.action_identity ?? "";
  const explanation = useMemo(() => parseActionExplanation(item.action_explanation), [item.action_explanation]);
  const [binding, setBinding] = useState<{ identity: string; opaque: string | null } | null>(null);
  useEffect(() => {
    let cancelled = false;
    if (!identity) { setBinding(null); return; }
    void opaqueExplanationIdentity(identity)
      .then((opaque) => { if (!cancelled) setBinding({ identity, opaque }); })
      .catch(() => { if (!cancelled) setBinding({ identity, opaque: null }); });
    return () => { cancelled = true; };
  }, [identity]);
  // This is an identity hash, not a command parser or an approval credential.
  // A previous record's async result must never label the currently selected action.
  const matched = binding?.identity === identity && binding.opaque !== null
    && explanation?.action_identity === binding.opaque;
  return {
    explanation: matched ? explanation : null,
    pending: explanation !== null && identity !== "" && binding?.identity !== identity,
    invalid: item.action_explanation != null && (!explanation || (binding?.identity === identity && !matched)),
  };
}
