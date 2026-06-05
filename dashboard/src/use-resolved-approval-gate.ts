import { useCallback, useEffect, useState } from "react";
import { fetchSettings } from "./guard-api";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

export function useResolvedApprovalGate(initialGate: GuardApprovalGatePublicConfig | null) {
  const [resolvedApprovalGate, setResolvedApprovalGate] =
    useState<GuardApprovalGatePublicConfig | null>(initialGate);

  useEffect(() => {
    setResolvedApprovalGate(initialGate);
  }, [initialGate]);

  const resolveApprovalGate = useCallback(async () => {
    if (resolvedApprovalGate !== null) {
      return resolvedApprovalGate;
    }
    try {
      const payload = await fetchSettings();
      const gate = payload.settings.approval_gate ?? null;
      setResolvedApprovalGate(gate);
      return gate;
    } catch {
      return null;
    }
  }, [resolvedApprovalGate]);

  return { resolvedApprovalGate, resolveApprovalGate };
}
