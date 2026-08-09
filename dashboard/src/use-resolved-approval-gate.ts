import { useCallback, useEffect, useState } from "react";
import { fetchSettings } from "./guard-api";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

type ApprovalGateFetcher = () => Promise<{
  settings: { approval_gate?: GuardApprovalGatePublicConfig | null };
}>;

export async function fetchResolvedApprovalGate(
  fetcher: ApprovalGateFetcher = fetchSettings,
): Promise<GuardApprovalGatePublicConfig | null> {
  const payload = await fetcher();
  return payload.settings.approval_gate ?? null;
}

export function useResolvedApprovalGate(initialGate: GuardApprovalGatePublicConfig | null) {
  const [resolvedApprovalGate, setResolvedApprovalGate] =
    useState<GuardApprovalGatePublicConfig | null>(initialGate);

  useEffect(() => {
    setResolvedApprovalGate(initialGate);
  }, [initialGate]);

  const resolveApprovalGate = useCallback(async (options?: { failClosed?: boolean }) => {
    if (resolvedApprovalGate !== null) {
      return resolvedApprovalGate;
    }
    try {
      const gate = await fetchResolvedApprovalGate();
      setResolvedApprovalGate(gate);
      return gate;
    } catch (error) {
      if (options?.failClosed) {
        throw error;
      }
      return null;
    }
  }, [resolvedApprovalGate]);

  return { resolvedApprovalGate, resolveApprovalGate };
}
