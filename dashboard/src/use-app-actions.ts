import { useCallback } from "react";
import {
  clearPolicy,
  fetchInboxState,
  fetchReceipts,
  fetchPolicies,
  fetchInventory,
  ensureGuardDashboardSession,
  resolveRequestWithQueueResult,
  GuardRequestResolutionError,
  retryResume,
  bulkAllowReadOnce,
  repairApprovalCenter,
} from "./guard-api";
import type { BulkGateCredentials } from "./approval-center-layout";
import type { GuardPolicyDecision, DecisionScope } from "./guard-types";
import { buildClearPayload } from "./clear-policy-payload";
import { harnessDisplayName, normalizeHarnessSlug } from "./approval-center-utils";
import { selectNextAfterResolution } from "./queue-state";
import { runAutomaticProtectionRepair } from "./protection-repair-flow";
import { navigate, PROTECT_ROUTE, TODAY_EVIDENCE_ROUTE } from "./app-routing";
import { loadDetail, refreshStaleScopeContractSelection } from "./app-detail-state";
import type { useAppData } from "./use-app-data";

export function useAppActions(data: ReturnType<typeof useAppData>) {
  const {
    requests,
    setRequests,
    setDetail,
    setReceipts,
    setRuntime,
    setPolicies,
    setInventory,
    setResolutionMessage,
    setCodexResume,
    resolvedRequestId,
    setResolvedRequestId,
    setHelpOpen,
    clearConfirm,
    setClearConfirm,
    resolutionInFlight,
    bulkApproveInFlight,
    activeRequestId,
  } = data;
  const handleOpenInbox = useCallback(() => navigate("/inbox"), []);
  const handleOpenFleet = useCallback(() => navigate(PROTECT_ROUTE), []);
  const handleOpenEvidence = useCallback(() => navigate("/evidence"), []);
  const handleOpenTodayEvidence = useCallback(() => navigate(TODAY_EVIDENCE_ROUTE), []);
  const handleOpenInsights = useCallback(() => navigate("/evidence?view=insights"), [navigate]);
  const handleOpenCommands = useCallback(() => navigate("/evidence?view=commands"), [navigate]);
  const handleOpenSettings = useCallback(() => navigate("/settings"), []);
  const handleOpenSupplyChain = useCallback(() => navigate("/supply-chain"), []);
  const handleOpenPolicy = useCallback(() => navigate("/policy"), []);
  const handleOpenHelp = useCallback(() => setHelpOpen(true), []);
  const handleCloseHelp = useCallback(() => setHelpOpen(false), []);
  const handleGoHome = useCallback(() => navigate("/"), []);
  const handleOpenRequest = useCallback((nextRequestId: string) => {
    navigate(`/requests/${nextRequestId}`);
  }, []);
  const handleOpenAppDetail = useCallback((harness: string) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}`);
    }
  }, []);

  const refreshStateAfterAction = useCallback(async () => {
    const [inboxResult, receiptsResult, policiesResult, inventoryResult] = await Promise.allSettled([
      fetchInboxState(),
      fetchReceipts(),
      fetchPolicies(),
      fetchInventory(),
    ]);
    if (inboxResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: inboxResult.value.snapshot });
      setRequests({ kind: "ready", items: inboxResult.value.items });
    } else {
      const message =
        inboxResult.reason instanceof Error ? inboxResult.reason.message : "Unable to load the local approval queue.";
      setRuntime({ kind: "error", message });
      setRequests({ kind: "error", message });
    }
    if (receiptsResult.status === "fulfilled") {
      setReceipts({ kind: "ready", items: receiptsResult.value });
    } else {
      setReceipts({
        kind: "error",
        message: receiptsResult.reason instanceof Error ? receiptsResult.reason.message : "Unable to load local approval history.",
      });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load remembered decisions.",
      });
    }
    if (inventoryResult.status === "fulfilled") {
      setInventory({ kind: "ready", items: inventoryResult.value });
    } else {
      setInventory({
        kind: "error",
        message: inventoryResult.reason instanceof Error ? inventoryResult.reason.message : "Unable to load watched app inventory.",
      });
    }
    return inboxResult.status === "fulfilled" ? inboxResult.value.snapshot : null;
  }, [setRuntime, setRequests, setReceipts, setPolicies, setInventory]);

  const refreshStateWithoutResult = useCallback(async () => {
    await refreshStateAfterAction();
  }, [refreshStateAfterAction]);

  const handleReconnectSession = useCallback(async () => {
    setRuntime({ kind: "loading" });
    setRequests({ kind: "loading" });
    const reminted = await ensureGuardDashboardSession();
    if (!reminted) {
      const message = "unauthorized (401)";
      setRuntime({ kind: "error", message });
      setRequests({ kind: "error", message });
      return;
    }
    await refreshStateAfterAction();
  }, [refreshStateAfterAction]);

  const handleClearPolicies = useCallback(async (scope: { harness?: string; all?: boolean }) => {
    setClearConfirm(scope);
  }, []);

  const handleConfirmClear = useCallback(async (credentials?: { approval_password?: string; approval_totp_code?: string }) => {
    if (clearConfirm === null) return;
    await clearPolicy({ ...clearConfirm, ...credentials });
    setClearConfirm(null);
    const [inboxResult, policiesResult] = await Promise.allSettled([fetchInboxState(), fetchPolicies()]);
    if (inboxResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: inboxResult.value.snapshot });
      setRequests({ kind: "ready", items: inboxResult.value.items });
    } else {
      const message =
        inboxResult.reason instanceof Error ? inboxResult.reason.message : "Unable to load the local approval queue.";
      setRuntime({ kind: "error", message });
      setRequests({ kind: "error", message });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals.",
      });
    }
  }, [clearConfirm, setRuntime, setRequests, setPolicies]);

  const handleCancelClear = useCallback(() => {
    setClearConfirm(null);
  }, []);

  const handleClearAppPolicies = useCallback(async (harness: string) => {
    await clearPolicy({ harness });
    const [inboxResult, policiesResult] = await Promise.allSettled([fetchInboxState(), fetchPolicies()]);
    if (inboxResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: inboxResult.value.snapshot });
      setRequests({ kind: "ready", items: inboxResult.value.items });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals.",
      });
    }
  }, [setRuntime, setRequests, setPolicies]);

  const handleRefreshPolicies = useCallback(async () => {
    try {
      const items = await fetchPolicies();
      setPolicies({ kind: "ready", items });
    } catch {
      // Keep the current policy list when refresh fails.
    }
  }, []);

  const handleClearPolicy = useCallback(async (policy: GuardPolicyDecision) => {
    await clearPolicy(buildClearPayload(policy));
    const [inboxResult, policiesResult] = await Promise.allSettled([fetchInboxState(), fetchPolicies()]);
    if (inboxResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: inboxResult.value.snapshot });
      setRequests({ kind: "ready", items: inboxResult.value.items });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals.",
      });
    }
  }, [setRuntime, setRequests, setPolicies]);

  const handleClearEvidence = useCallback(() => {
    setReceipts({ kind: "ready", items: [] });
  }, [setReceipts]);

  const handleResolve = useCallback(async (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: DecisionScope;
    workspace?: string;
    reason: string;
    approval_password?: string;
    approval_totp_code?: string;
    approval_gate_use_cooldown?: boolean;
    scope_contract_version?: string;
    scope_contract_digest?: string;
  }) => {
    resolutionInFlight.current = true;
    const queuedItemsSnapshot = requests.kind === "ready" ? requests.items : [];
    try {
      const result = await resolveRequestWithQueueResult(payload).catch(async (error: unknown) => {
        if (
          error instanceof GuardRequestResolutionError &&
          error.status === 409 &&
          error.payload?.["error"] === "stale_scope_contract"
        ) {
          await refreshStaleScopeContractSelection({
            requestId: activeRequestId,
            refreshQueue: async () => {
              await refreshStateAfterAction();
            },
            loadSelectedDetail: loadDetail,
            applySelectedDetail: setDetail,
          });
          throw new Error(
            "This request changed while you were reviewing it. Guard refreshed the current action and scopes; review them, then retry.",
          );
        }
        throw error;
      });
      const nextId = selectNextAfterResolution(result, queuedItemsSnapshot);
      const resume = result.codexResume ?? null;
      setCodexResume(resume);
      setResolvedRequestId(resume !== null ? payload.requestId : null);
      if (nextId !== null) {
        setResolutionMessage(null);
        navigate(`/requests/${nextId}`);
      } else {
        setResolutionMessage(resume !== null ? null : (result.resolution_summary || "Decision saved. Return to your chat and retry the command."));
        navigate("/inbox");
      }
      await refreshStateAfterAction();
    } finally {
      resolutionInFlight.current = false;
    }
  }, [activeRequestId, requests, refreshStateAfterAction, setResolutionMessage]);

  const handleRetryResume = useCallback(async () => {
    if (resolvedRequestId === null) return;
    const updated = await retryResume(resolvedRequestId);
    setCodexResume(updated);
  }, [resolvedRequestId]);

  const handleBulkApprove = useCallback(async (ids: string[], gateCredentials?: BulkGateCredentials) => {
    if (bulkApproveInFlight.current) {
      return;
    }
    if (!gateCredentials?.approval_password?.trim() && !gateCredentials?.approval_totp_code?.trim()) {
      throw new Error("Bulk approval requires approval proof.");
    }
    bulkApproveInFlight.current = true;
    try {
      const result = await bulkAllowReadOnce({
        requestIds: ids,
        approval_password: gateCredentials.approval_password,
        approval_totp_code: gateCredentials.approval_totp_code,
        approval_gate_use_cooldown: gateCredentials.approval_gate_use_cooldown,
      });
      await refreshStateAfterAction();
      if (result.failed.length > 0) {
        const succeeded = result.resolved_count;
        const failed = result.failed.length;
        throw new Error(
          failed === ids.length
            ? "Bulk approval failed. Retry the selected items manually."
            : `${succeeded} approved, ${failed} failed. Retry the failed items manually.`
        );
      }
      const label = `${result.resolved_count} item${result.resolved_count !== 1 ? "s" : ""} approved.`;
      setResolutionMessage(label);
    } finally {
      bulkApproveInFlight.current = false;
    }
  }, [refreshStateAfterAction, setResolutionMessage]);

  const handleRetry = useCallback(() => {
    setRuntime({ kind: "loading" });
    setRequests({ kind: "loading" });
    fetchInboxState()
      .then(({ snapshot, items }) => {
        setRuntime({ kind: "ready", snapshot });
        setRequests({ kind: "ready", items });
      })
      .catch((error: unknown) => {
        const message =
          error instanceof Error ? error.message : "Unable to load the local approval queue.";
        setRuntime({ kind: "error", message });
        setRequests({ kind: "error", message });
      });
  }, []);

  const handleRepair = useCallback(async () => {
    await repairApprovalCenter();
    await new Promise<void>((resolve) => setTimeout(resolve, 1200));
    fetchInboxState()
      .then(({ snapshot, items }) => {
        setRuntime({ kind: "ready", snapshot });
        setRequests({ kind: "ready", items });
      })
      .catch((error: unknown) => {
        const message =
          error instanceof Error ? error.message : "Unable to reconnect to Guard daemon.";
        setRuntime({ kind: "error", message });
        setRequests({ kind: "error", message });
      });
  }, []);

  const handleConnectHarness = useCallback((harness: string) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}?tab=settings`);
    }
  }, []);

  const handleTestHarness = useCallback((harness: string) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}?tab=settings`);
    }
  }, []);

  const handleRepairHarness = useCallback((harness: string) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}?tab=settings`);
    }
  }, []);

  const handleRepairProtection = useCallback(async (harnesses: string[]) => {
    return runAutomaticProtectionRepair({
      harnesses,
      displayName: harnessDisplayName,
      refreshStateAfterAction,
    });
  }, [refreshStateAfterAction]);

  return {
    handleOpenInbox,
    handleOpenFleet,
    handleOpenEvidence,
    handleOpenTodayEvidence,
    handleOpenInsights,
    handleOpenCommands,
    handleOpenSettings,
    handleOpenSupplyChain,
    handleOpenPolicy,
    handleOpenHelp,
    handleCloseHelp,
    handleGoHome,
    handleOpenRequest,
    handleOpenAppDetail,
    refreshStateAfterAction,
    refreshStateWithoutResult,
    handleReconnectSession,
    handleClearPolicies,
    handleConfirmClear,
    handleCancelClear,
    handleClearAppPolicies,
    handleRefreshPolicies,
    handleClearPolicy,
    handleClearEvidence,
    handleResolve,
    handleRetryResume,
    handleBulkApprove,
    handleRetry,
    handleRepair,
    handleConnectHarness,
    handleTestHarness,
    handleRepairHarness,
    handleRepairProtection,
  };
}
