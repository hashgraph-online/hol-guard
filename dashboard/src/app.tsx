import { useEffect, useState, useCallback } from "react";

import {
  clearPolicy,
  fetchDiff,
  fetchInventory,
  fetchLatestReceipt,
  fetchPolicies,
  fetchPolicy,
  fetchReceipts,
  fetchRequest,
  fetchRuntimeSnapshot,
  guardAwareHref,
  resolveRequestWithQueueResult,
} from "./guard-api";
import { ApprovalCenterLayout } from "./approval-center-layout";
import { FleetWorkspace } from "./fleet-workspace";
import { SettingsWorkspace } from "./settings-workspace";
import { HomeWorkspace } from "./home-dashboard";
import { selectNextAfterResolution } from "./queue-state";
import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  GuardInventoryItem,
  DecisionScope,
} from "./guard-types";

type RequestState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardApprovalRequest[] };

type DetailState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | {
      kind: "ready";
      item: GuardApprovalRequest;
      diff: GuardArtifactDiff | null;
      receipt: GuardReceipt | null;
      policy: GuardPolicyDecision[];
    };

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

type RuntimeState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; snapshot: GuardRuntimeSnapshot };

type PolicyState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardPolicyDecision[] };
type InventoryState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardInventoryItem[] };

function usePathname(): string {
  const [pathname, setPathname] = useState(window.location.pathname);

  useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  return pathname;
}

function navigate(pathname: string): void {
  window.history.pushState({}, "", guardAwareHref(pathname));
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function parseRequestId(pathname: string): string | null {
  if (pathname.startsWith("/requests/")) {
    return pathname.slice("/requests/".length);
  }
  if (pathname.startsWith("/approvals/")) {
    return pathname.slice("/approvals/".length);
  }
  return null;
}

function resolveView(pathname: string): "home" | "inbox" | "fleet" | "evidence" | "settings" {
  if (pathname === "/settings") {
    return "settings";
  }
  if (pathname === "/fleet") {
    return "fleet";
  }
  if (pathname === "/evidence") {
    return "evidence";
  }
  if (
    pathname === "/inbox" ||
    pathname === "/requests" ||
    pathname === "/approvals" ||
    pathname.startsWith("/requests/") ||
    pathname.startsWith("/approvals/")
  ) {
    return "inbox";
  }
  return "home";
}

async function loadDetail(requestId: string): Promise<Exclude<DetailState, { kind: "idle" | "loading" }>> {
  try {
    const item = await fetchRequest(requestId);
    const [diff, receipt, policy] = await Promise.all([
      fetchDiff(item.artifact_id, item.harness),
      fetchLatestReceipt(item.artifact_id, item.harness),
      fetchPolicy(item.harness)
    ]);
    return { kind: "ready", item, diff, receipt, policy };
  } catch (error) {
    return {
      kind: "error",
      message: error instanceof Error ? error.message : "Unable to load the approval request."
    };
  }
}

export function App() {
  const pathname = usePathname();
  const view = resolveView(pathname);
  const requestId = parseRequestId(pathname);
  const [requests, setRequests] = useState<RequestState>({ kind: "loading" });
  const [detail, setDetail] = useState<DetailState>({ kind: "idle" });
  const [receipts, setReceipts] = useState<ReceiptsState>({ kind: "loading" });
  const [runtime, setRuntime] = useState<RuntimeState>({ kind: "loading" });
  const [policies, setPolicies] = useState<PolicyState>({ kind: "loading" });
  const [inventory, setInventory] = useState<InventoryState>({ kind: "idle" });
  const [resolutionMessage, setResolutionMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let pollId: number | undefined;
    const loadRuntimeSnapshot = () => {
      fetchRuntimeSnapshot()
        .then((snapshot) => {
          if (!cancelled) {
            setRuntime({ kind: "ready", snapshot });
            setRequests({ kind: "ready", items: snapshot.items });
          }
        })
        .catch((error: unknown) => {
          if (!cancelled) {
            const message =
              error instanceof Error ? error.message : "Unable to load the local approval queue.";
            setRuntime({ kind: "error", message });
            setRequests({ kind: "error", message });
          }
        });
    };
    loadRuntimeSnapshot();
    pollId = window.setInterval(loadRuntimeSnapshot, 4000);
    return () => {
      cancelled = true;
      if (pollId !== undefined) {
        window.clearInterval(pollId);
      }
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchInventory()
      .then((items) => {
        if (!cancelled) {
          setInventory({ kind: "ready", items });
        }
      })
      .catch(() => {
        if (!cancelled) {
          setInventory({ kind: "ready", items: [] });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([fetchReceipts(), fetchPolicies()])
      .then(([receiptsResult, policiesResult]) => {
        if (cancelled) {
          return;
        }
        if (receiptsResult.status === "fulfilled") {
          setReceipts({ kind: "ready", items: receiptsResult.value });
        } else {
          setReceipts({
            kind: "error",
            message: receiptsResult.reason instanceof Error ? receiptsResult.reason.message : "Unable to load local approval history."
          });
        }
        if (policiesResult.status === "fulfilled") {
          setPolicies({ kind: "ready", items: policiesResult.value });
        } else {
          setPolicies({
            kind: "error",
            message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (view !== "fleet") {
      return;
    }
    let cancelled = false;
    setInventory({ kind: "loading" });
    fetchInventory()
      .then((items) => {
        if (!cancelled) {
          setInventory({ kind: "ready", items });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setInventory({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load watched app inventory."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [view]);

  const queuedItems = requests.kind === "ready" ? requests.items : [];
  const activeRequestId = requestId ?? queuedItems[0]?.request_id ?? null;

  useEffect(() => {
    if (activeRequestId === null) {
      setDetail({ kind: "idle" });
      return;
    }
    let cancelled = false;
    setDetail({ kind: "loading" });
    loadDetail(activeRequestId).then((nextState) => {
      if (!cancelled) {
        setDetail(nextState);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [activeRequestId]);

  const handleOpenInbox = useCallback(() => navigate("/inbox"), []);
  const handleOpenFleet = useCallback(() => navigate("/fleet"), []);
  const handleOpenEvidence = useCallback(() => navigate("/evidence"), []);
  const handleOpenSettings = useCallback(() => navigate("/settings"), []);
  const handleGoHome = useCallback(() => navigate("/"), []);
  const handleOpenRequest = useCallback((nextRequestId: string) => {
    navigate(`/requests/${nextRequestId}`);
  }, []);

  const handleClearPolicies = useCallback(async (scope: { harness?: string; all?: boolean }) => {
    const target = scope.all ? "all saved approvals" : `${scope.harness ?? "this app"} approvals`;
    if (!window.confirm(`Clear ${target}? Guard will ask again next time matching actions run.`)) {
      return;
    }
    await clearPolicy(scope);
    const [snapshotResult, policiesResult] = await Promise.allSettled([fetchRuntimeSnapshot(), fetchPolicies()]);
    if (snapshotResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: snapshotResult.value });
      setRequests({ kind: "ready", items: snapshotResult.value.items });
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

  const handleResolve = useCallback(async (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: DecisionScope;
    workspace?: string;
    reason: string;
  }) => {
    const queuedItemsSnapshot = requests.kind === "ready" ? requests.items : [];
    const result = await resolveRequestWithQueueResult(payload);
    const nextId = selectNextAfterResolution(result, queuedItemsSnapshot);
    if (nextId !== null) {
      setResolutionMessage(null);
      navigate(`/requests/${nextId}`);
    } else {
      setResolutionMessage(result.resolution_summary || "Decision saved. Return to your chat and retry the command.");
      navigate("/inbox");
    }
    const [snapshotResult, receiptsResult, policiesResult] = await Promise.allSettled([fetchRuntimeSnapshot(), fetchReceipts(), fetchPolicies()]);
    if (snapshotResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: snapshotResult.value });
      setRequests({ kind: "ready", items: snapshotResult.value.items });
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
  }, [requests, setRuntime, setRequests, setReceipts, setPolicies, setResolutionMessage]);

  const handleBulkApprove = useCallback(async (ids: string[]) => {
    const results = await Promise.allSettled(
      ids.map((id) =>
        resolveRequestWithQueueResult({ requestId: id, action: "allow", scope: "artifact", reason: "" })
      )
    );
    const succeeded = results.filter((r) => r.status === "fulfilled").length;
    const failed = results.length - succeeded;
    const label =
      failed === 0
        ? `${succeeded} item${succeeded !== 1 ? "s" : ""} approved.`
        : `${succeeded} approved, ${failed} failed. Retry the failed items manually.`;
    setResolutionMessage(label);
    navigate("/inbox");
    const [snapshotResult, receiptsResult, policiesResult] = await Promise.allSettled([fetchRuntimeSnapshot(), fetchReceipts(), fetchPolicies()]);
    if (snapshotResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: snapshotResult.value });
      setRequests({ kind: "ready", items: snapshotResult.value.items });
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
  }, [setRuntime, setRequests, setReceipts, setPolicies, setResolutionMessage]);

  return (
    <ApprovalCenterLayout
      view={view}
      requests={requests}
      detail={detail}
      receipts={receipts}
      runtime={runtime}
      inventory={inventory.kind === "ready" ? inventory.items : []}
      activeRequestId={activeRequestId}
      resolutionMessage={resolutionMessage}
      homeContent={
        <HomeWorkspace
          requests={requests}
          runtime={runtime}
          policies={policies}
          onOpenInbox={handleOpenInbox}
          onOpenFleet={handleOpenFleet}
          onOpenEvidence={handleOpenEvidence}
          onOpenSettings={handleOpenSettings}
          onClearPolicies={handleClearPolicies}
        />
      }
      onGoHome={handleGoHome}
      onNavigate={navigate}
      onOpenRequest={handleOpenRequest}
      onResolve={handleResolve}
      onBulkApprove={handleBulkApprove}
      fleetContent={
        runtime.kind === "ready" ? (
          <FleetWorkspace
            runtime={runtime.snapshot}
            policies={policies.kind === "ready" ? policies.items : []}
            inventory={inventory}
          />
        ) : null
      }
      settingsContent={<SettingsWorkspace />}
    />
  );
}
