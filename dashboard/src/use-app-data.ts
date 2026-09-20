import { useEffect, useRef, useState } from "react";
import {
  fetchAllPendingRequests,
  fetchApprovalPage,
  fetchRuntimeSnapshot,
  fetchInventory,
  fetchSettings,
  fetchGuardUpdateStatus,
  fetchReceipts,
  fetchPolicies,
} from "./guard-api";
import type {
  GuardApprovalGatePublicConfig,
  GuardCodexResumeResult,
  GuardReceipt,
  GuardPolicyDecision,
} from "./guard-types";
import type {
  RequestState,
  DetailState,
  ReceiptsState,
  RuntimeState,
  PolicyState,
  InventoryState,
} from "./app-state-types";
import { useDashboardPathname } from "./dashboard-location";
import { useRouteFocus } from "./use-route-focus";
import { resolveView, parseRequestId, parseAppDetail, focusVisibleDashboardSearch } from "./app-routing";
import { loadDetail } from "./app-detail-state";

export function useAppData() {
  const pathname = useDashboardPathname();
  const view = resolveView(pathname);
  useRouteFocus(view);
  const requestId = parseRequestId(pathname);
  const appDetailHarness = parseAppDetail(pathname);
  const [requests, setRequests] = useState<RequestState>({ kind: "loading" });
  const [detail, setDetail] = useState<DetailState>({ kind: "idle" });
  const [receipts, setReceipts] = useState<ReceiptsState>({ kind: "loading" });
  const [runtime, setRuntime] = useState<RuntimeState>({ kind: "loading" });
  const [policies, setPolicies] = useState<PolicyState>({ kind: "loading" });
  const [inventory, setInventory] = useState<InventoryState>({ kind: "idle" });
  const [resolutionMessage, setResolutionMessage] = useState<string | null>(null);
  const [codexResume, setCodexResume] = useState<GuardCodexResumeResult | null>(null);
  const [resolvedRequestId, setResolvedRequestId] = useState<string | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [clearConfirm, setClearConfirm] = useState<{ harness?: string; all?: boolean } | null>(null);
  const [approvalGate, setApprovalGate] = useState<GuardApprovalGatePublicConfig | null>(null);
  const [guardVersion, setGuardVersion] = useState<string | null>(null);
  const resolutionInFlight = useRef(false);
  const bulkApproveInFlight = useRef(false);
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
        if (nextState.kind === "ready") {
          setRequests((current) => {
            if (current.kind !== "ready" || current.items.some((item) => item.request_id === nextState.item.request_id)) {
              return current;
            }
            return { kind: "ready", items: [nextState.item, ...current.items] };
          });
        }
      }
    });
    return () => {
      cancelled = true;
    };
  }, [activeRequestId]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      const target = event.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return;
      if (event.key === "?") {
        event.preventDefault();
        setHelpOpen((open) => !open);
      }
      if (event.key === "/") {
        if (focusVisibleDashboardSearch()) {
          event.preventDefault();
        }
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    let cancelled = false;
    let pollId: number | undefined;
    let refreshInFlight = false;
    let clearedQueue = false;
    const needsFullQueue = view === "inbox" && requestId === null;
    const needsQueuePage = view === "inbox" || requestId !== null;
    const needsRuntimeReceipts =
      view === "home" ||
      view === "fleet" ||
      view === "app-detail" ||
      view === "supply-chain" ||
      view === "audit" ||
      view === "feed-health";
    const loadApprovalQueue = () => {
      if (refreshInFlight || cancelled || resolutionInFlight.current) {
        return;
      }
      refreshInFlight = true;
      const queueErrorMessage = "Unable to load the local approval queue.";
      const runtimeErrorMessage = "Unable to load the local runtime snapshot.";
      let pendingRequests: Promise<void>;
      if (needsFullQueue) {
        pendingRequests = fetchAllPendingRequests()
          .then((items) => {
            if (!cancelled && !resolutionInFlight.current) {
              setRequests({ kind: "ready", items });
            }
          })
          .catch((error: unknown) => {
            if (!cancelled && !resolutionInFlight.current) {
              const message = error instanceof Error ? error.message : queueErrorMessage;
              setRequests({ kind: "error", message });
            }
          });
      } else if (needsQueuePage) {
        pendingRequests = fetchApprovalPage({ status: "pending", limit: 200 })
          .then((page) => {
            if (!cancelled && !resolutionInFlight.current) {
              setRequests({ kind: "ready", items: page.items });
            }
          })
          .catch((error: unknown) => {
            if (!cancelled && !resolutionInFlight.current) {
              const message = error instanceof Error ? error.message : queueErrorMessage;
              setRequests({ kind: "error", message });
            }
          });
      } else {
        pendingRequests = Promise.resolve().then(() => {
          if (!cancelled && !resolutionInFlight.current && !clearedQueue) {
            setRequests({ kind: "ready", items: [] });
            clearedQueue = true;
          }
        });
      }
      const runtimeSnapshot = fetchRuntimeSnapshot({ includeItems: false, includeReceipts: needsRuntimeReceipts })
        .then((snapshot) => {
          if (!cancelled && !resolutionInFlight.current) {
            setRuntime({ kind: "ready", snapshot });
          }
        })
        .catch((error: unknown) => {
          if (!cancelled && !resolutionInFlight.current) {
            const message = error instanceof Error ? error.message : runtimeErrorMessage;
            setRuntime({ kind: "error", message });
          }
        });
      void Promise.allSettled([pendingRequests, runtimeSnapshot]).finally(() => {
        refreshInFlight = false;
      });
    };
    loadApprovalQueue();
    pollId = window.setInterval(loadApprovalQueue, needsFullQueue ? 4000 : 12000);
    return () => {
      cancelled = true;
      if (pollId !== undefined) {
        window.clearInterval(pollId);
      }
    };
  }, [view, requestId]);

  useEffect(() => {
    const needsInventory = view === "app-detail";
    if (!needsInventory) {
      return;
    }
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
  }, [view]);

  useEffect(() => {
    let cancelled = false;
    fetchSettings()
      .then((payload) => {
        if (!cancelled && payload.settings.approval_gate !== undefined) {
          setApprovalGate(payload.settings.approval_gate);
        }
      })
      .catch(() => {});
    if (view === "about") {
      fetchGuardUpdateStatus()
        .then((status) => {
          if (!cancelled && status.current_version) {
            setGuardVersion(status.current_version);
          }
        })
        .catch(() => {});
    }
    return () => { cancelled = true; };
  }, [view]);

  useEffect(() => {
    const needsReceipts =
      view === "evidence" ||
      view === "app-detail" ||
      view === "supply-chain" ||
      view === "audit" ||
      view === "feed-health";
    const needsPolicies =
      view === "home" ||
      view === "fleet" ||
      view === "app-detail" ||
      view === "supply-chain" ||
      view === "audit" ||
      view === "feed-health" ||
      view === "policy";
    if (!needsReceipts && !needsPolicies) {
      return;
    }
    let cancelled = false;
    Promise.allSettled([
      needsReceipts ? fetchReceipts() : Promise.resolve<GuardReceipt[] | null>(null),
      needsPolicies ? fetchPolicies() : Promise.resolve<GuardPolicyDecision[] | null>(null),
    ])
      .then(([receiptsResult, policiesResult]) => {
        if (cancelled) {
          return;
        }
        if (needsReceipts) {
          if (receiptsResult.status === "fulfilled" && receiptsResult.value !== null) {
            setReceipts({ kind: "ready", items: receiptsResult.value });
          } else {
            const reason = receiptsResult.status === "rejected" ? receiptsResult.reason : null;
            setReceipts({
              kind: "error",
              message: reason instanceof Error ? reason.message : "Unable to load local approval history."
            });
          }
        }
        if (needsPolicies) {
          if (policiesResult.status === "fulfilled" && policiesResult.value !== null) {
            setPolicies({ kind: "ready", items: policiesResult.value });
          } else {
            const reason = policiesResult.status === "rejected" ? policiesResult.reason : null;
            setPolicies({
              kind: "error",
              message: reason instanceof Error ? reason.message : "Unable to load saved approvals."
            });
          }
        }
      });
    return () => {
      cancelled = true;
    };
  }, [view]);

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

  return {
    pathname,
    view,
    requestId,
    appDetailHarness,
    requests,
    setRequests,
    detail,
    setDetail,
    receipts,
    setReceipts,
    runtime,
    setRuntime,
    policies,
    setPolicies,
    inventory,
    setInventory,
    resolutionMessage,
    setResolutionMessage,
    codexResume,
    setCodexResume,
    resolvedRequestId,
    setResolvedRequestId,
    helpOpen,
    setHelpOpen,
    clearConfirm,
    setClearConfirm,
    approvalGate,
    setApprovalGate,
    guardVersion,
    setGuardVersion,
    resolutionInFlight,
    bulkApproveInFlight,
    queuedItems,
    activeRequestId,
  };
}
