import { useEffect, useState, useCallback, useRef, useMemo, lazy, Suspense } from "react";

import {
  clearPolicy,
  fetchDiff,
  fetchInventory,
  fetchLatestReceipt,
  fetchPolicies,
  fetchPolicy,
  fetchReceipts,
  fetchRequest,
  fetchMcpPolicyRequest,
  fetchApprovalPage,
  fetchAllPendingRequests,
  fetchInboxState,
  fetchRuntimeSnapshot,
  fetchSettings,
  fetchGuardUpdateStatus,
  guardAwareHref,
  bulkAllowReadOnce,
  repairApprovalCenter,
  resolveRequestWithQueueResult,
  retryResume,
} from "./guard-api";
import { ApprovalCenterLayout, type BulkGateCredentials } from "./approval-center-layout";
import type { AppView } from "./approval-center-primitives";
import { buildClearPayload } from "./clear-policy-payload";
import { normalizeHarnessSlug } from "./approval-center-utils";
import { ErrorBoundary } from "./error-boundary";
import { selectNextAfterResolution } from "./queue-state";
import { useRouteFocus } from "./use-route-focus";

const HomeWorkspace = lazy(() => import("./home-dashboard").then((m) => ({ default: m.HomeWorkspace })));
const FleetWorkspace = lazy(() => import("./fleet-workspace").then((m) => ({ default: m.FleetWorkspace })));
const SettingsWorkspace = lazy(() => import("./settings-workspace").then((m) => ({ default: m.SettingsWorkspace })));
const AppDetailWorkspace = lazy(() => import("./apps/app-detail-workspace").then((m) => ({ default: m.AppDetailWorkspace })));
const HelpModal = lazy(() => import("./help-modal").then((m) => ({ default: m.HelpModal })));
const SupplyChainHubWorkspace = lazy(() =>
  import("./supply-chain-hub-workspace").then((m) => ({ default: m.SupplyChainHubWorkspace }))
);
const PolicyWorkspacePage = lazy(() =>
  import("./policy-workspace-page").then((m) => ({ default: m.PolicyWorkspacePage }))
);
const McpPolicyRequestPanel = lazy(() =>
  import("./mcp-policy-request-panel").then((m) => ({ default: m.McpPolicyRequestPanel }))
);
const AboutWorkspace = lazy(() =>
  import("./about/about-workspace").then((m) => ({ default: m.AboutWorkspace }))
);

function LazyFallback() {
  return (
    <div className="flex min-h-[200px] items-center justify-center">
      <div className="guard-skeleton h-8 w-48" />
    </div>
  );
}
import type {
  GuardApprovalGatePublicConfig,
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardCodexResumeResult,
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
  | { kind: "stale" }
  | {
      kind: "ready";
      item: GuardApprovalRequest;
      diff: GuardArtifactDiff | null;
      receipt: GuardReceipt | null;
      policy: GuardPolicyDecision[];
    }
  | { kind: "mcp-policy"; requestId: string };

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

export const PROTECT_ROUTE = "/protect";

export function viewTitle(view: AppView): string {
  if (view === "home") return "Home";
  if (view === "inbox") return "Inbox";
  if (view === "fleet") return "Protect";
  if (view === "evidence") return "Evidence";
  if (view === "settings") return "Settings";
  if (view === "supply-chain") return "Supply Chain";
  if (view === "audit") return "Audit";
  if (view === "policy") return "Policy";
  if (view === "feed-health") return "Feed Health";
  if (view === "about") return "About";
  return "App detail";
}

export function parseAppDetail(pathname: string): string | null {
  if (!pathname.startsWith("/apps/")) {
    return null;
  }
  const rawSlug = pathname.slice("/apps/".length);
  try {
    return normalizeHarnessSlug(decodeURIComponent(rawSlug));
  } catch {
    return null;
  }
}

export function resolveView(pathname: string): AppView {
  if (parseAppDetail(pathname) !== null) {
    return "app-detail";
  }
  if (pathname.startsWith("/apps/")) {
    return "fleet";
  }
  if (pathname === "/settings") {
    return "settings";
  }
  if (pathname === PROTECT_ROUTE) {
    return "fleet";
  }
  if (pathname === "/evidence") {
    return "evidence";
  }
  if (pathname === "/supply-chain") {
    return "supply-chain";
  }
  if (pathname === "/audit") {
    return "audit";
  }
  if (pathname === "/policy") {
    return "policy";
  }
  if (pathname === "/feed-health") {
    return "feed-health";
  }
  if (pathname === "/about") {
    return "about";
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
    const message = error instanceof Error ? error.message : "";
    if (message.includes("404")) {
      // VPC045-047/056: a 404 on /v1/requests/<id> may mean this is a staged
      // MCP policy creation request rather than a regular approval. Probe the
      // MCP endpoint; if it exists, render the MCP panel. Otherwise fall back
      // to the stale state so the inbox shows an honest "gone" message.
      try {
        const mcpRequest = await fetchMcpPolicyRequest(requestId);
        if (mcpRequest !== null) {
          return { kind: "mcp-policy", requestId };
        }
      } catch {
        // Swallow — the original 404 is the source of truth here.
      }
      return { kind: "stale" };
    }
    return {
      kind: "error",
      message: message.length > 0 ? message : "Unable to load the approval request."
    };
  }
}

export function App() {
  const pathname = usePathname();
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
        event.preventDefault();
        const searchInput = document.querySelector('input[type="search"]') as HTMLInputElement | null;
        searchInput?.focus();
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

  const handleOpenInbox = useCallback(() => navigate("/inbox"), []);
  const handleOpenFleet = useCallback(() => navigate(PROTECT_ROUTE), []);
  const handleOpenEvidence = useCallback(() => navigate("/evidence"), []);
  const handleOpenInsights = useCallback(() => navigate("/evidence?view=insights"), [navigate]);
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
  }, [setRuntime, setRequests, setReceipts, setPolicies, setInventory]);

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
  }) => {
    resolutionInFlight.current = true;
    const queuedItemsSnapshot = requests.kind === "ready" ? requests.items : [];
    try {
      const result = await resolveRequestWithQueueResult(payload);
      const nextId = selectNextAfterResolution(result, queuedItemsSnapshot);
      const resume = result.codex_resume ?? null;
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
  }, [requests, refreshStateAfterAction, setResolutionMessage]);

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

  const appDetailContent = useMemo(() => {
    if (view !== "app-detail" || !appDetailHarness || runtime.kind !== "ready") {
      return null;
    }
    return (
      <AppDetailWorkspace
        harness={appDetailHarness}
        runtime={runtime.snapshot}
        receipts={receipts.kind === "ready" ? receipts.items : []}
        policies={policies.kind === "ready" ? policies.items : []}
        inventory={inventory.kind === "ready" ? inventory.items : []}
        requests={requests.kind === "ready" ? requests.items : []}
        onGoHome={handleGoHome}
        onOpenRequest={handleOpenRequest}
        onClearAppPolicies={handleClearAppPolicies}
        onClearPolicy={handleClearPolicy}
        onManagedInstallChanged={refreshStateAfterAction}
      />
    );
  }, [view, appDetailHarness, runtime, receipts, policies, inventory, requests, handleGoHome, handleOpenRequest, handleClearAppPolicies, handleClearPolicy, refreshStateAfterAction]);

  const policyContent = useMemo(() => {
    if (runtime.kind !== "ready") {
      return null;
    }
    if (policies.kind === "ready") {
      return (
        <Suspense fallback={<LazyFallback />}>
          <PolicyWorkspacePage
            snapshot={runtime.snapshot}
            policies={policies.items}
            onClearPolicy={handleClearPolicy}
            onOpenSettings={handleOpenSettings}
            onOpenInbox={handleOpenInbox}
            onRefreshPolicies={handleRefreshPolicies}
            onNavigate={navigate}
          />
        </Suspense>
      );
    }
    if (policies.kind === "error") {
      return (
        <div className="rounded-2xl border border-red-200 bg-red-50/80 px-4 py-3 text-sm text-red-700">
          {policies.message}
        </div>
      );
    }
    return <LazyFallback />;
  }, [
    runtime,
    policies,
    handleClearPolicy,
    handleOpenSettings,
    handleOpenInbox,
    handleRefreshPolicies,
    navigate,
  ]);

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-lg focus:bg-brand-blue focus:px-4 focus:py-2 focus:text-white focus:outline-none"
      >
        Skip to content
      </a>
      <div aria-live="polite" aria-atomic="true" className="sr-only">
        {viewTitle(view)}
      </div>
    <ApprovalCenterLayout
      view={view}
      requests={requests}
      detail={detail}
      receipts={receipts}
      runtime={runtime}
      inventory={inventory.kind === "ready" ? inventory.items : []}
      activeRequestId={activeRequestId}
      resolutionMessage={resolutionMessage}
      codexResume={codexResume}
      approvalGate={approvalGate}
      onRetryResume={handleRetryResume}
      homeContent={
        <Suspense fallback={<LazyFallback />}>
          <HomeWorkspace
            requests={requests}
            runtime={runtime}
            policies={policies}
            onOpenInbox={handleOpenInbox}
            onOpenFleet={handleOpenFleet}
            onOpenEvidence={handleOpenEvidence}
            onOpenInsights={handleOpenInsights}
            onOpenSettings={handleOpenSettings}
            onOpenSupplyChain={handleOpenSupplyChain}
            onClearPolicies={handleClearPolicies}
            onOpenAppDetail={handleOpenAppDetail}
            clearConfirm={clearConfirm}
            approvalGate={approvalGate}
            onConfirmClear={handleConfirmClear}
            onCancelClear={handleCancelClear}
            onOpenHelp={handleOpenHelp}
          />
        </Suspense>
      }
      onGoHome={handleGoHome}
      onNavigate={navigate}
      onOpenRequest={handleOpenRequest}
      onResolve={handleResolve}
      onBulkApprove={handleBulkApprove}
      onRetry={handleRetry}
      onRepair={handleRepair}
      onGuardReconnected={handleRetry}
      enableUpdateStatus={view !== "inbox"}
      onClearEvidence={handleClearEvidence}
      fleetContent={
        runtime.kind === "ready" ? (
          <Suspense fallback={<LazyFallback />}>
            <FleetWorkspace
              runtime={runtime.snapshot}
              policies={policies.kind === "ready" ? policies.items : []}
              inventory={inventory}
              onConnectHarness={handleConnectHarness}
              onTestHarness={handleTestHarness}
              onRepairHarness={handleRepairHarness}
              onOpenAppDetail={handleOpenAppDetail}
            />
          </Suspense>
        ) : null
      }
      appDetailContent={
        <ErrorBoundary onReset={handleGoHome}>
          <Suspense fallback={<LazyFallback />}>
            {appDetailContent}
          </Suspense>
        </ErrorBoundary>
      }
      settingsContent={
        <Suspense fallback={<LazyFallback />}>
          <SettingsWorkspace onApprovalGateChange={setApprovalGate} />
        </Suspense>
      }
      supplyChainHubContent={
        runtime.kind === "ready" ? (
          <Suspense fallback={<LazyFallback />}>
	            <SupplyChainHubWorkspace
	              activeView={view}
	              snapshot={runtime.snapshot}
	              receipts={receipts.kind === "ready" ? receipts.items : []}
	              policies={policies.kind === "ready" ? policies.items : []}
	              approvalGate={approvalGate}
	              onClearPolicy={handleClearPolicy}
	              onOpenSettings={handleOpenSettings}
	              onGoHome={handleGoHome}
              onNavigate={navigate}
              onRuntimeRefresh={refreshStateAfterAction}
            />
          </Suspense>
        ) : null
      }
      policyContent={policyContent}
      aboutContent={
        <Suspense fallback={<LazyFallback />}>
          <AboutWorkspace runtimeSummary={
            runtime.kind === "ready"
              ? {
                  // TODO: GuardRuntimeSnapshot does not yet expose guard_version or protected_app_count.
                  // When those fields are added, populate them here instead of null/0.
                  guardVersion: guardVersion,
                  cloudState: runtime.snapshot.cloud_state ?? "unknown",
                  cloudStateLabel: runtime.snapshot.cloud_state_label ?? "Unknown",
                  syncConfigured: runtime.snapshot.sync_configured ?? false,
                  pendingCount: runtime.snapshot.pending_count ?? 0,
                  receiptCount: runtime.snapshot.receipt_count ?? 0,
                  protectedAppCount: 0,
                }
              : null
          } />
        </Suspense>
      }
    />
    {helpOpen && (
      <Suspense fallback={null}>
        <HelpModal open={helpOpen} onClose={handleCloseHelp} />
      </Suspense>
    )}
    </>);
}
