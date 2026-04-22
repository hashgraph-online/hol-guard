import { useEffect, useState } from "react";

import {
  fetchDiff,
  fetchLocalStateSummary,
  fetchLatestReceipt,
  fetchPolicy,
  fetchReceipts,
  fetchRequest,
  fetchRequests,
  fetchRuntimeSummary,
  resolveRequest
} from "./guard-api";
import { ApprovalCenterLayout } from "./approval-center-layout";
import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardLocalStateSummary,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSummary
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
  | { kind: "ready"; item: GuardRuntimeSummary };

type LocalState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; item: GuardLocalStateSummary };

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
  window.history.pushState({}, "", pathname);
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

function resolveView(pathname: string): "home" | "inbox" | "fleet" | "evidence" {
  if (pathname === "/" || pathname === "/home") {
    return "home";
  }
  if (pathname === "/inbox") {
    return "inbox";
  }
  if (pathname === "/fleet") {
    return "fleet";
  }
  if (pathname === "/receipts" || pathname === "/evidence") {
    return "evidence";
  }
  return "inbox";
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
  const [localState, setLocalState] = useState<LocalState>({ kind: "loading" });
  const [resolutionMessage, setResolutionMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchRequests()
      .then((items) => {
        if (!cancelled) {
          setRequests({ kind: "ready", items });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setRequests({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load the local Guard inbox."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchReceipts()
      .then((items) => {
        if (!cancelled) {
          setReceipts({ kind: "ready", items });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setReceipts({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load local Guard evidence."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchRuntimeSummary()
      .then((item) => {
        if (!cancelled) {
          setRuntime({ kind: "ready", item });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setRuntime({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load Guard runtime health."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchLocalStateSummary()
      .then((item) => {
        if (!cancelled) {
          setLocalState({ kind: "ready", item });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setLocalState({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load Guard local status."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

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

  return (
    <ApprovalCenterLayout
      view={view}
      requests={requests}
      detail={detail}
      receipts={receipts}
      runtime={runtime}
      localState={localState}
      activeRequestId={activeRequestId}
      resolutionMessage={resolutionMessage}
      onGoHome={() => navigate("/")}
      onOpenRequest={(nextRequestId) => navigate(`/requests/${nextRequestId}`)}
      onResolve={async (payload) => {
        await resolveRequest(payload);
        setResolutionMessage("Decision saved. Return to the harness and rerun the same command.");
        navigate("/");
        const [nextRequests, nextReceipts] = await Promise.all([fetchRequests(), fetchReceipts()]);
        setRequests({ kind: "ready", items: nextRequests });
        setReceipts({ kind: "ready", items: nextReceipts });
        try {
          setRuntime({ kind: "ready", item: await fetchRuntimeSummary() });
          setLocalState({ kind: "ready", item: await fetchLocalStateSummary() });
        } catch (error) {
          const message = error instanceof Error ? error.message : "Unable to refresh Guard runtime health.";
          setRuntime({ kind: "error", message });
          setLocalState({ kind: "error", message });
        }
      }}
    />
  );
}
