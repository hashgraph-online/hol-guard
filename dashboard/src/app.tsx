import { useEffect, useState } from "react";

import {
  fetchDiff,
  fetchLatestReceipt,
  fetchPolicy,
  fetchReceipts,
  fetchRequest,
  fetchRuntimeSnapshot,
  resolveRequest
} from "./guard-api";
import { ApprovalCenterLayout } from "./approval-center-layout";
import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot
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

function resolveView(pathname: string): "queue" | "receipts" {
  if (pathname === "/receipts") {
    return "receipts";
  }
  return "queue";
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
            message: error instanceof Error ? error.message : "Unable to load local receipt history."
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
      activeRequestId={activeRequestId}
      resolutionMessage={resolutionMessage}
      onGoHome={() => navigate("/")}
      onOpenRequest={(nextRequestId) => navigate(`/requests/${nextRequestId}`)}
      onResolve={async (payload) => {
        await resolveRequest(payload);
        setResolutionMessage("Decision saved. Return to the harness and rerun the same command.");
        navigate("/");
        const [nextSnapshot, nextReceipts] = await Promise.all([fetchRuntimeSnapshot(), fetchReceipts()]);
        setRuntime({ kind: "ready", snapshot: nextSnapshot });
        setRequests({ kind: "ready", items: nextSnapshot.items });
        setReceipts({ kind: "ready", items: nextReceipts });
      }}
    />
  );
}
