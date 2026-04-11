import { useEffect, useState } from "react";

import {
  fetchDiff,
  fetchPolicy,
  fetchReceipts,
  fetchRequest,
  fetchRequests,
  resolveRequest
} from "./guard-api";
import { ApprovalCenterLayout } from "./approval-center-layout";
import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt
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

async function loadDetail(requestId: string): Promise<Exclude<DetailState, { kind: "idle" | "loading" }>> {
  try {
    const item = await fetchRequest(requestId);
    const [diff, receipts, policy] = await Promise.all([
      fetchDiff(item.artifact_id, item.harness),
      fetchReceipts(),
      fetchPolicy(item.harness)
    ]);
    const receipt = receipts.find((entry) => entry.artifact_id === item.artifact_id) ?? null;
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
  const requestId = parseRequestId(pathname);
  const [requests, setRequests] = useState<RequestState>({ kind: "loading" });
  const [detail, setDetail] = useState<DetailState>({ kind: "idle" });
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
            message: error instanceof Error ? error.message : "Unable to load the local approval queue."
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
      requests={requests}
      detail={detail}
      activeRequestId={activeRequestId}
      resolutionMessage={resolutionMessage}
      onGoHome={() => navigate("/")}
      onOpenRequest={(nextRequestId) => navigate(`/requests/${nextRequestId}`)}
      onResolve={async (payload) => {
        await resolveRequest(payload);
        setResolutionMessage("Decision saved. Return to the harness and rerun the same command.");
        navigate("/");
        const items = await fetchRequests();
        setRequests({ kind: "ready", items });
      }}
    />
  );
}
