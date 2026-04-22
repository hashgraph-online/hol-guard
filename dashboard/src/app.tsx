import { useEffect, useState } from "react";

import {
  ActionButton,
  Badge,
  EmptyState,
  SectionLabel,
  Surface,
  Tag
} from "./approval-center-primitives";
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
import { FleetWorkspace } from "./fleet-workspace";
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

function resolveView(pathname: string): "home" | "inbox" | "fleet" | "evidence" {
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
      homeContent={
        <HomeWorkspace
          requests={requests}
          runtime={runtime}
          onOpenInbox={() => navigate("/inbox")}
          onOpenFleet={() => navigate("/fleet")}
          onOpenEvidence={() => navigate("/evidence")}
        />
      }
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
      fleetContent={
        runtime.kind === "ready" ? (
          <FleetWorkspace runtime={runtime.snapshot} />
        ) : null
      }
    />
  );
}

function HomeWorkspace(props: {
  requests: RequestState;
  runtime: RuntimeState;
  onOpenInbox: () => void;
  onOpenFleet: () => void;
  onOpenEvidence: () => void;
}) {
  if (props.runtime.kind === "loading" || props.requests.kind === "loading") {
    return (
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="guard-skeleton h-40 w-full" />
        <div className="guard-skeleton h-40 w-full" />
        <div className="guard-skeleton h-40 w-full" />
      </div>
    );
  }

  if (props.runtime.kind === "error") {
    return (
      <EmptyState
        title="Local Home is waiting for the runtime"
        body={props.runtime.message}
        action={<ActionButton onClick={props.onOpenInbox}>Open Inbox anyway</ActionButton>}
      />
    );
  }

  const snapshot = props.runtime.snapshot;
  const queuedCount = props.requests.kind === "ready" ? props.requests.items.length : 0;
  const latestReceipts = snapshot.latest_receipts
    .slice(0, 3)
    .map((receipt) => receipt.artifact_name ?? receipt.artifact_id)
    .filter((receiptName) => receiptName.length > 0);

  return (
    <div className="space-y-6">
      <Surface tone="accent">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <SectionLabel>Local Home</SectionLabel>
              <Badge tone={queuedCount > 0 ? "warning" : "success"}>
                {queuedCount > 0 ? `${queuedCount} queued` : "Queue clear"}
              </Badge>
              <Tag tone={snapshot.cloud_state === "local_only" ? "slate" : "blue"}>
                {snapshot.cloud_state_label}
              </Tag>
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-semibold tracking-tight text-brand-dark">
                See the local queue, machine coverage, and cloud handoff from one place
              </h2>
              <p className="max-w-3xl text-sm leading-relaxed text-brand-dark/80">
                Home keeps the current queue, the protected machine, and the next cloud step visible without dropping you straight into a decision lane.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <ActionButton onClick={props.onOpenInbox}>Open Inbox</ActionButton>
            <ActionButton variant="outline" onClick={props.onOpenFleet}>
              Open Fleet
            </ActionButton>
            <ActionButton variant="outline" onClick={props.onOpenEvidence}>
              Open Evidence
            </ActionButton>
            {snapshot.cloud_state === "local_only" ? (
              <ActionButton href={snapshot.connect_url} variant="secondary">
                Connect this machine
              </ActionButton>
            ) : null}
          </div>
        </div>
      </Surface>

      <div className="grid gap-4 lg:grid-cols-3">
        <Surface>
          <SectionLabel>Inbox</SectionLabel>
          <h3 className="mt-2 text-lg font-semibold tracking-tight text-brand-dark">
            {queuedCount > 0 ? "Work is waiting" : "Nothing needs review"}
          </h3>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            {queuedCount > 0
              ? "Open Inbox to review the current blocked launch and keep the same harness flow moving."
              : "Inbox stays quiet until a changed tool or blocked launch needs a real decision."}
          </p>
          <div className="mt-4">
            <ActionButton onClick={props.onOpenInbox}>
              {queuedCount > 0 ? "Review current queue" : "Open Inbox"}
            </ActionButton>
          </div>
        </Surface>

        <Surface>
          <SectionLabel>Fleet</SectionLabel>
          <h3 className="mt-2 text-lg font-semibold tracking-tight text-brand-dark">
            {snapshot.runtime_state ? "This machine is connected" : "Runtime offline"}
          </h3>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            {snapshot.runtime_state
              ? "Fleet shows the active machine, the current session, and whether the cloud handoff has started."
              : "Guard is not publishing runtime state right now. Restart the local daemon before expecting fresh machine coverage."}
          </p>
          <div className="mt-4">
            <ActionButton variant="outline" onClick={props.onOpenFleet}>
              Open Fleet
            </ActionButton>
          </div>
        </Surface>

        <Surface>
          <SectionLabel>Evidence</SectionLabel>
          <h3 className="mt-2 text-lg font-semibold tracking-tight text-brand-dark">
            {snapshot.receipt_count > 0 ? `${snapshot.receipt_count} stored decisions` : "No local evidence yet"}
          </h3>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            {latestReceipts.length > 0
              ? `Recent memory: ${latestReceipts.join(", ")}.`
              : "The first local proof appears here after Guard evaluates or approves a tool on this machine."}
          </p>
          <div className="mt-4">
            <ActionButton variant="outline" onClick={props.onOpenEvidence}>
              Open Evidence
            </ActionButton>
          </div>
        </Surface>
      </div>
    </div>
  );
}
