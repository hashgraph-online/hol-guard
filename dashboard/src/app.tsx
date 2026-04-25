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
  clearPolicy,
  fetchDiff,
  fetchLatestReceipt,
  fetchPolicies,
  fetchPolicy,
  fetchReceipts,
  fetchRequest,
  fetchRuntimeSnapshot,
  guardAwareHref,
  resolveRequest
} from "./guard-api";
import { ApprovalCenterLayout } from "./approval-center-layout";
import { FleetWorkspace } from "./fleet-workspace";
import { SettingsWorkspace } from "./settings-workspace";
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

type PolicyState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardPolicyDecision[] };

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
    Promise.all([fetchReceipts(), fetchPolicies()])
      .then(([items, policyItems]) => {
        if (!cancelled) {
          setReceipts({ kind: "ready", items });
          setPolicies({ kind: "ready", items: policyItems });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          const message = error instanceof Error ? error.message : "Unable to load local approval history.";
          setReceipts({
            kind: "error",
            message
          });
          setPolicies({ kind: "error", message });
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
          policies={policies}
          onOpenInbox={() => navigate("/inbox")}
          onOpenFleet={() => navigate("/fleet")}
          onOpenEvidence={() => navigate("/evidence")}
          onOpenSettings={() => navigate("/settings")}
          onClearPolicies={async (scope) => {
            const target = scope.all ? "all saved approvals" : `${scope.harness ?? "this app"} approvals`;
            if (!window.confirm(`Clear ${target}? Guard will ask again next time matching actions run.`)) {
              return;
            }
            await clearPolicy(scope);
            const [nextSnapshot, nextPolicies] = await Promise.all([fetchRuntimeSnapshot(), fetchPolicies()]);
            setRuntime({ kind: "ready", snapshot: nextSnapshot });
            setRequests({ kind: "ready", items: nextSnapshot.items });
            setPolicies({ kind: "ready", items: nextPolicies });
          }}
        />
      }
      onGoHome={() => navigate("/")}
      onOpenRequest={(nextRequestId) => navigate(`/requests/${nextRequestId}`)}
      onResolve={async (payload) => {
        await resolveRequest(payload);
        setResolutionMessage("Decision saved. Return to the same chat and retry the command.");
        navigate("/");
        const [nextSnapshot, nextReceipts, nextPolicies] = await Promise.all([fetchRuntimeSnapshot(), fetchReceipts(), fetchPolicies()]);
        setRuntime({ kind: "ready", snapshot: nextSnapshot });
        setRequests({ kind: "ready", items: nextSnapshot.items });
        setReceipts({ kind: "ready", items: nextReceipts });
        setPolicies({ kind: "ready", items: nextPolicies });
      }}
      fleetContent={
        runtime.kind === "ready" ? (
          <FleetWorkspace runtime={runtime.snapshot} policies={policies.kind === "ready" ? policies.items : []} />
        ) : null
      }
      settingsContent={<SettingsWorkspace />}
    />
  );
}

function HomeWorkspace(props: {
  requests: RequestState;
  runtime: RuntimeState;
  policies: PolicyState;
  onOpenInbox: () => void;
  onOpenFleet: () => void;
  onOpenEvidence: () => void;
  onOpenSettings: () => void;
  onClearPolicies: (scope: { harness?: string; all?: boolean }) => Promise<void>;
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
  const policyItems = props.policies.kind === "ready" ? props.policies.items : [];
  const managedInstalls = snapshot.managed_installs ?? [];
  const activeInstalls = managedInstalls.filter((item) => item.active);
  const observedHarnesses = Array.from(
    new Set([
      ...snapshot.items.map((item) => item.harness),
      ...snapshot.latest_receipts.map((receipt) => receipt.harness),
      ...policyItems.map((policy) => policy.harness)
    ])
  ).sort();
  const clearHarnesses = activeInstalls.length > 0 ? activeInstalls.map((install) => install.harness) : observedHarnesses;
  const latestReceipts = snapshot.latest_receipts
    .slice(0, 3)
    .map((receipt) => receipt.artifact_name ?? receipt.artifact_id)
    .filter((receiptName) => receiptName.length > 0);
  const watchedAppsCount = activeInstalls.length > 0 ? activeInstalls.length : observedHarnesses.length;
  const primaryActionLabel = queuedCount > 0 ? "Review blocked action" : "Open review queue";

  return (
    <div className="space-y-6">
      <section className="guard-surface-in relative overflow-hidden rounded-[2rem] border border-brand-blue/15 bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(72,223,123,0.10)_100%)] p-5 shadow-[0_20px_60px_rgba(63,65,116,0.08)] sm:p-6 lg:p-7">
        <div className="pointer-events-none absolute right-10 top-8 h-24 w-24 rounded-full bg-brand-blue/20 blur-3xl" />
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-start">
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-2">
              <SectionLabel>Home</SectionLabel>
              <Badge tone={queuedCount > 0 ? "warning" : "success"}>
                {queuedCount > 0 ? `${queuedCount} waiting` : "Nothing waiting"}
              </Badge>
              <Tag tone={snapshot.cloud_state === "local_only" ? "slate" : "blue"}>
                {snapshot.cloud_state_label}
              </Tag>
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-semibold tracking-tight text-brand-dark">
                HOL Guard is watching this machine.
              </h2>
              <p className="max-w-3xl text-sm leading-relaxed text-brand-dark/80">
                If Codex, Claude Code, Copilot, or another connected app tries something risky, Guard pauses it here before it runs.
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <HomeStat label="Needs your choice" value={queuedCount.toString()} />
              <HomeStat label="Apps watched" value={watchedAppsCount.toString()} />
              <HomeStat label="Saved choices" value={policyItems.length.toString()} />
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <ActionButton onClick={props.onOpenInbox}>{primaryActionLabel}</ActionButton>
            <ActionButton variant="outline" onClick={props.onOpenFleet}>
              Watched apps
            </ActionButton>
            <ActionButton variant="outline" onClick={props.onOpenEvidence}>
              History
            </ActionButton>
            <ActionButton variant="outline" onClick={props.onOpenSettings}>
              Settings
            </ActionButton>
            {snapshot.cloud_state === "local_only" ? (
              <ActionButton href={snapshot.connect_url} variant="secondary">
                Connect this machine
              </ActionButton>
            ) : null}
          </div>
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
        <section className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
          <SectionLabel>Today</SectionLabel>
          <h3 className="mt-2 text-lg font-semibold tracking-tight text-brand-dark">
            {queuedCount > 0 ? "A blocked action needs your choice." : "No blocked actions right now."}
          </h3>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            {queuedCount > 0
              ? "Open the review queue to see exactly what app and command were paused."
              : latestReceipts.length > 0
                ? `Recent choices: ${latestReceipts.join(", ")}.`
                : "Guard will show the next risky action here before it runs."}
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            <ActionButton onClick={props.onOpenInbox}>{primaryActionLabel}</ActionButton>
            <ActionButton variant="outline" onClick={props.onOpenEvidence}>View history</ActionButton>
          </div>
        </section>

        <section className="rounded-[1.75rem] border border-brand-blue/15 bg-brand-blue/[0.04] p-5 sm:p-6">
          <details className="group">
            <summary className="flex cursor-pointer select-none items-center justify-between gap-3 text-sm font-semibold text-brand-dark [&::-webkit-details-marker]:hidden">
              <span>Reset saved approvals</span>
              <span className="text-brand-blue transition-transform group-open:rotate-90">›</span>
            </summary>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Clear saved choices when you want Guard to ask again. This does not remove your review history.
            </p>
            <div className="mt-4 flex flex-wrap gap-3">
              <ActionButton variant="outline" onClick={() => props.onClearPolicies({ all: true })}>
                Clear all approvals
              </ActionButton>
              {clearHarnesses.slice(0, 3).map((harness) => (
                <ActionButton
                  key={harness}
                  variant="ghost"
                  onClick={() => props.onClearPolicies({ harness })}
                >
                  Clear {harness}
                </ActionButton>
              ))}
            </div>
          </details>
        </section>
      </div>
    </div>
  );
}

function HomeStat(props: { label: string; value: string }) {
  return (
    <div className="rounded-[1.25rem] border border-white/80 bg-white/80 px-4 py-3 shadow-sm">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{props.label}</p>
      <p className="mt-1 text-2xl font-semibold tracking-tight text-brand-dark">{props.value}</p>
    </div>
  );
}
