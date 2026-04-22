import { ActionButton, Badge, EmptyState, SectionLabel, Surface } from "./approval-center-primitives";
import type { GuardApprovalRequest, GuardReceipt } from "./guard-types";

type RequestState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardApprovalRequest[] };

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

type HarnessSummary = {
  harness: string;
  latestDecision: string | null;
  queuedCount: number;
  receiptCount: number;
};

function actionTone(decision: string | null): "default" | "success" | "warning" | "destructive" {
  if (decision === "block") {
    return "destructive";
  }
  if (decision === "review" || decision === "warn" || decision === "require-reapproval") {
    return "warning";
  }
  if (decision === "allow") {
    return "success";
  }
  return "default";
}

function labelDecision(decision: string | null): string {
  if (decision === "allow") {
    return "Protected";
  }
  if (decision === "block") {
    return "Blocked";
  }
  if (decision === "review" || decision === "require-reapproval") {
    return "Needs review";
  }
  if (decision === "warn") {
    return "Watch";
  }
  return "Unknown";
}

function buildHarnessSummaries(
  requests: GuardApprovalRequest[],
  receipts: GuardReceipt[],
): HarnessSummary[] {
  const harnesses = new Set<string>();
  for (const item of requests) {
    harnesses.add(item.harness);
  }
  for (const item of receipts) {
    harnesses.add(item.harness);
  }
  return Array.from(harnesses)
    .sort((left, right) => left.localeCompare(right))
    .map((harness) => {
      const harnessRequests = requests.filter((item) => item.harness === harness);
      const harnessReceipts = receipts.filter((item) => item.harness === harness);
      return {
        harness,
        latestDecision: harnessReceipts[0]?.policy_decision ?? null,
        queuedCount: harnessRequests.length,
        receiptCount: harnessReceipts.length,
      };
    });
}

export function FleetWorkspace(props: {
  requests: RequestState;
  receipts: ReceiptsState;
}) {
  if (props.requests.kind === "loading" || props.receipts.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-8 w-40" />
        <div className="guard-skeleton h-32 w-full" />
      </div>
    );
  }

  if (props.requests.kind === "error") {
    return (
      <Surface tone="danger">
        <p className="text-sm text-red-700">{props.requests.message}</p>
      </Surface>
    );
  }

  if (props.receipts.kind === "error") {
    return (
      <Surface tone="danger">
        <p className="text-sm text-red-700">{props.receipts.message}</p>
      </Surface>
    );
  }

  const summaries = buildHarnessSummaries(props.requests.items, props.receipts.items);

  if (summaries.length === 0) {
    return (
        <EmptyState
          title="No local fleet activity yet"
          body="Run Guard once from a supported harness to start building local machine coverage, saved decisions, and reusable proof."
          action={<ActionButton href="/inbox">Open inbox</ActionButton>}
        />
    );
  }

  return (
    <div className="space-y-6">
      <Surface tone="accent">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="space-y-2">
            <SectionLabel>Fleet</SectionLabel>
            <h2 className="text-2xl font-semibold tracking-tight text-brand-dark">
              Local machine coverage
            </h2>
            <p className="max-w-3xl text-sm leading-6 text-gray-500">
              Guard is already building a local control plane on this machine. Use Fleet to confirm
              which harnesses are protected here, where queue pressure is building, and how much
              decision memory is ready to reuse.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Surface className="p-4">
              <SectionLabel>Harnesses</SectionLabel>
              <p className="mt-2 text-2xl font-semibold text-brand-dark">{summaries.length}</p>
            </Surface>
            <Surface className="p-4">
              <SectionLabel>Queued</SectionLabel>
              <p className="mt-2 text-2xl font-semibold text-brand-dark">{props.requests.items.length}</p>
            </Surface>
            <Surface className="p-4">
              <SectionLabel>Decisions</SectionLabel>
              <p className="mt-2 text-2xl font-semibold text-brand-dark">{props.receipts.items.length}</p>
            </Surface>
            <Surface className="p-4">
              <SectionLabel>Mode</SectionLabel>
              <p className="mt-2 text-sm font-semibold text-brand-dark">Local-first</p>
            </Surface>
          </div>
        </div>
      </Surface>

      <div className="grid gap-4 lg:grid-cols-2">
        {summaries.map((summary) => (
          <Surface key={summary.harness}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <SectionLabel>{summary.harness}</SectionLabel>
                <h3 className="mt-1 text-lg font-semibold tracking-tight text-brand-dark">
                  {summary.harness} coverage
                </h3>
              </div>
              <Badge tone={actionTone(summary.latestDecision)}>
                {labelDecision(summary.latestDecision)}
              </Badge>
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <div className="rounded-lg border border-border bg-white px-4 py-3">
                <SectionLabel>Queued asks</SectionLabel>
                <p className="mt-1 text-lg font-semibold text-brand-dark">{summary.queuedCount}</p>
              </div>
              <div className="rounded-lg border border-border bg-white px-4 py-3">
                <SectionLabel>Saved decisions</SectionLabel>
                <p className="mt-1 text-lg font-semibold text-brand-dark">{summary.receiptCount}</p>
              </div>
              <div className="rounded-lg border border-border bg-white px-4 py-3">
                <SectionLabel>Latest verdict</SectionLabel>
                <p className="mt-1 text-sm font-semibold text-brand-dark">
                  {labelDecision(summary.latestDecision)}
                </p>
              </div>
            </div>
            <div className="mt-4 flex flex-wrap gap-3">
              <ActionButton href="/inbox">Open inbox</ActionButton>
              <ActionButton href="/evidence" variant="outline">
                Open evidence
              </ActionButton>
            </div>
          </Surface>
        ))}
      </div>
    </div>
  );
}
