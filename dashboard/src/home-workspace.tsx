import { ActionButton, Badge, EmptyState, SectionLabel, Surface } from "./approval-center-primitives";
import type {
  GuardApprovalRequest,
  GuardLocalStateSummary,
  GuardReceipt,
  GuardRuntimeSummary
} from "./guard-types";

type RequestState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardApprovalRequest[] };

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

function localHeadlineLabel(state: string): string {
  if (state === "blocked") return "Needs review";
  if (state === "stale") return "Needs sync";
  if (state === "connected") return "Connected";
  if (state === "protected") return "Protected";
  if (state === "setup") return "Setup";
  return "Local only";
}

function localHeadlineTone(
  state: string
): "default" | "success" | "warning" | "info" | "destructive" {
  if (state === "blocked") return "destructive";
  if (state === "stale") return "warning";
  if (state === "connected") return "info";
  if (state === "protected") return "success";
  return "default";
}

function formatRuntimeState(runtime: RuntimeState): string {
  if (runtime.kind !== "ready" || runtime.item.session === null) {
    return "Waiting";
  }
  return `${runtime.item.session.harness} via ${runtime.item.session.surface}`;
}

export function HomeWorkspace(props: {
  requests: RequestState;
  receipts: ReceiptsState;
  runtime: RuntimeState;
  localState: LocalState;
}) {
  const queuedItems = props.requests.kind === "ready" ? props.requests.items : [];
  const receiptItems = props.receipts.kind === "ready" ? props.receipts.items : [];
  const headlineState =
    props.localState.kind === "ready" ? props.localState.item.headline_state : "setup";
  const guidance = props.localState.kind === "ready" ? props.localState.item.guidance : null;
  const nextActionHref =
    queuedItems.length > 0
      ? `/requests/${queuedItems[0].request_id}`
      : props.localState.kind === "ready" && props.localState.item.portal_links.home
        ? props.localState.item.portal_links.home
        : "/inbox";

  const previewReceipts = receiptItems.slice(0, 3);
  const previewQueue = queuedItems.slice(0, 3);

  return (
    <div className="space-y-6">
      <Surface tone="accent">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SectionLabel>Home</SectionLabel>
              <Badge tone={localHeadlineTone(headlineState)}>
                {localHeadlineLabel(headlineState)}
              </Badge>
            </div>
            <h2 className="text-3xl font-semibold tracking-tight text-brand-dark">
              Local Guard command center
            </h2>
            <p className="max-w-3xl text-sm leading-6 text-gray-600">
              {guidance?.body ??
                "Guard is watching this machine, reusing prior decisions, and surfacing the next thing that actually needs attention."}
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <ActionButton href={nextActionHref}>
              {queuedItems.length > 0 ? "Open current request" : "Open inbox"}
            </ActionButton>
            <ActionButton href="/fleet" variant="outline">
              Open fleet
            </ActionButton>
            <ActionButton href="/evidence" variant="outline">
              Open evidence
            </ActionButton>
          </div>
        </div>
      </Surface>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Inbox"
          value={String(queuedItems.length)}
          detail={queuedItems.length > 0 ? "Items waiting for a decision" : "No blocked work right now"}
        />
        <MetricCard
          label="Evidence"
          value={String(receiptItems.length)}
          detail="Saved local decisions and proof records"
        />
        <MetricCard
          label="Runtime"
          value={formatRuntimeState(props.runtime)}
          detail="Current harness session attached to the approval center"
        />
        <MetricCard
          label="Cloud"
          value={
            props.localState.kind === "ready" && props.localState.item.sync_configured
              ? "Configured"
              : "Local only"
          }
          detail="Cloud pairing is optional; local protection remains active either way"
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <Surface>
          <div className="flex items-center justify-between gap-3">
            <div>
              <SectionLabel>Next action</SectionLabel>
              <h3 className="mt-1 text-xl font-semibold tracking-tight text-brand-dark">
                {guidance?.title ?? "Review the next Guard decision"}
              </h3>
            </div>
            {guidance?.command ? <Badge tone="info">{guidance.command}</Badge> : null}
          </div>
          <p className="mt-3 text-sm leading-6 text-gray-600">
            {guidance?.body ??
              "Guard already has enough local state to guide the next step without sending anything to the cloud."}
          </p>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <ActionButton href={nextActionHref}>
              {queuedItems.length > 0 ? "Handle inbox item" : "Open inbox"}
            </ActionButton>
            {guidance?.primary_link ? (
              <ActionButton href={guidance.primary_link} variant="outline">
                Open shared view
              </ActionButton>
            ) : (
              <ActionButton href="/fleet" variant="outline">
                Check machine coverage
              </ActionButton>
            )}
          </div>
        </Surface>

        <Surface>
          <SectionLabel>Queue preview</SectionLabel>
          <h3 className="mt-1 text-xl font-semibold tracking-tight text-brand-dark">
            What needs attention now
          </h3>
          {props.requests.kind === "loading" ? (
            <div className="mt-4 space-y-3">
              <div className="guard-skeleton h-16 w-full" />
              <div className="guard-skeleton h-16 w-full" />
            </div>
          ) : props.requests.kind === "error" ? (
            <p className="mt-3 text-sm text-red-700">{props.requests.message}</p>
          ) : previewQueue.length === 0 ? (
            <EmptyState
              title="Inbox is clear"
              body="Guard has no blocked launches or changed tools waiting for review."
            />
          ) : (
            <div className="mt-4 space-y-3">
              {previewQueue.map((item) => (
                <div
                  key={item.request_id}
                  className="rounded-xl border border-border bg-white px-4 py-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">
                        {item.artifact_name}
                      </p>
                      <p className="mt-1 text-xs text-gray-500">
                        {item.harness} · {item.policy_action}
                      </p>
                    </div>
                    <ActionButton href={`/requests/${item.request_id}`} variant="outline">
                      Open
                    </ActionButton>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Surface>
      </div>

      <Surface>
        <div className="flex items-center justify-between gap-3">
          <div>
            <SectionLabel>Evidence preview</SectionLabel>
            <h3 className="mt-1 text-xl font-semibold tracking-tight text-brand-dark">
              Recent local proof
            </h3>
          </div>
          <ActionButton href="/evidence" variant="outline">
            Open evidence
          </ActionButton>
        </div>
        {props.receipts.kind === "loading" ? (
          <div className="mt-4 space-y-3">
            <div className="guard-skeleton h-16 w-full" />
            <div className="guard-skeleton h-16 w-full" />
          </div>
        ) : props.receipts.kind === "error" ? (
          <p className="mt-3 text-sm text-red-700">{props.receipts.message}</p>
        ) : previewReceipts.length === 0 ? (
          <div className="mt-4">
            <EmptyState
              title="No local proof yet"
              body="The first allow or block decision will appear here with the artifact fingerprint and saved context."
            />
          </div>
        ) : (
          <div className="mt-4 grid gap-3 lg:grid-cols-3">
            {previewReceipts.map((receipt) => (
              <div
                key={receipt.receipt_id}
                className="rounded-xl border border-border bg-white px-4 py-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <Badge
                    tone={
                      receipt.policy_decision === "allow"
                        ? "success"
                        : receipt.policy_decision === "block"
                          ? "destructive"
                          : "warning"
                    }
                  >
                    {receipt.policy_decision}
                  </Badge>
                  <Badge tone="info">{receipt.harness}</Badge>
                </div>
                <p className="mt-3 text-sm font-semibold text-brand-dark">
                  {receipt.artifact_name ?? receipt.artifact_id}
                </p>
                <p className="mt-1 text-xs text-gray-500">
                  {receipt.capabilities_summary || "No capabilities saved"}
                </p>
              </div>
            ))}
          </div>
        )}
      </Surface>
    </div>
  );
}

function MetricCard(props: { detail: string; label: string; value: string }) {
  return (
    <Surface className="p-4">
      <SectionLabel>{props.label}</SectionLabel>
      <p className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">
        {props.value}
      </p>
      <p className="mt-2 text-sm leading-6 text-gray-500">{props.detail}</p>
    </Surface>
  );
}
