import { useEffect, useState, type ReactNode } from "react";

import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt
} from "./guard-types";
import {
  ActionButton,
  EmptyState,
  KeyValueGrid,
  SectionEyebrow,
  ShellFooter,
  ShellHeader,
  StatusPill,
  Surface,
  Tag
} from "./approval-center-primitives";
import {
  buildPauseLine,
  buildRecommendation,
  profileItems,
  scopeLabel
} from "./approval-center-utils";

const scopeOptions = [
  { value: "artifact", title: "This version only", detail: "Trust only this exact fingerprint." },
  { value: "workspace", title: "This workspace", detail: "Remember it only for this project path." },
  { value: "publisher", title: "This publisher", detail: "Trust future versions from this publisher in this harness." },
  { value: "harness", title: "This harness", detail: "Stop prompting for similar launches here." },
  { value: "global", title: "Everywhere", detail: "Broadest rule. Use rarely." }
] as const;

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

export function ApprovalCenterLayout(props: {
  requests: RequestState;
  detail: DetailState;
  activeRequestId: string | null;
  resolutionMessage: string | null;
  onOpenRequest: (requestId: string) => void;
  onGoHome: () => void;
  onResolve: (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: string;
    workspace: string;
    reason: string;
  }) => Promise<void>;
}) {
  const queuedItems = props.requests.kind === "ready" ? props.requests.items : [];
  const activeHarness = props.detail.kind === "ready" ? props.detail.item.harness : queuedItems[0]?.harness ?? null;

  return (
    <div className="min-h-screen bg-transparent text-brand-dark">
      <ShellHeader queuedCount={queuedItems.length} activeHarness={activeHarness} />

      <main className="mx-auto w-[min(1240px,calc(100vw-32px))] py-6 sm:py-8">
        <TopStrip detail={props.detail} />

        <div className="mt-5 grid gap-5 lg:grid-cols-[320px_minmax(0,1fr)]">
          <QueuePanel requests={props.requests} activeRequestId={props.activeRequestId} onOpenRequest={props.onOpenRequest} />

          <div className="space-y-5">
            {props.resolutionMessage ? (
              <Surface tone="success">
                <p className="text-sm font-semibold text-brand-green-text">{props.resolutionMessage}</p>
              </Surface>
            ) : null}

            {props.detail.kind === "idle" ? (
              <Surface>
                <EmptyState
                  title="Nothing is waiting for a decision"
                  body="When a package, skill, or MCP server changes, Guard will place the blocked launch here with the exact drift and the safest trust rule."
                />
              </Surface>
            ) : (
              <DecisionWorkspace
                detail={props.detail}
                onGoHome={props.onGoHome}
                onResolve={props.onResolve}
              />
            )}
          </div>
        </div>
      </main>

      <ShellFooter />
    </div>
  );
}

function TopStrip(props: { detail: DetailState }) {
  if (props.detail.kind !== "ready") {
    return (
      <Surface className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-2">
          <SectionEyebrow>How this works</SectionEyebrow>
          <h1 className="text-[clamp(1.5rem,2.2vw,2.15rem)] font-semibold tracking-[-0.05em] text-brand-dark">
            Guard pauses the risky launch, shows the drift, and waits for one decision.
          </h1>
        </div>
        <KeyValueGrid
          columns={1}
          items={[
            ["Local workflow", "Review the drift, save a rule, rerun the harness."],
            ["Cloud optional", "Use hol.org only for sync, teams, alerts, and history."]
          ]}
        />
      </Surface>
    );
  }

  const { item } = props.detail;
  return (
    <Surface className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Tag tone="red">Paused launch</Tag>
          <Tag tone="green">{item.harness}</Tag>
          <Tag tone="slate">{item.source_scope}</Tag>
        </div>
        <div className="space-y-2">
          <h1 className="text-[clamp(1.55rem,2.4vw,2.2rem)] font-semibold tracking-[-0.05em] text-brand-dark">
            {item.artifact_name}
          </h1>
          <p className="max-w-3xl text-[0.95rem] leading-7 text-brand-dark/70">{buildPauseLine(item)}</p>
        </div>
        <div className="rounded-[20px] border border-slate-200/70 bg-slate-50/88 px-4 py-4">
          <p className="font-mono text-[11px] font-black uppercase tracking-[0.18em] text-brand-dark/48">CLI fallback</p>
          <code className="mt-2 block overflow-x-auto text-sm text-brand-dark/80">{item.review_command}</code>
        </div>
      </div>
      <KeyValueGrid
        columns={1}
        items={[
          ["Why Guard paused it", buildRecommendation(item)],
          ["Best starting scope", scopeLabel(item.recommended_scope)]
        ]}
      />
    </Surface>
  );
}

function QueuePanel(props: {
  requests: RequestState;
  activeRequestId: string | null;
  onOpenRequest: (requestId: string) => void;
}) {
  return (
        <Surface className="h-fit guard-delay-1">
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <SectionEyebrow>Approval queue</SectionEyebrow>
            <h2 className="mt-2 text-[1.55rem] font-semibold tracking-[-0.04em] text-brand-dark">Paused launches</h2>
          </div>
          {props.requests.kind === "ready" ? <StatusPill tone="neutral">{props.requests.items.length}</StatusPill> : null}
        </div>

        {props.requests.kind === "loading" ? <EmptyState title="Loading queue" body="Guard is reading the local approval queue." /> : null}
        {props.requests.kind === "error" ? <EmptyState title="Queue unavailable" body={props.requests.message} /> : null}
        {props.requests.kind === "ready" && props.requests.items.length === 0 ? (
          <EmptyState title="No blocked launches" body="Guard has not paused any launches right now." />
        ) : null}

        {props.requests.kind === "ready" && props.requests.items.length > 0 ? (
          <div className="space-y-2">
            {props.requests.items.map((item) => {
              const active = props.activeRequestId === item.request_id;
              return (
                <button
                  key={item.request_id}
                  type="button"
                  className={`block w-full rounded-[22px] border px-4 py-4 text-left transition-[border-color,background-color,transform,box-shadow] duration-200 hover:-translate-y-0.5 hover:shadow-[0_18px_32px_-24px_rgba(85,153,254,0.25)] ${
                    active
                      ? "border-brand-blue/25 bg-brand-blue/8"
                      : "border-slate-200/70 bg-slate-50/85 hover:border-brand-blue/18 hover:bg-white"
                  }`}
                  onClick={() => props.onOpenRequest(item.request_id)}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Tag tone="green">{item.harness}</Tag>
                    <Tag tone={item.policy_action === "block" ? "purple" : "blue"}>{item.policy_action}</Tag>
                  </div>
                  <strong className="mt-3 block text-[1rem] font-semibold tracking-[-0.03em] text-brand-dark">{item.artifact_name}</strong>
                  <p className="mt-2 text-sm leading-6 text-brand-dark/65">{item.changed_fields.join(", ")} changed</p>
                </button>
              );
            })}
          </div>
        ) : null}
      </div>
    </Surface>
  );
}

function DecisionWorkspace(props: {
  detail: DetailState;
  onGoHome: () => void;
  onResolve: (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: string;
    workspace: string;
    reason: string;
  }) => Promise<void>;
}) {
  const [scope, setScope] = useState("artifact");
  const [workspace, setWorkspace] = useState("");
  const [reason, setReason] = useState("approved in local approval center");
  const [submitting, setSubmitting] = useState<"allow" | "block" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (props.detail.kind === "ready") {
      setScope(props.detail.item.recommended_scope);
    }
  }, [props.detail]);

  if (props.detail.kind === "loading") {
    return (
      <Surface>
        <EmptyState title="Loading request" body="Guard is loading the diff, receipt, and saved policy for this launch." />
      </Surface>
    );
  }

  if (props.detail.kind === "error") {
    return (
      <Surface>
        <EmptyState title="Request unavailable" body={props.detail.message} />
      </Surface>
    );
  }

  if (props.detail.kind !== "ready") {
    return null;
  }

  const { item, diff, receipt, policy } = props.detail;
  const cards = profileItems(item, diff, receipt, policy);
  const submitDisabled = submitting !== null || (scope === "workspace" && workspace.trim().length === 0);

  async function handleResolve(action: "allow" | "block") {
    setSubmitting(action);
    setErrorMessage(null);
    try {
      await props.onResolve({
        requestId: item.request_id,
        action,
        scope,
        workspace,
        reason
      });
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "Unable to save decision.");
    } finally {
      setSubmitting(null);
    }
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
      <div className="space-y-5">
        <Surface className="guard-delay-1">
          <div className="space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="space-y-2">
                <SectionEyebrow>Blocked launch</SectionEyebrow>
                <h2 className="text-[2rem] font-semibold tracking-[-0.05em] text-brand-dark">{item.artifact_name}</h2>
                <p className="max-w-3xl text-sm leading-7 text-brand-dark/70">{buildPauseLine(item)}</p>
              </div>
              <ActionButton variant="secondary" onClick={props.onGoHome}>
                Back to queue
              </ActionButton>
            </div>

            <KeyValueGrid
              items={[
                ["Why it stopped", buildRecommendation(item)],
                ["Resume path", "Save a decision here, then rerun the same harness command."]
              ]}
            />
          </div>
        </Surface>

        <div className="grid gap-5 lg:grid-cols-2">
          <DetailCard title="Identity" body="What is trying to run right now.">
            <KeyValueGrid items={cards.identity} columns={1} />
          </DetailCard>
          <DetailCard title="Drift" body="What changed since the last trusted version.">
            <KeyValueGrid items={cards.drift} columns={1} />
          </DetailCard>
          <DetailCard title="Last trusted version" body="What Guard trusted before this launch.">
            <KeyValueGrid items={cards.trust} columns={1} />
          </DetailCard>
          <DetailCard title="Rule memory" body="What Guard will remember after you save.">
            <KeyValueGrid items={cards.memory} columns={1} />
          </DetailCard>
        </div>
      </div>

      <Surface className="h-fit guard-delay-2 lg:sticky lg:top-24" tone="accent">
        <div className="space-y-5">
          <div className="space-y-2">
            <SectionEyebrow>Decision</SectionEyebrow>
            <h3 className="text-[1.6rem] font-semibold tracking-[-0.04em] text-brand-dark">Choose the narrowest safe rule</h3>
            <p className="text-sm leading-7 text-brand-dark/68">
              Start narrow. You can widen trust later if the same artifact keeps reappearing.
            </p>
          </div>

          <div className="rounded-[20px] border border-brand-blue/14 bg-brand-blue/7 px-4 py-4">
            <p className="font-mono text-[11px] font-black uppercase tracking-[0.18em] text-brand-blue">Guard will remember</p>
            <p className="mt-2 text-sm leading-6 text-brand-dark/78">
              {submitting === "block"
                ? "This launch stays blocked until you review it again."
                : `Allow ${scopeLabel(scope).toLowerCase()} and let the harness continue after you rerun the command.`}
            </p>
          </div>

          <div className="space-y-2">
            {scopeOptions.map((option) => (
              <button
                key={option.value}
                type="button"
                className={`block w-full rounded-[20px] border px-4 py-4 text-left transition-[border-color,background-color,transform,box-shadow] duration-200 hover:-translate-y-0.5 hover:shadow-[0_18px_32px_-24px_rgba(85,153,254,0.22)] ${
                  scope === option.value
                    ? "border-brand-blue/24 bg-brand-blue/8"
                    : "border-slate-200/70 bg-white hover:border-slate-300"
                }`}
                onClick={() => setScope(option.value)}
              >
                <strong className="block text-sm font-semibold tracking-[-0.02em] text-brand-dark">{option.title}</strong>
                <span className="mt-1 block text-sm leading-6 text-brand-dark/62">{option.detail}</span>
              </button>
            ))}
          </div>

          {scope === "workspace" ? (
            <label className="block">
              <span className="mb-2 block text-sm font-semibold text-brand-dark">Workspace path</span>
              <input
                className="w-full rounded-[18px] border border-slate-200/70 bg-white px-4 py-3 text-sm text-brand-dark"
                value={workspace}
                onChange={(event) => setWorkspace(event.target.value)}
                placeholder="Required for workspace scope"
              />
            </label>
          ) : null}

          <label className="block">
            <span className="mb-2 block text-sm font-semibold text-brand-dark">Reason</span>
            <input
              className="w-full rounded-[18px] border border-slate-200/70 bg-white px-4 py-3 text-sm text-brand-dark"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>

          {errorMessage ? <p className="rounded-[18px] border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{errorMessage}</p> : null}

          <div className="grid gap-3 sm:grid-cols-2">
            <ActionButton onClick={() => void handleResolve("allow")} disabled={submitDisabled}>
              {submitting === "allow" ? "Saving…" : `Allow ${scopeLabel(scope).toLowerCase()}`}
            </ActionButton>
            <ActionButton variant="secondary" onClick={() => void handleResolve("block")} disabled={submitting !== null}>
              {submitting === "block" ? "Saving…" : "Block for now"}
            </ActionButton>
          </div>
        </div>
      </Surface>
    </div>
  );
}

function DetailCard(props: {
  title: string;
  body: string;
  children: ReactNode;
}) {
  return (
    <Surface className="guard-delay-2">
      <div className="space-y-4">
        <div className="space-y-1">
          <SectionEyebrow>{props.title}</SectionEyebrow>
          <p className="text-sm leading-6 text-brand-dark/68">{props.body}</p>
        </div>
        {props.children}
      </div>
    </Surface>
  );
}
