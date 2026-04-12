import { useState, useEffect, useCallback } from "react";

import {
  ShellHeader,
  ShellFooter,
  Surface,
  Badge,
  Tag,
  ActionButton,
  KeyValueGrid,
  EmptyState,
  WelcomeState,
  SectionLabel
} from "./approval-center-primitives";
import { ReceiptsWorkspace } from "./receipts-workspace";
import {
  buildPauseLine,
  buildRecommendation,
  buildQueueSummary,
  buildMemorySummary,
  buildStoppedReason,
  buildResumeInstruction,
  scopeLabel,
  policyActionLabel,
  artifactTypeLabel,
  shortConfigPath,
  buildTechnicalSummary,
  inferProjectFolder,
  humanizeChangedFields
} from "./approval-center-utils";
import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt,
  DecisionScope
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
type LayoutProps = {
  view: "queue" | "receipts";
  requests: RequestState;
  detail: DetailState;
  receipts: ReceiptsState;
  activeRequestId: string | null;
  resolutionMessage: string | null;
  onGoHome: () => void;
  onOpenRequest: (requestId: string) => void;
  onResolve: (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: DecisionScope;
    workspace?: string;
    reason: string;
  }) => void;
};

const scopeOptions: Array<{ value: DecisionScope; label: string; description: string }> = [
  { value: "artifact", label: "This exact version", description: "Only the current hash — any change triggers re-review." },
  { value: "workspace", label: "This project folder", description: "Trust this tool in the current workspace regardless of version." },
  { value: "publisher", label: "This publisher", description: "Trust all artifacts from this publisher in this harness." },
  { value: "harness", label: "This harness", description: "Trust all artifacts in this harness." },
  { value: "global", label: "All projects", description: "Trust this everywhere on this machine." }
];

const commonScopeValues = new Set<DecisionScope>(["artifact", "workspace"]);
export function ApprovalCenterLayout(props: LayoutProps) {
  const queuedItems = props.requests.kind === "ready" ? props.requests.items : [];
  const activeHarness =
    props.detail.kind === "ready" ? props.detail.item.harness : queuedItems[0]?.harness ?? null;
  return (
    <div className="flex min-h-screen flex-col bg-transparent text-brand-dark">
      <ShellHeader queuedCount={queuedItems.length} activeHarness={activeHarness} view={props.view} />
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 sm:py-8 lg:px-8">
        {props.view === "receipts" ? (
          <ReceiptsWorkspace receipts={props.receipts} />
        ) : (
          <QueueWorkspace
            requests={props.requests}
            detail={props.detail}
            activeRequestId={props.activeRequestId}
            resolutionMessage={props.resolutionMessage}
            onOpenRequest={props.onOpenRequest}
            onGoHome={props.onGoHome}
            onResolve={props.onResolve}
          />
        )}
      </main>
      <ShellFooter />
    </div>
  );
}

function QueueWorkspace(props: {
  requests: RequestState;
  detail: DetailState;
  activeRequestId: string | null;
  resolutionMessage: string | null;
  onOpenRequest: (requestId: string) => void;
  onGoHome: () => void;
  onResolve: LayoutProps["onResolve"];
}) {
  if (props.requests.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-8 w-64" />
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
  if (props.requests.items.length === 0) {
    return <WelcomeState resolutionMessage={props.resolutionMessage} />;
  }
  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[320px_1fr]">
      <aside className="space-y-2">
        <SectionLabel>Blocked items</SectionLabel>
        {props.requests.items.map((item) => (
          <QueueCard
            key={item.request_id}
            item={item}
            active={item.request_id === props.activeRequestId}
            onClick={() => props.onOpenRequest(item.request_id)}
          />
        ))}
      </aside>
      <div className="min-w-0">
        <DecisionWorkspace
          detail={props.detail}
          onGoHome={props.onGoHome}
          onResolve={props.onResolve}
        />
      </div>
    </div>
  );
}

function QueueCard(props: { item: GuardApprovalRequest; active: boolean; onClick: () => void }) {
  const summary = buildQueueSummary(props.item);
  const isFirstSeen = props.item.changed_fields.length === 1 && props.item.changed_fields[0] === "first_seen";
  const accentBorder = props.item.policy_action === "block" ? "border-l-brand-red" : isFirstSeen ? "border-l-brand-blue" : "border-l-brand-amber";
  return (
    <button
      type="button"
      onClick={props.onClick}
      className={`guard-surface-in w-full cursor-pointer rounded-xl border border-l-[3px] p-4 text-left transition-all duration-200 ${accentBorder} ${
        props.active
          ? "border-brand-blue/40 bg-brand-blue/5 shadow-md shadow-brand-blue/10"
          : "border-border bg-white shadow-sm hover:border-brand-dark/20 hover:shadow"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold text-brand-dark">{props.item.artifact_name}</p>
          <p className="mt-0.5 text-xs text-muted-foreground">{artifactTypeLabel(props.item.artifact_type)} · {props.item.harness}</p>
        </div>
        <PolicyBadge action={props.item.policy_action} />
      </div>
      <p className="mt-2 line-clamp-2 text-xs leading-relaxed text-muted-foreground">{summary}</p>
    </button>
  );
}
function DecisionWorkspace(props: {
  detail: DetailState;
  onGoHome: () => void;
  onResolve: LayoutProps["onResolve"];
}) {
  const [scope, setScope] = useState<DecisionScope>("artifact");
  const [reason, setReason] = useState("approved in local approval center");
  const [submitting, setSubmitting] = useState<"allow" | "block" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (props.detail.kind === "ready") {
      setScope(props.detail.item.recommended_scope);
      setErrorMessage(null);
      setSubmitting(null);
    }
  }, [props.detail]);
  const readyItem = props.detail.kind === "ready" ? props.detail.item : null;
  const readyRequestId = readyItem?.request_id ?? "";
  const readyWorkspace = readyItem?.workspace ?? undefined;

  const handleResolve = useCallback(
    async (action: "allow" | "block") => {
      setSubmitting(action);
      setErrorMessage(null);
      try {
        await props.onResolve({
          requestId: readyRequestId,
          action,
          scope,
          reason,
          workspace: scope === "workspace" ? readyWorkspace : undefined,
        });
      } catch (error) {
        setErrorMessage(error instanceof Error ? error.message : "Something went wrong.");
        setSubmitting(null);
      }
    },
    [props.onResolve, readyRequestId, readyWorkspace, reason, scope]
  );

  if (props.detail.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-8 w-48" />
        <div className="guard-skeleton h-40 w-full" />
        <div className="guard-skeleton h-56 w-full" />
      </div>
    );
  }
  if (props.detail.kind === "error") {
    return (
      <Surface tone="danger">
        <p className="text-sm text-red-700">{props.detail.message}</p>
        <ActionButton variant="outline" onClick={props.onGoHome}>Back to queue</ActionButton>
      </Surface>
    );
  }
  if (props.detail.kind === "idle") {
    return <EmptyState title="Select an item" body="Choose a blocked item from the sidebar to review the evidence and make a decision." />;
  }
  const { item, diff, receipt, policy } = props.detail;
  const commonScopeOpts = scopeOptions.filter((option) => commonScopeValues.has(option.value));
  const broadScopeOpts = scopeOptions.filter((option) => !commonScopeValues.has(option.value));
  return (
    <div className="guard-surface-in space-y-3">
      <ThreatHeader item={item} />
      <WhyGuardCares item={item} />
      <div className="pt-4">
        <WhatChanged item={item} diff={diff} receipt={receipt} policy={policy} />
      </div>
      <div className="pt-4">
        <RuleBuilder
          item={item}
          scope={scope}
          reason={reason}
          submitting={submitting}
          errorMessage={errorMessage}
          commonScopeOptions={commonScopeOpts}
          broadScopeOptions={broadScopeOpts}
          onScopeChange={setScope}
          onReasonChange={setReason}
          onResolve={handleResolve}
        />
      </div>
    </div>
  );
}

function ThreatHeader(props: { item: GuardApprovalRequest }) {
  const { item } = props;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Tag tone="blue">{artifactTypeLabel(item.artifact_type)}</Tag>
        <Tag tone="slate">{item.harness}</Tag>
        {item.publisher ? <Tag tone="purple">{item.publisher}</Tag> : null}
        <PolicyBadge action={item.policy_action} />
      </div>
      <h2 className="text-xl font-semibold tracking-tight text-brand-dark">{item.artifact_name}</h2>
      {item.risk_headline ? (
        <p className="text-sm font-medium text-red-700">{item.risk_headline}</p>
      ) : null}
      <p className="text-sm leading-relaxed text-brand-dark/70">{buildPauseLine(item)}</p>
    </div>
  );
}

function WhyGuardCares(props: { item: GuardApprovalRequest }) {
  const { item } = props;
  const signals = item.risk_signals ?? [];
  if (signals.length === 0 && !item.risk_summary && !item.why_now) return null;
  return (
    <Surface tone="danger">
      <SectionLabel>Why Guard cares</SectionLabel>
      {item.why_now ? <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">{item.why_now}</p> : null}
      {item.risk_summary ? <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">{item.risk_summary}</p> : null}
      {signals.length > 0 ? (
        <ul className="mt-2 space-y-1">
          {signals.map((signal) => (
            <li key={signal} className="flex items-start gap-2 text-sm text-red-800">
              <span className="mt-1 block h-1.5 w-1.5 flex-shrink-0 rounded-full bg-red-400" />
              <span className="font-mono text-[13px]">{signal}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </Surface>
  );
}

function WhatChanged(props: { item: GuardApprovalRequest; diff: GuardArtifactDiff | null; receipt: GuardReceipt | null; policy: GuardPolicyDecision[]; }) {
  const { item, diff, receipt, policy } = props;
  const evidenceRows: Array<[string, string]> = [
    ["Artifact ID", item.artifact_id],
    ["Hash", item.artifact_hash],
    ["Config", shortConfigPath(item.config_path)],
    ["Changed fields", item.changed_fields.length > 0 ? humanizeChangedFields(item.changed_fields) : "none"],
    ...(item.launch_target ? [["Launch target", item.launch_target] as [string, string]] : []),
    ...(item.transport ? [["Transport", item.transport] as [string, string]] : []),
    ...buildTechnicalSummary(diff, item)
  ];
  return (
    <details className="group" open>
      <summary className="flex cursor-pointer select-none items-center gap-2 text-sm font-medium text-brand-dark [&::-webkit-details-marker]:hidden">
        <span className="text-brand-blue transition-transform duration-200 group-open:rotate-90">▶</span>
        What changed & Previously trusted
      </summary>
      <div className="mt-3 space-y-3 pl-4 border-l-2 border-brand-blue/10">
        <p className="text-sm leading-relaxed text-brand-dark/70">{buildStoppedReason(item, receipt)}</p>
        <KeyValueGrid items={evidenceRows} columns={2} />
        {receipt ? (
          <Surface className="text-xs">
            <SectionLabel>What was previously trusted</SectionLabel>
            <p className="mt-1 text-brand-dark/70">{buildMemorySummary(item, receipt)}</p>
            <p className="mt-1 font-mono text-muted-foreground">
              {receipt.policy_decision} · {receipt.timestamp}
            </p>
          </Surface>
        ) : null}
      </div>
    </details>
  );
}

function RuleBuilder(props: {
  item: GuardApprovalRequest;
  scope: DecisionScope;
  reason: string;
  submitting: "allow" | "block" | null;
  errorMessage: string | null;
  commonScopeOptions: typeof scopeOptions;
  broadScopeOptions: typeof scopeOptions;
  onScopeChange: (scope: DecisionScope) => void;
  onReasonChange: (reason: string) => void;
  onResolve: (action: "allow" | "block") => void;
}) {
  const previewText = getRulePreviewText(props.item, props.scope);
  return (
    <Surface tone="accent">
      <SectionLabel>Rule Builder</SectionLabel>
      <p className="mt-1 text-sm leading-relaxed text-brand-dark/70">Select what happens if you allow this launch.</p>
      <fieldset className="mt-4 space-y-2">
        {props.commonScopeOptions.map((option) => (
          <ScopeOption
            key={option.value}
            value={option.value}
            label={option.label}
            description={option.description}
            checked={props.scope === option.value}
            onChange={() => props.onScopeChange(option.value)}
          />
        ))}
        <details className="pt-1">
          <summary className="cursor-pointer text-xs font-medium text-muted-foreground hover:text-brand-dark/70 [&::-webkit-details-marker]:hidden">
            ▶ Show broader scopes
          </summary>
          <div className="mt-2 space-y-2">
            {props.broadScopeOptions.map((option) => (
              <ScopeOption
                key={option.value}
                value={option.value}
                label={option.label}
                description={option.description}
                checked={props.scope === option.value}
                onChange={() => props.onScopeChange(option.value)}
              />
            ))}
          </div>
        </details>
      </fieldset>
      
      <div className="mt-4 rounded-md border border-brand-blue/20 bg-brand-blue/5 p-3">
        <p className="text-[11px] font-semibold tracking-widest text-brand-blue uppercase">Live Preview</p>
        <p className="mt-1 text-sm font-medium text-brand-dark">{previewText}</p>
        <p className="mt-1 text-xs text-muted-foreground">This rule is stored locally. Sign in to sync with Guard Cloud.</p>
      </div>

      <div className="mt-4">
        <label htmlFor="guard-reason" className="block text-xs font-medium text-muted-foreground">
          Reason for rule
        </label>
        <input
          id="guard-reason"
          type="text"
          value={props.reason}
          onChange={(e) => props.onReasonChange(e.target.value)}
          className="mt-1 h-9 w-full rounded-md border border-border bg-white px-3 text-sm text-brand-dark placeholder:text-muted-foreground focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 transition-colors"
          placeholder="Why are you allowing or blocking?"
        />
      </div>
      {props.errorMessage ? (
        <p className="guard-fade-in mt-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{props.errorMessage}</p>
      ) : null}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <ActionButton onClick={() => props.onResolve("allow")} disabled={props.submitting !== null}>
          {props.submitting === "allow" ? "Saving…" : `Allow and resume`}
        </ActionButton>
        <ActionButton variant="danger" onClick={() => props.onResolve("block")} disabled={props.submitting !== null}>
          {props.submitting === "block" ? "Saving…" : "Keep blocked"}
        </ActionButton>
      </div>
    </Surface>
  );
}

function getRulePreviewText(
  item: GuardApprovalRequest,
  scope: DecisionScope,
): string {
  if (scope === "artifact") {
    return `Allow this exact hash matching ${item.artifact_hash.substring(0, 8)}...`;
  }
  if (scope === "workspace") {
    return `Allow anything matching ${item.artifact_name} inside this project folder`;
  }
  return "Allow globally across local system";
}

function ScopeOption(props: {
  value: string;
  label: string;
  description: string;
  checked: boolean;
  onChange: () => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-all duration-150 ${
        props.checked
          ? "border-brand-blue/30 bg-blue-50/50 shadow-sm"
          : "border-border bg-white hover:border-brand-dark/20"
      }`}
    >
      <input
        type="radio"
        name="guard-scope"
        value={props.value}
        checked={props.checked}
        onChange={props.onChange}
        className="mt-0.5 accent-brand-blue"
      />
      <div>
        <span className="text-sm font-medium text-brand-dark">{props.label}</span>
        <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{props.description}</p>
      </div>
    </label>
  );
}

function PolicyBadge(props: { action: string }) {
  const tone =
    props.action === "block" ? "destructive" as const :
    props.action === "allow" ? "success" as const :
    "warning" as const;
  return <Badge tone={tone}>{policyActionLabel(props.action)}</Badge>;
}
