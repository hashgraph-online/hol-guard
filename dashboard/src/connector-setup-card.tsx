import { useCallback, useEffect, useState, type ReactNode } from "react";
import { HiMiniExclamationTriangle, HiMiniWrenchScrewdriver } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { approvalGateProofReady } from "./approval-proof-inline";
import {
  connectorItemCallCount,
  connectorSurfaceLabel,
  type ConnectorSetupGroup,
} from "./connector-setup-groups";
import { GUARD_REVIEW_INTENT_COPY } from "./guard-action";
import type { GuardApprovalGatePublicConfig, GuardApprovalRequest } from "./guard-types";
import { fetchLocalCliList, type LocalCliItem } from "./local-cli-api";
import { queueItemPreview } from "./review-queue-item";

const SETUP_COPY = GUARD_REVIEW_INTENT_COPY.setup;

const CLI_LIST_RETRY_DELAYS_MS = [2_000, 10_000];

/**
 * Read-only local tool list, used only to name each connector and link its
 * Protect page. It is fetched again whenever the set of connector identities
 * changes (`identityKey`, from `connectorSetupIdentityKey`) and retried after a
 * failed fetch, so a connector that appears while the Inbox is open is named too.
 */
export function useConnectorSetupClis(identityKey: string): LocalCliItem[] {
  const [items, setItems] = useState<LocalCliItem[]>([]);
  useEffect(() => {
    if (identityKey === "") return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const load = (attempt: number) => {
      fetchLocalCliList()
        .then((list) => {
          if (!cancelled) setItems([...list.items, ...list.seeded_items]);
        })
        .catch(() => {
          // Without the list the card still links to the Protect list; try again shortly.
          if (cancelled || attempt >= CLI_LIST_RETRY_DELAYS_MS.length) return;
          timer = setTimeout(() => load(attempt + 1), CLI_LIST_RETRY_DELAYS_MS[attempt]);
        });
    };
    load(0);
    return () => {
      cancelled = true;
      if (timer !== null) clearTimeout(timer);
    };
  }, [identityKey]);
  return items;
}

function connectorName(group: ConnectorSetupGroup): string {
  const name = group.cli?.display_name ?? group.cli?.name;
  return name && name.trim().length > 0 ? name : "a local tool";
}

function callCountCopy(count: number): string {
  return `${count} ${count === 1 ? "call" : "calls"} waiting on this`;
}

function Block(props: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">{props.label}</dt>
      <dd className="mt-1 text-sm leading-relaxed text-brand-dark">{props.children}</dd>
    </div>
  );
}

function EvidenceRow(props: {
  item: GuardApprovalRequest;
  active: boolean;
  onOpenRequest: (requestId: string) => void;
}) {
  const { item, onOpenRequest } = props;
  const handleOpen = useCallback(() => onOpenRequest(item.request_id), [item.request_id, onOpenRequest]);
  const repeats = connectorItemCallCount(item);
  return (
    <li>
      <button
        type="button"
        onClick={handleOpen}
        aria-current={props.active ? "true" : undefined}
        className={`flex min-h-11 w-full items-center justify-between gap-3 rounded-lg px-3 py-2 text-left transition-colors hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-brand-blue/20 ${
          props.active ? "bg-brand-blue/[0.06]" : ""
        }`}
      >
        <span className="min-w-0 truncate font-mono text-xs text-brand-dark">{queueItemPreview(item)}</span>
        {repeats > 1 && (
          <span className="shrink-0 text-[11px] font-medium text-muted-foreground">×{repeats}</span>
        )}
      </button>
    </li>
  );
}

export function ConnectorSetupCard(props: {
  group: ConnectorSetupGroup;
  approvalGate: GuardApprovalGatePublicConfig | null;
  activeRequestId: string | null;
  onOpenRequest: (requestId: string) => void;
}) {
  const { group } = props;
  const name = connectorName(group);
  const surface = connectorSurfaceLabel(group.cli?.surface ?? null);
  const gateReady = approvalGateProofReady(props.approvalGate);
  const doing = group.latest.trigger_summary ?? group.latest.why_now ?? null;
  const titleId = `connector-setup-${group.identityHash}`;
  const tone = group.caution
    ? "border-brand-attention/30 bg-brand-attention/[0.04]"
    : "border-brand-blue/20 bg-brand-blue/[0.04]";

  return (
    <section
      className={`rounded-2xl border p-4 ${tone}`}
      aria-labelledby={titleId}
      data-testid="connector-setup-card"
      data-connector-group={group.key}
    >
      <div className="flex items-start gap-3">
        <HiMiniWrenchScrewdriver className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" aria-hidden="true" />
        <div className="min-w-0 flex-1 space-y-3">
          <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{SETUP_COPY.label}</p>
              <h2 id={titleId} className="mt-1 text-sm font-semibold text-brand-dark">
                {SETUP_COPY.action}: {name}
              </h2>
            </div>
            <span className="text-xs font-medium text-muted-foreground">{callCountCopy(group.callCount)}</span>
          </div>
          <p className="text-sm leading-relaxed text-brand-dark/80">
            Guard does not recognise this {surface.toLowerCase()} and it is not set up on this device, so its calls
            are paused. {SETUP_COPY.scope}
          </p>
          <dl className="grid gap-3 sm:grid-cols-2">
            <Block label="What it is">
              {surface}
              {group.cli?.source_label ? ` · ${group.cli.source_label}` : " · seen only from agent calls"}
              <span className="mt-0.5 block font-mono text-xs text-muted-foreground">
                identity {group.identityHash.slice(0, 12)}
              </span>
            </Block>
            <Block label="What the agent was doing">
              {doing ?? "Running a command that uses this tool."}
              <span className="mt-0.5 block text-xs text-muted-foreground">
                {group.harnesses.join(", ")}
                {group.workspaceLabel ? ` · ${group.workspaceLabel}` : ""}
              </span>
            </Block>
            {group.triedCommands.length > 0 && (
              <Block label="What it tried to use">
                <span className="flex flex-wrap gap-1">
                  {group.triedCommands.map((command) => (
                    <code key={command} className="rounded bg-white px-1.5 py-0.5 font-mono text-xs text-brand-dark">
                      {command}
                    </code>
                  ))}
                </span>
              </Block>
            )}
          </dl>
          {group.caution && (
            <div className="flex items-start gap-2 rounded-lg border border-brand-attention/30 bg-white px-3 py-2" role="note">
              <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
              <p className="text-sm font-medium text-brand-attention">
                {group.cautionCount} of these calls {group.cautionCount === 1 ? "is" : "are"} destructive or touch
                sensitive data. Review each one before you set this tool up.
              </p>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            {gateReady ? (
              <ActionButton href={group.setupHref} variant={group.caution ? "outline" : "primary"}>
                Set up
              </ActionButton>
            ) : (
              <ActionButton href="/settings?section=approval" variant="outline">
                Set up approval password
              </ActionButton>
            )}
            {gateReady && (
              <ActionButton href={group.setupHref} variant="quiet">
                Block on this device
              </ActionButton>
            )}
          </div>
          {!gateReady && (
            <p className="text-xs text-slate-500">
              Setting up a tool needs an approval password so agents cannot change protection on their own.
            </p>
          )}
          <details className="group rounded-lg border border-slate-200/70 bg-white">
            <summary className="flex min-h-11 cursor-pointer items-center px-3 text-sm font-medium text-brand-blue">
              Review details ({group.items.length} {group.items.length === 1 ? "action" : "actions"})
            </summary>
            <ul className="space-y-0.5 border-t border-slate-100 p-1.5" aria-label={`Paused calls for ${name}`}>
              {group.items.map((item) => (
                <EvidenceRow
                  key={item.request_id}
                  item={item}
                  active={item.request_id === props.activeRequestId}
                  onOpenRequest={props.onOpenRequest}
                />
              ))}
            </ul>
          </details>
        </div>
      </div>
    </section>
  );
}

export function ConnectorSetupCards(props: {
  groups: ConnectorSetupGroup[];
  approvalGate: GuardApprovalGatePublicConfig | null;
  activeRequestId: string | null;
  onOpenRequest: (requestId: string) => void;
}) {
  if (props.groups.length === 0) return null;
  return (
    <div className="space-y-3" data-testid="connector-setup-cards">
      {props.groups.map((group) => (
        <ConnectorSetupCard
          key={group.key}
          group={group}
          approvalGate={props.approvalGate}
          activeRequestId={props.activeRequestId}
          onOpenRequest={props.onOpenRequest}
        />
      ))}
    </div>
  );
}
