import { useCallback, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { HiMiniChevronDown, HiMiniChevronUp } from "react-icons/hi2";
import { Badge, EmptyState, Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { GuardCloudException } from "./guard-types";
import type { GuardCloudExceptionRequestItem } from "./guard-api";
import {
  isCloudExceptionAckFailure,
  parseCloudExceptionTimestamp,
  resolveCloudExceptionHeadline,
  resolveCloudExceptionExpiryTimestamp,
  resolveCloudExceptionExpiryValue,
  resolvePersonDisplayLabel,
} from "./policy-cloud-exceptions-utils";
import { policyScopeLabel } from "./policy-workspace-helpers";

type PolicyCloudExceptionsListProps = {
  active: GuardCloudException[];
  pending: GuardCloudExceptionRequestItem[];
  expiringSoon: GuardCloudException[];
  selectedExceptionId: string | null;
  onSelectException: (exception: GuardCloudException) => void;
  cloudConnected: boolean;
};

type GroupSectionProps = {
  title: string;
  description: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
};

function GroupSection({ title, description, defaultOpen = true, children }: GroupSectionProps) {
  const [open, setOpen] = useState(defaultOpen);
  const handleToggle = useCallback(() => {
    setOpen((current) => !current);
  }, []);

  return (
    <section className="rounded-2xl border border-slate-100 bg-white shadow-sm" aria-label={title}>
      <button
        type="button"
        onClick={handleToggle}
        className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left"
        aria-expanded={open}
        aria-label={`${title} group`}
      >
        <div>
          <h3 className="text-sm font-semibold text-brand-dark">{title}</h3>
          <p className="mt-0.5 text-xs text-slate-500">{description}</p>
        </div>
        {open ? (
          <HiMiniChevronUp className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
        ) : (
          <HiMiniChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
        )}
      </button>
      {open ? <div className="space-y-2 border-t border-slate-100 px-3 py-3">{children}</div> : null}
    </section>
  );
}

function ExceptionCard({
  item,
  selected,
  onSelect,
}: {
  item: GuardCloudException;
  selected: boolean;
  onSelect: (item: GuardCloudException) => void;
}) {
  const handleSelect = useCallback(() => {
    onSelect(item);
  }, [item, onSelect]);

  const expiryTimestamp = resolveCloudExceptionExpiryTimestamp(item);
  const expiryValue = resolveCloudExceptionExpiryValue(item);
  const headline = resolveCloudExceptionHeadline(item);

  return (
    <button
      type="button"
      onClick={handleSelect}
      aria-pressed={selected}
      className={`min-w-0 w-full rounded-xl border px-3.5 py-3 text-left transition ${
        selected
          ? "border-brand-blue/30 bg-brand-blue/[0.04] ring-1 ring-brand-blue/20"
          : "border-slate-100 bg-white hover:border-brand-blue/20 hover:bg-brand-blue/[0.02]"
      }`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="success">{item.effect}</Badge>
        <Tag tone="slate">{policyScopeLabel(item.scope)}</Tag>
        {isCloudExceptionAckFailure(item) ? <Badge tone="warning">Ack issue</Badge> : null}
      </div>
      <p className="mt-2 break-words text-sm font-semibold text-brand-dark">{headline}</p>
      <p className="mt-1 break-words text-xs text-slate-500">
        Owner {resolvePersonDisplayLabel(item.owner)}
        {expiryTimestamp && expiryValue ? ` · expires ${formatRelativeTime(expiryValue)}` : null}
      </p>
    </button>
  );
}

function PendingRequestCard({ item }: { item: GuardCloudExceptionRequestItem }) {
  return (
    <article className="min-w-0 rounded-xl border border-amber-100 bg-amber-50/40 px-3.5 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="warning">Pending</Badge>
        <Tag tone="slate">{policyScopeLabel(item.scope)}</Tag>
      </div>
      <p className="mt-2 break-words text-sm font-semibold text-brand-dark">{item.reason}</p>
      <p className="mt-1 break-words text-xs text-slate-600">
        Requested by {resolvePersonDisplayLabel(item.owner)} · expires{" "}
        {formatRelativeTime(item.requestedExpiresAt)}
      </p>
    </article>
  );
}

export function PolicyCloudExceptionsListSkeleton() {
  return (
    <div className="space-y-3" aria-busy="true" aria-label="Loading Cloud exceptions">
      {[0, 1, 2].map((index) => (
        <div key={index} className="h-28 animate-pulse rounded-2xl border border-slate-100 bg-slate-100" />
      ))}
    </div>
  );
}

export function PolicyCloudExceptionsList({
  active,
  pending,
  expiringSoon,
  selectedExceptionId,
  onSelectException,
  cloudConnected,
}: PolicyCloudExceptionsListProps) {
  const expiringSoonIds = useMemo(() => new Set(expiringSoon.map((item) => item.id)), [expiringSoon]);
  const activeWithoutExpiringGroup = useMemo(
    () => active.filter((item) => !expiringSoonIds.has(item.id)),
    [active, expiringSoonIds],
  );

  if (!cloudConnected) {
    return null;
  }

  const hasAnyRows = active.length > 0 || pending.length > 0;

  if (!hasAnyRows) {
    return (
      <EmptyState
        title="No Cloud exceptions synced yet"
        body="Approved Cloud risk acceptances will appear here after Guard Cloud syncs a signed policy bundle to this device."
        tone="teach"
      />
    );
  }

  return (
    <div className="space-y-3" role="list" aria-label="Cloud exception groups">
      {activeWithoutExpiringGroup.length > 0 ? (
        <GroupSection
          title="Active on this device"
          description="Synced Cloud risk acceptances currently enforced locally."
          defaultOpen
        >
          {activeWithoutExpiringGroup.map((item) => (
            <ExceptionCard
              key={item.id}
              item={item}
              selected={selectedExceptionId === item.id}
              onSelect={onSelectException}
            />
          ))}
        </GroupSection>
      ) : null}

      {pending.length > 0 ? (
        <GroupSection
          title="Pending in Guard Cloud"
          description="Requests waiting for Cloud approval before they can sync to this device."
          defaultOpen
        >
          {pending.map((item) => (
            <PendingRequestCard key={item.requestId} item={item} />
          ))}
        </GroupSection>
      ) : null}

      {expiringSoon.length > 0 ? (
        <GroupSection
          title="Expiring soon"
          description="Active acceptances nearing expiry. Renew or revoke them in Guard Cloud."
          defaultOpen
        >
          {expiringSoon.map((item) => (
            <ExceptionCard
              key={`expiring-${item.id}`}
              item={item}
              selected={selectedExceptionId === item.id}
              onSelect={onSelectException}
            />
          ))}
        </GroupSection>
      ) : null}
    </div>
  );
}
