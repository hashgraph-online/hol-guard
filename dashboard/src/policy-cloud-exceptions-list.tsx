import { useCallback, useMemo, useState, type ChangeEvent } from "react";
import { HiMiniChevronDown, HiMiniChevronRight, HiMiniChevronUp } from "react-icons/hi2";
import { Badge, EmptyState, Tag } from "./approval-center-primitives";
import { formatRelativeTime, harnessDisplayName, scopeLabel } from "./approval-center-utils";
import type { GuardCloudException } from "./guard-types";
import type { GuardCloudExceptionRequestItem } from "./guard-api";
import {
  isCloudExceptionAckFailure,
  resolveCloudExceptionExpiryTimestamp,
  resolveCloudExceptionExpiryValue,
  resolveCloudExceptionHeadline,
  resolvePersonDisplayLabel,
  resolvePersonInitials,
} from "./policy-cloud-exceptions-utils";

type PolicyCloudExceptionsListProps = {
  active: GuardCloudException[];
  pending: GuardCloudExceptionRequestItem[];
  expiringSoon: GuardCloudException[];
  selectedExceptionId: string | null;
  onSelectException: (exception: GuardCloudException) => void;
  cloudConnected: boolean;
  scopeFilter: string;
  actionFilter: string;
  onScopeFilterChange: (value: string) => void;
  onActionFilterChange: (value: string) => void;
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
      {open ? (
        <div className="space-y-2 border-t border-slate-100 px-3 py-3" role="list">
          {children}
        </div>
      ) : null}
    </section>
  );
}

function PersonAvatar({ label }: { label: string | null | undefined }) {
  const initials = resolvePersonInitials(label);
  return (
    <span
      aria-hidden="true"
      className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-[10px] font-semibold text-brand-blue"
      title={resolvePersonDisplayLabel(label)}
    >
      {initials}
    </span>
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
      role="listitem"
      onClick={handleSelect}
      aria-pressed={selected}
      className={`min-w-0 w-full rounded-xl border px-3.5 py-3 text-left transition ${
        selected
          ? "border-brand-blue/30 bg-brand-blue/[0.04] ring-1 ring-brand-blue/20"
          : "border-slate-100 bg-white hover:border-brand-blue/20 hover:bg-brand-blue/[0.02]"
      }`}
    >
      <div className="flex items-start gap-3">
        <div className="flex -space-x-2 pt-0.5">
          <PersonAvatar label={item.owner} />
          <PersonAvatar label={item.approver} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="success">{item.effect}</Badge>
            <Tag tone="slate">{scopeLabel(item.scope, "policy")}</Tag>
            {item.harness ? <Tag tone="slate">{harnessDisplayName(item.harness)}</Tag> : null}
            {isCloudExceptionAckFailure(item) ? <Badge tone="warning">Ack issue</Badge> : null}
          </div>
          <p className="mt-2 break-words text-sm font-semibold text-brand-dark">{headline}</p>
          <p className="mt-1 break-words text-xs text-slate-500">
            Owner {resolvePersonDisplayLabel(item.owner)}
            {expiryTimestamp && expiryValue ? ` · Expires ${formatRelativeTime(expiryValue)}` : null}
            {item.last_used_at ? ` · Last used ${formatRelativeTime(item.last_used_at)}` : null}
          </p>
        </div>
        <HiMiniChevronRight
          className={`mt-1 h-4 w-4 shrink-0 ${selected ? "text-brand-blue" : "text-slate-300"}`}
          aria-hidden="true"
        />
      </div>
    </button>
  );
}

function PendingRequestCard({ item }: { item: GuardCloudExceptionRequestItem }) {
  return (
    <article className="min-w-0 rounded-xl border border-amber-100 bg-amber-50/40 px-3.5 py-3" role="listitem">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="warning">Pending</Badge>
        <Tag tone="slate">{scopeLabel(item.scope, "policy")}</Tag>
      </div>
      <p className="mt-2 break-words text-sm font-semibold text-brand-dark">{item.reason}</p>
      <p className="mt-1 break-words text-xs text-slate-600">
        Requested by {resolvePersonDisplayLabel(item.owner)} · expires{" "}
        {formatRelativeTime(item.requestedExpiresAt)}
      </p>
    </article>
  );
}

function ExceptionFilters({
  scopeFilter,
  actionFilter,
  onScopeFilterChange,
  onActionFilterChange,
}: {
  scopeFilter: string;
  actionFilter: string;
  onScopeFilterChange: (value: string) => void;
  onActionFilterChange: (value: string) => void;
}) {
  const handleScopeChange = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => {
      onScopeFilterChange(event.target.value);
    },
    [onScopeFilterChange],
  );
  const handleActionChange = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => {
      onActionFilterChange(event.target.value);
    },
    [onActionFilterChange],
  );

  return (
    <div className="flex flex-wrap gap-2">
      <label className="text-sm text-slate-600">
        <span className="sr-only">Filter by scope</span>
        <select
          value={scopeFilter}
          onChange={handleScopeChange}
          className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark"
          aria-label="All scopes"
        >
          <option value="all">All scopes</option>
          <option value="artifact">Artifact</option>
          <option value="publisher">Publisher</option>
          <option value="harness">Harness</option>
          <option value="workspace">Workspace</option>
          <option value="global">Global</option>
        </select>
      </label>
      <label className="text-sm text-slate-600">
        <span className="sr-only">Filter by action</span>
        <select
          value={actionFilter}
          onChange={handleActionChange}
          className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark"
          aria-label="All actions"
        >
          <option value="all">All actions</option>
          <option value="allow">Allow</option>
        </select>
      </label>
    </div>
  );
}

function matchesFilters(item: GuardCloudException, scopeFilter: string, actionFilter: string): boolean {
  if (scopeFilter !== "all" && item.scope !== scopeFilter) {
    return false;
  }
  if (actionFilter !== "all" && item.effect !== actionFilter) {
    return false;
  }
  return true;
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
  scopeFilter,
  actionFilter,
  onScopeFilterChange,
  onActionFilterChange,
}: PolicyCloudExceptionsListProps) {
  const filterActive = useCallback(
    (items: GuardCloudException[]) => items.filter((item) => matchesFilters(item, scopeFilter, actionFilter)),
    [scopeFilter, actionFilter],
  );

  const expiringSoonIds = useMemo(() => new Set(expiringSoon.map((item) => item.id)), [expiringSoon]);
  const filteredActive = useMemo(() => filterActive(active), [active, filterActive]);
  const filteredExpiringSoon = useMemo(() => filterActive(expiringSoon), [expiringSoon, filterActive]);
  const activeWithoutExpiringGroup = useMemo(
    () => filteredActive.filter((item) => !expiringSoonIds.has(item.id)),
    [filteredActive, expiringSoonIds],
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

  const hasFilteredRows =
    activeWithoutExpiringGroup.length > 0 || pending.length > 0 || filteredExpiringSoon.length > 0;

  return (
    <div className="space-y-3" aria-label="Cloud exception groups">
      <ExceptionFilters
        scopeFilter={scopeFilter}
        actionFilter={actionFilter}
        onScopeFilterChange={onScopeFilterChange}
        onActionFilterChange={onActionFilterChange}
      />

      {!hasFilteredRows ? (
        <EmptyState
          title="No exceptions match these filters"
          body="Try a broader scope or action filter to see synced Cloud exceptions."
          tone="teach"
        />
      ) : (
        <>
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

          {filteredExpiringSoon.length > 0 ? (
            <GroupSection
              title="Expiring soon"
              description="Active acceptances nearing expiry. Renew or revoke them in Guard Cloud."
              defaultOpen
            >
              {filteredExpiringSoon.map((item) => (
                <ExceptionCard
                  key={`expiring-${item.id}`}
                  item={item}
                  selected={selectedExceptionId === item.id}
                  onSelect={onSelectException}
                />
              ))}
            </GroupSection>
          ) : null}
        </>
      )}
    </div>
  );
}
