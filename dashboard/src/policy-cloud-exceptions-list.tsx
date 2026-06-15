import { useCallback, useMemo, useState, type ChangeEvent } from "react";
import {
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniChevronRight,
  HiMiniChevronUp,
  HiMiniCommandLine,
  HiMiniFolder,
  HiMiniGlobeAlt,
  HiMiniMagnifyingGlass,
  HiMiniPuzzlePiece,
} from "react-icons/hi2";
import { Badge, EmptyState, Tag } from "./approval-center-primitives";
import { formatRelativeTime, harnessDisplayName, scopeLabel } from "./approval-center-utils";
import type { GuardCloudException } from "./guard-types";
import type { GuardCloudExceptionRequestItem } from "./guard-api";
import {
  isCloudExceptionAckFailure,
  resolveCloudExceptionEffectLabel,
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

const EXCEPTION_ROW_GRID =
  "grid grid-cols-[minmax(0,1fr)] items-center gap-x-2 gap-y-2 border-b border-slate-100 px-3 py-2.5 last:border-0 hover:bg-slate-50/80 md:grid-cols-[72px_minmax(140px,1.3fr)_88px_72px_36px_36px_88px_80px_72px]";

const EXCEPTION_HEADER_GRID =
  "hidden border-b border-slate-100 bg-slate-50/80 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500 md:grid md:grid-cols-[72px_minmax(140px,1.3fr)_88px_72px_36px_36px_88px_80px_72px] md:gap-x-2";

function resolveAckStatusLabel(item: GuardCloudException): { label: string; tone: "success" | "warning" | "default" } {
  if (item.ack_status === "synced") {
    return { label: "Ack OK", tone: "success" };
  }
  if (isCloudExceptionAckFailure(item)) {
    return { label: "Ack issue", tone: "warning" };
  }
  if (item.ack_status === "pending") {
    return { label: "Pending", tone: "default" };
  }
  return { label: "Unknown", tone: "default" };
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

function resolveRowIcon(scope: GuardCloudException["scope"]) {
  if (scope === "artifact") {
    return HiMiniCommandLine;
  }
  if (scope === "publisher" || scope === "workspace") {
    return HiMiniFolder;
  }
  if (scope === "harness") {
    return HiMiniPuzzlePiece;
  }
  return HiMiniGlobeAlt;
}

function ExceptionTableRow({
  item,
  selected,
  onSelect,
}: {
  item: GuardCloudException;
  selected: boolean;
  onSelect: (item: GuardCloudException) => void;
}) {
  const handleSelect = useCallback(() => onSelect(item), [item, onSelect]);
  const expiryValue = resolveCloudExceptionExpiryValue(item);
  const headline = resolveCloudExceptionHeadline(item);
  const ackStatus = resolveAckStatusLabel(item);
  const effectLabel = resolveCloudExceptionEffectLabel(item.effect);
  const RowIcon = resolveRowIcon(item.scope);

  return (
    <button
      type="button"
      role="listitem"
      onClick={handleSelect}
      aria-pressed={selected}
      className={`min-w-0 w-full text-left transition ${EXCEPTION_ROW_GRID} ${
        selected ? "bg-brand-blue/[0.04] ring-1 ring-inset ring-brand-blue/20" : ""
      }`}
    >
      <div className="flex items-center gap-2 md:col-start-1">
        <RowIcon className="hidden h-4 w-4 shrink-0 text-slate-400 md:block" aria-hidden="true" />
        <Badge tone="success">{effectLabel}</Badge>
      </div>
      <div className="min-w-0 md:col-start-2">
        <p className="truncate text-sm font-semibold text-brand-dark">{headline}</p>
        <div className="mt-1 flex flex-wrap gap-2 text-xs text-slate-500 md:hidden">
          <span>{scopeLabel(item.scope, "policy")}</span>
          {item.harness ? <span>{harnessDisplayName(item.harness)}</span> : null}
        </div>
      </div>
      <div className="hidden md:col-start-3 md:block">
        <Tag tone="blue">{scopeLabel(item.scope, "policy")}</Tag>
      </div>
      <div className="hidden truncate text-sm text-brand-dark md:col-start-4 md:block">
        {item.harness ? harnessDisplayName(item.harness) : "—"}
      </div>
      <div className="hidden md:col-start-5 md:flex md:justify-center">
        <PersonAvatar label={item.owner} />
      </div>
      <div className="hidden md:col-start-6 md:flex md:justify-center">
        <PersonAvatar label={item.approver} />
      </div>
      <div className="hidden whitespace-nowrap text-xs text-slate-500 md:col-start-7 md:block">
        {expiryValue ? formatRelativeTime(expiryValue) : "—"}
      </div>
      <div className="hidden whitespace-nowrap text-xs text-slate-500 md:col-start-8 md:block">
        {item.last_used_at ? formatRelativeTime(item.last_used_at) : "—"}
      </div>
      <div className="hidden md:col-start-9 md:flex md:items-center md:gap-1">
        {ackStatus.tone === "success" ? (
          <HiMiniCheckCircle className="h-3.5 w-3.5 text-emerald-600" aria-hidden="true" />
        ) : null}
        <Badge tone={ackStatus.tone}>{ackStatus.label}</Badge>
        <HiMiniChevronRight className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
      </div>
    </button>
  );
}

function PendingRequestRow({ item }: { item: GuardCloudExceptionRequestItem }) {
  return (
    <article className={`${EXCEPTION_ROW_GRID} bg-amber-50/30`} role="listitem">
      <div className="md:col-start-1">
        <Badge tone="warning">Pending</Badge>
      </div>
      <div className="min-w-0 md:col-start-2 md:col-span-8">
        <p className="break-words text-sm font-semibold text-brand-dark">{item.reason}</p>
        <p className="mt-0.5 text-xs text-slate-600">
          {scopeLabel(item.scope, "policy")} · {resolvePersonDisplayLabel(item.owner)} · expires{" "}
          {formatRelativeTime(item.requestedExpiresAt)}
        </p>
      </div>
    </article>
  );
}

function GroupSection({
  title,
  count,
  defaultOpen = true,
  children,
}: {
  title: string;
  count: number;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const handleToggle = useCallback(() => setOpen((current) => !current), []);

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm" aria-label={title}>
      <button
        type="button"
        onClick={handleToggle}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
        aria-expanded={open}
      >
        <h3 className="text-sm font-semibold text-brand-dark">
          {title} ({count})
        </h3>
        {open ? (
          <HiMiniChevronUp className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
        ) : (
          <HiMiniChevronDown className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
        )}
      </button>
      {open ? (
        <div className="border-t border-slate-100">
          <div className={EXCEPTION_HEADER_GRID} aria-hidden="true">
            <span>Action</span>
            <span>Description</span>
            <span>Scope</span>
            <span>App</span>
            <span className="text-center">Owner</span>
            <span className="text-center">Approver</span>
            <span>Expires</span>
            <span>Last used</span>
            <span>Status</span>
          </div>
          <div role="list">{children}</div>
        </div>
      ) : null}
    </section>
  );
}

function ExceptionFilters({
  searchQuery,
  onSearchChange,
  scopeFilter,
  actionFilter,
  onScopeFilterChange,
  onActionFilterChange,
}: {
  searchQuery: string;
  onSearchChange: (value: string) => void;
  scopeFilter: string;
  actionFilter: string;
  onScopeFilterChange: (value: string) => void;
  onActionFilterChange: (value: string) => void;
}) {
  const handleSearchChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => onSearchChange(event.target.value),
    [onSearchChange],
  );
  const handleScopeChange = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => onScopeFilterChange(event.target.value),
    [onScopeFilterChange],
  );
  const handleActionChange = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => onActionFilterChange(event.target.value),
    [onActionFilterChange],
  );

  return (
    <div className="flex flex-col gap-2 lg:flex-row lg:items-center">
      <div className="flex flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2">
        <HiMiniMagnifyingGlass className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
        <input
          type="search"
          placeholder="Search exceptions…"
          value={searchQuery}
          onChange={handleSearchChange}
          aria-label="Search exceptions"
          className="w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
        />
      </div>
      <div className="flex flex-wrap gap-2">
        <select
          value={scopeFilter}
          onChange={handleScopeChange}
          className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark"
          aria-label="All scopes"
        >
          <option value="all">All scopes</option>
          <option value="artifact">Once</option>
          <option value="publisher">This cwd</option>
          <option value="workspace">This project</option>
          <option value="harness">This harness</option>
          <option value="global">Team policy</option>
        </select>
        <select
          value={actionFilter}
          onChange={handleActionChange}
          className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark"
          aria-label="All actions"
        >
          <option value="all">All actions</option>
          <option value="allow">Allow</option>
        </select>
      </div>
    </div>
  );
}

function matchesFilters(
  item: GuardCloudException,
  scopeFilter: string,
  actionFilter: string,
  searchQuery: string,
): boolean {
  if (scopeFilter !== "all" && item.scope !== scopeFilter) {
    return false;
  }
  if (actionFilter !== "all" && item.effect !== actionFilter) {
    return false;
  }
  const query = searchQuery.trim().toLowerCase();
  if (!query) {
    return true;
  }
  const haystack = [
    resolveCloudExceptionHeadline(item),
    item.owner,
    item.approver,
    item.harness,
    item.scope,
    item.source_receipt_id,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(query);
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
  const [searchQuery, setSearchQuery] = useState("");

  const filterActive = useCallback(
    (items: GuardCloudException[]) =>
      items.filter((item) => matchesFilters(item, scopeFilter, actionFilter, searchQuery)),
    [scopeFilter, actionFilter, searchQuery],
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
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        scopeFilter={scopeFilter}
        actionFilter={actionFilter}
        onScopeFilterChange={onScopeFilterChange}
        onActionFilterChange={onActionFilterChange}
      />

      {!hasFilteredRows ? (
        <EmptyState
          title="No exceptions match these filters"
          body="Try a broader search, scope, or action filter to see synced Cloud exceptions."
          tone="teach"
        />
      ) : (
        <>
          {activeWithoutExpiringGroup.length > 0 ? (
            <GroupSection title="Active on this device" count={activeWithoutExpiringGroup.length} defaultOpen>
              {activeWithoutExpiringGroup.map((item) => (
                <ExceptionTableRow
                  key={item.id}
                  item={item}
                  selected={selectedExceptionId === item.id}
                  onSelect={onSelectException}
                />
              ))}
            </GroupSection>
          ) : null}

          {pending.length > 0 ? (
            <GroupSection title="Pending in Guard Cloud" count={pending.length} defaultOpen={false}>
              {pending.map((item) => (
                <PendingRequestRow key={item.requestId} item={item} />
              ))}
            </GroupSection>
          ) : null}

          {filteredExpiringSoon.length > 0 ? (
            <GroupSection title="Expiring soon" count={filteredExpiringSoon.length} defaultOpen={false}>
              {filteredExpiringSoon.map((item) => (
                <ExceptionTableRow
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
