import {
  HiMiniCheckCircle,
  HiMiniCloudArrowUp,
  HiMiniDocumentText,
  HiMiniXMark,
} from "react-icons/hi2";
import { ActionButton, Badge, SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime, scopeLabel } from "./approval-center-utils";
import type { GuardCloudException } from "./guard-types";
import {
  isCloudExceptionAckFailure,
  isCloudExceptionActive,
  resolveCloudExceptionBlastRadius,
  resolveCloudExceptionEffectLabel,
  resolveCloudExceptionEvidenceUrl,
  resolveCloudExceptionExpiryTimestamp,
  resolveCloudExceptionExpiryValue,
  resolveCloudExceptionHeadline,
  resolveCloudExceptionScopePath,
  resolveCloudExceptionWhyCopy,
  resolvePersonDisplayLabel,
  resolvePersonInitials,
} from "./policy-cloud-exceptions-utils";

type PolicyCloudExceptionDetailPanelProps = {
  exception: GuardCloudException;
  cloudControlsUrl: string | null;
  onClose: () => void;
};

function PersonRow({
  label,
  value,
}: {
  label: string;
  value: string | null | undefined;
}) {
  const display = resolvePersonDisplayLabel(value);
  const initials = resolvePersonInitials(value);
  return (
    <div className="flex items-center gap-3">
      <span
        aria-hidden="true"
        className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-xs font-semibold text-brand-blue"
      >
        {initials}
      </span>
      <div className="min-w-0">
        <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
        <p className="break-words text-sm font-medium text-brand-dark">{display}</p>
      </div>
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value) {
    return null;
  }
  return (
    <div>
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 break-all text-sm text-brand-dark">{value}</p>
    </div>
  );
}

function resolveAckCopy(item: GuardCloudException): { label: string; detail: string } {
  if (item.ack_status === "synced") {
    return { label: "Acknowledged", detail: "This device acknowledged the signed policy bundle." };
  }
  if (item.ack_status === "pending") {
    return { label: "Pending ack", detail: "Waiting for this device to acknowledge the signed bundle on next sync." };
  }
  if (item.ack_status === "failed") {
    return {
      label: "Ack failed",
      detail: item.rejection_reason?.trim() || "The local daemon could not acknowledge this exception bundle.",
    };
  }
  if (item.ack_status === "offline") {
    return {
      label: "Offline",
      detail: "This device was offline when the signed bundle was issued.",
    };
  }
  return { label: "Unknown", detail: "Local acknowledgement status is unavailable." };
}

function ExpiryTimeline({
  expiryTimestamp,
  expiryValue,
}: {
  expiryTimestamp: Date | null;
  expiryValue: string | null;
}) {
  if (!expiryTimestamp || !expiryValue) {
    return null;
  }
  return (
    <div className="mt-3">
      <div className="flex items-center justify-between text-[11px] font-medium text-slate-500">
        <span>Approved</span>
        <span>Expires {formatRelativeTime(expiryValue)}</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-200">
        <div className="h-full w-full animate-pulse rounded-full bg-brand-blue/40" aria-hidden="true" />
      </div>
      <p className="mt-2 text-xs text-slate-600">{expiryTimestamp.toLocaleString()}</p>
    </div>
  );
}

function blastRadiusBadgeTone(tone: ReturnType<typeof resolveCloudExceptionBlastRadius>["tone"]) {
  if (tone === "narrow") {
    return "success" as const;
  }
  if (tone === "medium") {
    return "warning" as const;
  }
  return "destructive" as const;
}

export function PolicyCloudExceptionDetailPanel({
  exception,
  cloudControlsUrl,
  onClose,
}: PolicyCloudExceptionDetailPanelProps) {
  const expiryTimestamp = resolveCloudExceptionExpiryTimestamp(exception);
  const expiryValue = resolveCloudExceptionExpiryValue(exception);
  const ackCopy = resolveAckCopy(exception);
  const headline = resolveCloudExceptionHeadline(exception);
  const blast = resolveCloudExceptionBlastRadius(exception.scope);
  const whyCopy = resolveCloudExceptionWhyCopy(exception);
  const isActive = isCloudExceptionActive(exception);
  const isEnforcedLocally = exception.ack_status === "synced";
  const evidenceUrl = resolveCloudExceptionEvidenceUrl(exception);
  const scopePath = resolveCloudExceptionScopePath(exception);
  const effectLabel = resolveCloudExceptionEffectLabel(exception.effect);

  return (
    <aside
      className="min-w-0 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm lg:sticky lg:top-4"
      aria-label="Cloud exception details"
    >
      <div className="mb-4 flex min-w-0 items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <SectionLabel>Temporary cloud exception</SectionLabel>
          <h3 className="mt-1 break-words text-lg font-semibold text-brand-dark">{headline}</h3>
          <p className="mt-1 text-sm text-slate-600">{effectLabel}</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-brand-dark"
          aria-label="Close exception detail"
        >
          <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
        </button>
      </div>

      <div className="mb-4 flex flex-wrap gap-2">
        {isActive ? <Badge tone="success">Active</Badge> : <Badge tone="default">Expired</Badge>}
        {isEnforcedLocally ? <Tag tone="slate">Enforced locally</Tag> : null}
        <Badge tone="success">{effectLabel}</Badge>
        {!isEnforcedLocally ? <Badge tone="warning">{ackCopy.label}</Badge> : null}
      </div>

      <div className="space-y-4">
        <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Why this exists</p>
          <p className="mt-2 text-sm leading-relaxed text-brand-dark">{whyCopy}</p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Blast radius</p>
            <div className="mt-2">
              <Badge tone={blastRadiusBadgeTone(blast.tone)}>{blast.label}</Badge>
            </div>
            <p className="mt-2 text-sm text-slate-600">{blast.detail}</p>
          </div>
          <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Scope (exact)</p>
            <div className="mt-2">
              <Tag tone="blue">{scopeLabel(exception.scope, "policy")}</Tag>
            </div>
            {scopePath ? <p className="mt-2 break-all text-sm text-slate-600">{scopePath}</p> : null}
          </div>
        </div>

        {evidenceUrl ? (
          <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Source review item</p>
            <p className="mt-2 text-sm font-medium text-brand-dark">
              {exception.source_receipt_id?.trim() ?? "Linked approval record"}
            </p>
            <div className="mt-3">
              <ActionButton href={evidenceUrl} variant="secondary">
                Open in Review
              </ActionButton>
            </div>
          </div>
        ) : null}

        <PersonRow label="Owner" value={exception.owner} />
        <PersonRow label="Approved by" value={exception.approver} />

        <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Expiry timeline</p>
          <p className="mt-2 text-sm text-brand-dark">
            {expiryTimestamp && expiryValue
              ? `${expiryTimestamp.toLocaleString()} (${formatRelativeTime(expiryValue)})`
              : expiryValue ?? "Expiry unavailable"}
          </p>
          <ExpiryTimeline expiryTimestamp={expiryTimestamp} expiryValue={expiryValue} />
          <DetailField
            label="Last used"
            value={exception.last_used_at ? formatRelativeTime(exception.last_used_at) : null}
          />
        </div>

        <DetailField label="Harness" value={exception.harness} />

        {exception.bundle_hash ? (
          <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Signed bundle entry</p>
            <div className="mt-2 flex items-start gap-2">
              <HiMiniDocumentText className="mt-0.5 h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
              <div className="min-w-0">
                <p className="break-all text-sm font-medium text-brand-dark">{exception.bundle_hash}</p>
                {exception.source_receipt_id ? (
                  <p className="mt-1 break-all text-xs text-slate-500">{exception.source_receipt_id}</p>
                ) : null}
              </div>
            </div>
          </div>
        ) : null}

        <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Local daemon acknowledgement</p>
          <div className="mt-2 flex items-center gap-2">
            {exception.ack_status === "synced" ? (
              <HiMiniCheckCircle className="h-4 w-4 text-emerald-600" aria-hidden="true" />
            ) : null}
            <p className="text-sm font-medium text-brand-dark">{ackCopy.label}</p>
          </div>
          <p className="mt-1 text-sm text-slate-600">{ackCopy.detail}</p>
          {isCloudExceptionAckFailure(exception) ? (
            <p className="mt-2 text-xs text-slate-500">Run Guard sync to retry bundle acknowledgement.</p>
          ) : null}
        </div>
      </div>

      {cloudControlsUrl ? (
        <div className="mt-5 space-y-2">
          <p className="text-xs text-slate-500">Open Guard Cloud to revoke or renew this exception.</p>
          <ActionButton href={cloudControlsUrl} variant="secondary">
            <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
            Open in Guard Cloud
          </ActionButton>
        </div>
      ) : null}
    </aside>
  );
}
