import { HiMiniCloudArrowUp, HiMiniXMark } from "react-icons/hi2";
import { Badge, SectionLabel } from "./approval-center-primitives";
import { formatRelativeTime, scopeLabel } from "./approval-center-utils";
import type { GuardCloudException } from "./guard-types";
import {
  isCloudExceptionAckFailure,
  resolveCloudExceptionExpiryTimestamp,
  resolveCloudExceptionExpiryValue,
  resolveCloudExceptionHeadline,
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
    return { label: "Synced", detail: "This device acknowledged the signed policy bundle." };
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

export function PolicyCloudExceptionDetailPanel({
  exception,
  cloudControlsUrl,
  onClose,
}: PolicyCloudExceptionDetailPanelProps) {
  const expiryTimestamp = resolveCloudExceptionExpiryTimestamp(exception);
  const expiryValue = resolveCloudExceptionExpiryValue(exception);
  const ackCopy = resolveAckCopy(exception);
  const headline = resolveCloudExceptionHeadline(exception);

  return (
    <aside
      className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
      aria-label="Cloud exception details"
    >
      <div className="mb-4 flex min-w-0 items-start justify-between gap-3">
        <div className="min-w-0">
          <SectionLabel>Exception detail</SectionLabel>
          <h3 className="mt-1 break-words text-lg font-semibold text-brand-dark">{headline}</h3>
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
        <Badge tone="success">{exception.effect}</Badge>
        <Badge tone="default">{scopeLabel(exception.scope)}</Badge>
        {isCloudExceptionAckFailure(exception) ? <Badge tone="warning">{ackCopy.label}</Badge> : null}
      </div>

      <div className="space-y-4">
        <PersonRow label="Owner" value={exception.owner} />
        <PersonRow label="Approved by" value={exception.approver} />

        <DetailField
          label="Expiry"
          value={
            expiryTimestamp && expiryValue
              ? `${expiryTimestamp.toLocaleString()} (${formatRelativeTime(expiryValue)})`
              : expiryValue
          }
        />
        <DetailField label="Harness" value={exception.harness} />
        <DetailField label="Source receipt" value={exception.source_receipt_id} />
        <DetailField label="Signed bundle hash" value={exception.bundle_hash} />
        <DetailField
          label="Last used"
          value={exception.last_used_at ? formatRelativeTime(exception.last_used_at) : null}
        />

        <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Local daemon acknowledgement</p>
          <p className="mt-1 text-sm font-medium text-brand-dark">{ackCopy.label}</p>
          <p className="mt-1 text-sm text-slate-600">{ackCopy.detail}</p>
          {isCloudExceptionAckFailure(exception) ? (
            <p className="mt-2 text-xs text-slate-500">Run Guard sync to retry bundle acknowledgement.</p>
          ) : null}
        </div>
      </div>

      {cloudControlsUrl ? (
        <div className="mt-5">
          <a
            href={cloudControlsUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-sm font-medium text-brand-blue hover:underline"
          >
            <HiMiniCloudArrowUp className="h-4 w-4" aria-hidden="true" />
            Open in Guard Cloud
          </a>
        </div>
      ) : null}
    </aside>
  );
}
