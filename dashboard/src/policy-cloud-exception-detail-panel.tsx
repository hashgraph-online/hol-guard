import {
  HiMiniCheckCircle,
  HiMiniCloudArrowUp,
  HiMiniCommandLine,
  HiMiniDocumentText,
  HiMiniExclamationTriangle,
  HiMiniXMark,
} from "react-icons/hi2";
import { ActionButton, Badge, SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime, harnessDisplayName, scopeLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardCloudException } from "./guard-types";
import {
  isCloudExceptionAckFailure,
  isCloudExceptionActive,
  isCloudExceptionExpiringSoon,
  resolveCloudExceptionBlastRadius,
  resolveCloudExceptionEffectLabel,
  resolveCloudExceptionEvidenceUrl,
  resolveCloudExceptionExpiryTimestamp,
  resolveCloudExceptionExpiryValue,
  resolveCloudExceptionHeadline,
  resolveCloudExceptionScopePath,
  resolveCloudExceptionSubtitle,
  resolveCloudExceptionWhyCopy,
  resolvePersonDisplayLabel,
  resolvePersonInitials,
} from "./policy-cloud-exceptions-utils";

type PolicyCloudExceptionDetailPanelProps = {
  exception: GuardCloudException;
  cloudControlsUrl: string | null;
  onClose: () => void;
};

function PersonBlock({
  label,
  value,
  role,
}: {
  label: string;
  value: string | null | undefined;
  role: string;
}) {
  const display = resolvePersonDisplayLabel(value);
  const initials = resolvePersonInitials(value);
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
      <div className="mt-2 flex items-center gap-2.5">
        <span
          aria-hidden="true"
          className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-xs font-semibold text-brand-blue"
        >
          {initials}
        </span>
        <div className="min-w-0">
          <p className="text-sm font-medium text-brand-dark">{display}</p>
          <p className="text-xs text-slate-500">{role}</p>
        </div>
      </div>
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
    return { label: "Offline", detail: "This device was offline when the signed bundle was issued." };
  }
  return { label: "Unknown", detail: "Local acknowledgement status is unavailable." };
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
  const subtitle = resolveCloudExceptionSubtitle(exception);
  const blast = resolveCloudExceptionBlastRadius(exception.scope);
  const whyCopy = resolveCloudExceptionWhyCopy(exception);
  const isActive = isCloudExceptionActive(exception);
  const isEnforcedLocally = exception.ack_status === "synced";
  const evidenceUrl = resolveCloudExceptionEvidenceUrl(exception);
  const scopePath = resolveCloudExceptionScopePath(exception);
  const effectLabel = resolveCloudExceptionEffectLabel(exception.effect);
  const atRisk = isCloudExceptionExpiringSoon(exception) || isCloudExceptionAckFailure(exception);

  return (
    <aside
      className="min-w-0 rounded-2xl border border-slate-200 bg-white shadow-sm lg:sticky lg:top-4"
      aria-label="Cloud exception details"
    >
      <div className="border-b border-slate-100 px-5 py-4">
        <div className="flex items-start justify-between gap-3">
          <SectionLabel>Temporary cloud exception</SectionLabel>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-brand-dark"
            aria-label="Close exception detail"
          >
            <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {isActive ? <Badge tone="success">Active</Badge> : <Badge tone="default">Expired</Badge>}
          {isEnforcedLocally ? <Tag tone="slate">Enforced locally</Tag> : null}
          {!isEnforcedLocally ? <Badge tone="warning">{ackCopy.label}</Badge> : null}
        </div>
        <div className="mt-4 flex items-start gap-3">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-500">
            <HiMiniCommandLine className="h-5 w-5" aria-hidden="true" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="break-words text-lg font-semibold text-brand-dark">{headline}</h3>
              {atRisk ? (
                <Tag tone="purple">
                  <HiMiniExclamationTriangle className="mr-1 inline h-3.5 w-3.5" aria-hidden="true" />
                  At risk
                </Tag>
              ) : null}
            </div>
            <p className="mt-1 text-sm text-slate-600">{subtitle}</p>
            <p className="mt-1 text-xs text-slate-500">{effectLabel}</p>
          </div>
        </div>
      </div>

      <div className="space-y-4 px-5 py-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Why this exists</p>
          <p className="mt-2 text-sm leading-relaxed text-brand-dark">{whyCopy}</p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Blast radius</p>
            <div className="mt-2">
              <Badge tone={blastRadiusBadgeTone(blast.tone)}>{blast.label}</Badge>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-slate-600">{blast.detail}</p>
          </div>
          <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Scope (exact)</p>
            <div className="mt-2">
              <Tag tone="blue">{scopeLabel(exception.scope, "policy")}</Tag>
            </div>
            {exception.harness ? (
              <p className="mt-2 text-sm font-medium text-brand-dark">{harnessDisplayName(exception.harness)}</p>
            ) : null}
            {scopePath ? <p className="mt-1 break-all text-xs text-slate-500">{scopePath}</p> : null}
          </div>
        </div>

        {evidenceUrl ? (
          <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Source review item</p>
            <p className="mt-2 text-sm font-semibold text-brand-dark">
              {exception.artifact_id?.trim() || exception.source_receipt_id?.trim() || "Linked approval record"}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              {exception.harness ? harnessDisplayName(exception.harness) : "Guard review"} · receipt linked
            </p>
            <div className="mt-3">
              <ActionButton href={guardAwareHref(evidenceUrl)} variant="secondary">
                Open in Review
              </ActionButton>
            </div>
          </div>
        ) : null}

        <div className="grid gap-4 sm:grid-cols-2">
          <PersonBlock label="Owner" value={exception.owner} role="Repository member" />
          <PersonBlock label="Approved by" value={exception.approver} role="Security team" />
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Expires</p>
            <p className="mt-1 text-sm font-medium text-brand-dark">
              {expiryTimestamp ? expiryTimestamp.toLocaleDateString() : "Not set"}
            </p>
            {expiryValue ? (
              <p className="mt-0.5 text-xs text-slate-500">{formatRelativeTime(expiryValue)}</p>
            ) : null}
          </div>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Last used</p>
            <p className="mt-1 text-sm font-medium text-brand-dark">
              {exception.last_used_at ? formatRelativeTime(exception.last_used_at) : "Not yet used"}
            </p>
          </div>
        </div>

        {exception.bundle_hash ? (
          <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Signed bundle entry</p>
            <div className="mt-2 flex items-start gap-2">
              <HiMiniDocumentText className="mt-0.5 h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
              <div className="min-w-0">
                <p className="break-all font-mono text-xs text-brand-dark">{exception.bundle_hash}</p>
                {exception.source_receipt_id ? (
                  <p className="mt-1 break-all text-xs text-slate-500">{exception.source_receipt_id}</p>
                ) : null}
              </div>
            </div>
          </div>
        ) : null}

        <div className="rounded-xl border border-slate-100 bg-slate-50/80 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Local daemon ack</p>
          <div className="mt-2 flex items-center gap-2">
            {exception.ack_status === "synced" ? (
              <HiMiniCheckCircle className="h-4 w-4 text-emerald-600" aria-hidden="true" />
            ) : null}
            <p className="text-sm font-medium text-brand-dark">{ackCopy.label}</p>
          </div>
          <p className="mt-1 text-xs leading-relaxed text-slate-600">{ackCopy.detail}</p>
        </div>
      </div>

      {cloudControlsUrl ? (
        <div className="border-t border-slate-100 px-5 py-4">
          <p className="text-xs text-slate-500">Open Guard Cloud to revoke or renew this exception.</p>
          <div className="mt-3">
            <ActionButton href={cloudControlsUrl} variant="secondary">
              <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Open in Guard Cloud
            </ActionButton>
          </div>
        </div>
      ) : null}
    </aside>
  );
}
