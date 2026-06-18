import type { ChangeEvent } from "react";
import {
  HiMiniArrowTopRightOnSquare,
  HiMiniCheckCircle,
  HiMiniClipboardDocument,
  HiMiniCloudArrowDown,
  HiMiniCodeBracket,
  HiMiniDocumentText,
  HiMiniIdentification,
  HiMiniShieldCheck,
  HiMiniUsers,
} from "react-icons/hi2";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName, scopeLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardApprovalRequest, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import type { CloudExceptionRequestDraft, SourceMode, SubmittedRequestState } from "./policy-cloud-exception-request-draft";
import {
  formatRelativeTime,
  isExpiryValid,
  isReasonValid,
  resolveResolvedApprovals,
  resolveSelectedApproval,
  resolveSelectedReceipt,
  fromDatetimeLocalValue,
  toDatetimeLocalValue,
} from "./policy-cloud-exception-request-draft";
import {
  ResultPreview,
  SafetyPreview,
  ScopeCardGrid,
  SourceReceiptSummary,
  type RequestScopeValue,
} from "./policy-cloud-exception-request-layout";
import { resolveRequestScopeBlastRadius } from "./policy-cloud-exceptions-utils";

const SOURCE_MODE_OPTIONS: Array<{
  mode: SourceMode;
  label: string;
  description: string;
  icon: typeof HiMiniDocumentText;
  recommended?: boolean;
}> = [
  {
    mode: "approval",
    label: "Recent approval",
    description: "Use a recent Review approval already recorded on this device.",
    icon: HiMiniDocumentText,
    recommended: true,
  },
  {
    mode: "receipt",
    label: "Evidence receipt",
    description: "Use an evidence record such as policy-eval, token-scan, or runtime event.",
    icon: HiMiniShieldCheck,
  },
  {
    mode: "paste-id",
    label: "Paste request id",
    description: "Paste a request or action id recorded by Guard on this machine.",
    icon: HiMiniIdentification,
  },
];

type CloudExceptionSourceStepProps = {
  snapshot: GuardRuntimeSnapshot;
  draft: CloudExceptionRequestDraft;
  receipts: GuardReceipt[];
  onDraftChange: (patch: Partial<CloudExceptionRequestDraft>) => void;
};

export function CloudExceptionSourceStep({
  snapshot,
  draft,
  receipts,
  onDraftChange,
}: CloudExceptionSourceStepProps) {
  const approvals = resolveResolvedApprovals(snapshot);
  const hasApprovals = approvals.length > 0;
  const hasReceipts = receipts.length > 0;
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);

  const handleModeChange = (mode: SourceMode) => {
    if (mode === "approval" && !hasApprovals) {
      return;
    }
    if (mode === "receipt" && !hasReceipts) {
      return;
    }
    const patch: Partial<CloudExceptionRequestDraft> = { sourceMode: mode };
    if (mode === "approval" && approvals[0]) {
      patch.sourceReviewItemId = approvals[0].request_id;
      patch.sourceReceiptId = "";
      patch.pastedRequestId = "";
      patch.harness = approvals[0].harness;
      patch.artifactId = approvals[0].artifact_id;
      if (approvals[0].workspace?.trim()) {
        patch.workingDirectory = approvals[0].workspace.trim();
      }
      if (approvals[0].publisher?.trim()) {
        patch.publisher = approvals[0].publisher.trim();
      }
    } else if (mode === "receipt" && receipts[0]) {
      patch.sourceReceiptId = receipts[0].receipt_id;
      patch.sourceReviewItemId = "";
      patch.pastedRequestId = "";
      patch.harness = receipts[0].harness;
      patch.artifactId = receipts[0].artifact_id;
    } else if (mode === "paste-id") {
      patch.pastedRequestId = "";
      patch.sourceReceiptId = "";
      patch.sourceReviewItemId = "";
    }
    onDraftChange(patch);
  };

  const handleReceiptSelect = (event: ChangeEvent<HTMLSelectElement>) => {
    const receiptId = event.target.value;
    const receipt = receipts.find((entry) => entry.receipt_id === receiptId);
    onDraftChange({
      sourceReceiptId: receiptId,
      harness: receipt?.harness ?? draft.harness,
      artifactId: receipt?.artifact_id ?? draft.artifactId,
    });
  };

  const handleApprovalSelect = (event: ChangeEvent<HTMLSelectElement>) => {
    const requestId = event.target.value;
    const approval = approvals.find((entry) => entry.request_id === requestId);
    onDraftChange({
      sourceReviewItemId: requestId,
      harness: approval?.harness ?? draft.harness,
      artifactId: approval?.artifact_id ?? draft.artifactId,
      workingDirectory: approval?.workspace?.trim() || draft.workingDirectory,
      publisher: approval?.publisher?.trim() || draft.publisher,
    });
  };

  const handlePasteIdChange = (event: ChangeEvent<HTMLInputElement>) => {
    const pastedRequestId = event.target.value;
    const approval = snapshot.items?.find((item) => item.request_id === pastedRequestId.trim());
    onDraftChange({
      pastedRequestId,
      sourceReviewItemId: pastedRequestId.trim(),
      harness: approval?.harness ?? draft.harness,
      artifactId: approval?.artifact_id ?? draft.artifactId,
      workingDirectory: approval?.workspace?.trim() || draft.workingDirectory,
      publisher: approval?.publisher?.trim() || draft.publisher,
    });
  };

  return (
    <div className="space-y-4">
      <div>
        <SectionLabel>What should this exception be based on?</SectionLabel>
        <p className="mt-1 text-sm text-slate-600">
          Choose the record that best represents the action or request you want to allow with a policy override.
        </p>
      </div>

      <div className="grid gap-2 sm:grid-cols-3" role="radiogroup" aria-label="Source type">
        {SOURCE_MODE_OPTIONS.map((option) => {
          const disabled =
            (option.mode === "approval" && !hasApprovals) ||
            (option.mode === "receipt" && !hasReceipts);
          const selected = draft.sourceMode === option.mode;
          const Icon = option.icon;
          return (
            <button
              key={option.mode}
              type="button"
              role="radio"
              aria-checked={selected}
              disabled={disabled}
              onClick={() => handleModeChange(option.mode)}
              className={`rounded-xl border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${
                selected
                  ? "border-brand-blue bg-brand-blue/5 ring-2 ring-brand-blue/25"
                  : "border-slate-200 bg-white hover:border-slate-300"
              }`}
            >
              <div className="flex items-start gap-2">
                <span
                  className={`mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${
                    selected ? "border-brand-blue bg-brand-blue" : "border-slate-300 bg-white"
                  }`}
                  aria-hidden="true"
                >
                  {selected ? <span className="h-1.5 w-1.5 rounded-full bg-white" /> : null}
                </span>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Icon className="h-4 w-4 text-slate-500" aria-hidden="true" />
                    <p className="text-sm font-semibold text-brand-dark">{option.label}</p>
                    {option.recommended && hasApprovals ? (
                      <span className="rounded-full bg-brand-blue/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-brand-blue">
                        Recommended
                      </span>
                    ) : null}
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-slate-600">{option.description}</p>
                  {disabled ? (
                    <p className="mt-2 text-[11px] text-slate-500">
                      {option.mode === "approval"
                        ? "No resolved Review approvals on this device yet."
                        : "No evidence receipts on this device yet."}
                    </p>
                  ) : null}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {draft.sourceMode === "receipt" && hasReceipts ? (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Choose evidence receipt</span>
          <select
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
            value={draft.sourceReceiptId}
            onChange={handleReceiptSelect}
            required
          >
            {receipts.map((receipt) => (
              <option key={receipt.receipt_id} value={receipt.receipt_id}>
                {harnessDisplayName(receipt.harness)} · {receipt.artifact_name ?? receipt.artifact_id}
              </option>
            ))}
          </select>
        </label>
      ) : null}

      {draft.sourceMode === "approval" && hasApprovals ? (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Choose approval record</span>
          <select
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
            value={draft.sourceReviewItemId}
            onChange={handleApprovalSelect}
            required
          >
            {approvals.map((approval) => (
              <option key={approval.request_id} value={approval.request_id}>
                {harnessDisplayName(approval.harness)} · {approval.artifact_name || approval.artifact_id}
              </option>
            ))}
          </select>
        </label>
      ) : null}

      {draft.sourceMode === "paste-id" ? (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Request or action id</span>
          <input
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
            value={draft.pastedRequestId}
            onChange={handlePasteIdChange}
            placeholder="Paste a Guard request id from this device"
            required
          />
          {draft.pastedRequestId.trim() && !selectedApproval ? (
            <p className="text-xs text-amber-700" role="alert">
              No matching request found on this device. Guard only accepts ids recorded locally.
            </p>
          ) : null}
        </label>
      ) : null}

      {selectedReceipt ? <SourceReceiptSummary receipt={selectedReceipt} /> : null}
      {!selectedReceipt && selectedApproval ? (
        <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Selected source preview</p>
          <div className="mt-3 flex items-start gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-200/80 text-slate-600">
              <HiMiniCodeBracket className="h-4 w-4" aria-hidden="true" />
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-brand-dark">
                {selectedApproval.artifact_name || selectedApproval.artifact_id}
              </p>
              <p className="mt-1 text-xs text-slate-600">
                {harnessDisplayName(selectedApproval.harness)}
                {selectedApproval.resolved_at
                  ? ` · ${formatRelativeTime(selectedApproval.resolved_at) ?? selectedApproval.resolved_at}`
                  : ""}
              </p>
              <p className="mt-2 break-all font-mono text-xs text-slate-500">{selectedApproval.request_id}</p>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

type CloudExceptionScopeStepProps = {
  snapshot: GuardRuntimeSnapshot;
  draft: CloudExceptionRequestDraft;
  receipts: GuardReceipt[];
  harnessOptions: string[];
  publisherAvailable: boolean;
  onDraftChange: (patch: Partial<CloudExceptionRequestDraft>) => void;
};

export function CloudExceptionScopeStep({
  snapshot,
  draft,
  receipts,
  harnessOptions,
  publisherAvailable,
  onDraftChange,
}: CloudExceptionScopeStepProps) {
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);
  const sourceLabel = selectedApproval?.artifact_name || selectedApproval?.artifact_id || selectedReceipt?.artifact_name || selectedReceipt?.artifact_id;

  const scopeOptions: Array<{
    value: RequestScopeValue;
    label: string;
    description: string;
    disabled?: boolean;
    disabledReason?: string;
  }> = [
    {
      value: "artifact",
      label: "Exact action",
      description: "Only this exact command and context.",
    },
    {
      value: "publisher",
      label: "This cwd",
      description: "Any matching action in this working directory.",
      disabled: !publisherAvailable,
      disabledReason: publisherAvailable ? undefined : "Publisher not available from the selected source.",
    },
    {
      value: "workspace",
      label: "This project",
      description: "Any matching action in this project repository.",
    },
    {
      value: "harness",
      label: "This harness",
      description: "Any matching action for this harness.",
    },
    {
      value: "team-policy",
      label: "Team policy",
      description: "Make this an allow rule for your whole team.",
      disabled: true,
      disabledReason: "Create team policy exceptions in Guard Cloud.",
    },
  ];

  return (
    <div className="space-y-4">
      {(selectedReceipt || selectedApproval) && sourceLabel ? (
        <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Source (from review)</p>
          <div className="mt-2 flex items-start gap-2">
            <HiMiniCodeBracket className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-brand-dark">{sourceLabel}</p>
              <p className="text-xs text-slate-600">
                {harnessDisplayName(selectedApproval?.harness ?? selectedReceipt?.harness ?? draft.harness)}
                {selectedReceipt ? (
                  <>
                    {" · "}
                    <a
                      href={guardAwareHref(`/evidence?search=${encodeURIComponent(selectedReceipt.receipt_id)}`)}
                      className="text-brand-blue hover:underline"
                    >
                      {selectedReceipt.receipt_id}
                    </a>
                  </>
                ) : selectedApproval ? (
                  <> · {selectedApproval.request_id}</>
                ) : null}
              </p>
            </div>
          </div>
        </div>
      ) : null}

      <div>
        <SectionLabel>Where should this cloud exception apply?</SectionLabel>
        <p className="mt-1 text-sm text-slate-600">Choose the narrowest scope that solves the problem.</p>
      </div>

      <ScopeCardGrid
        options={scopeOptions}
        value={draft.scope}
        onChange={(scope) => onDraftChange({ scope })}
      />

      {draft.scope === "artifact" ? (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Artifact fingerprint</span>
          <input
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
            value={draft.artifactId}
            onChange={(event) => onDraftChange({ artifactId: event.target.value })}
            required
          />
        </label>
      ) : null}

      {draft.scope === "publisher" ? (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Publisher / cwd</span>
          <input
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
            value={draft.publisher}
            onChange={(event) => onDraftChange({ publisher: event.target.value })}
            required
          />
        </label>
      ) : null}

      {(draft.scope === "harness" || draft.scope === "artifact") && (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">App</span>
          <select
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
            value={draft.harness}
            onChange={(event) => onDraftChange({ harness: event.target.value })}
            required
          >
            {harnessOptions.map((option) => (
              <option key={option} value={option}>
                {harnessDisplayName(option)}
              </option>
            ))}
          </select>
        </label>
      )}

      {draft.scope === "workspace" ? (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Project folder</span>
          <input
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
            value={draft.workingDirectory}
            onChange={(event) => onDraftChange({ workingDirectory: event.target.value })}
            required
          />
        </label>
      ) : null}

      <div className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2 text-xs text-brand-dark/80">
        Broader scopes may require additional verification and approvals in Guard Cloud.
      </div>
    </div>
  );
}

type CloudExceptionGuardrailsStepProps = {
  draft: CloudExceptionRequestDraft;
  snapshot: GuardRuntimeSnapshot;
  receipts: GuardReceipt[];
  expiryLabel: string;
  onDraftChange: (patch: Partial<CloudExceptionRequestDraft>) => void;
};

export function CloudExceptionGuardrailsStep({
  draft,
  snapshot,
  receipts,
  expiryLabel,
  onDraftChange,
}: CloudExceptionGuardrailsStepProps) {
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);
  const sourceLabel = selectedApproval?.artifact_name || selectedApproval?.artifact_id || selectedReceipt?.artifact_name || selectedReceipt?.artifact_id;
  const blast = resolveRequestScopeBlastRadius(draft.scope);
  const reasonTooShort = draft.reason.trim().length > 0 && !isReasonValid(draft.reason);
  const expiryInvalid = draft.requestedExpiresAt.trim().length > 0 && !isExpiryValid(draft.requestedExpiresAt);

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,280px)] lg:items-start">
      <div className="space-y-4">
        <div className="grid gap-3 rounded-xl border border-slate-200 bg-slate-50/60 p-3 sm:grid-cols-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Source</p>
            <p className="mt-1 text-sm font-medium text-brand-dark">{sourceLabel || "Not set"}</p>
          </div>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Scope</p>
            <p className="mt-1 text-sm font-medium text-brand-dark">
              {draft.scope === "workspace"
                ? "This project"
                : draft.scope === "publisher"
                  ? "This cwd"
                  : draft.scope === "artifact"
                    ? "Exact action"
                    : draft.scope === "harness"
                      ? "This harness"
                      : "Team policy"}
            </p>
          </div>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Blast radius</p>
            <p className="mt-1 text-sm font-medium text-brand-dark">{blast.label}</p>
          </div>
        </div>

        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Risk owner (required)</span>
          <input
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
            type="email"
            value={draft.owner}
            onChange={(event) => onDraftChange({ owner: event.target.value })}
            placeholder="owner@example.com"
            required
            aria-invalid={!draft.owner.trim()}
          />
          {!draft.owner.trim() ? <p className="text-xs text-red-600">Choose an owner.</p> : null}
        </label>

        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Requested by (required)</span>
          <input
            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
            type="email"
            value={draft.requestedBy}
            onChange={(event) => onDraftChange({ requestedBy: event.target.value })}
            placeholder="requester@example.com"
            required
            aria-invalid={!draft.requestedBy.trim()}
          />
          {!draft.requestedBy.trim() ? (
            <p className="text-xs text-slate-600">Enter the email Guard Cloud should associate with this request.</p>
          ) : null}
        </label>

        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Reason (required)</span>
          <textarea
            className={`min-h-24 w-full rounded-xl border bg-white px-3 py-2 text-sm ${
              reasonTooShort ? "border-red-300" : "border-slate-200"
            }`}
            value={draft.reason}
            onChange={(event) => onDraftChange({ reason: event.target.value })}
            placeholder="Explain why this exception is needed."
            maxLength={280}
            required
            aria-invalid={reasonTooShort || !draft.reason.trim()}
          />
          <p className="text-xs text-slate-500">{draft.reason.trim().length}/280 (minimum 24)</p>
          {!draft.reason.trim() ? (
            <p className="text-xs text-red-600">Reason is required.</p>
          ) : reasonTooShort ? (
            <p className="text-xs text-red-600">Reason must be at least 24 characters.</p>
          ) : null}
        </label>

        <label className="block space-y-1 md:max-w-sm">
          <span className="text-sm font-medium text-brand-dark">Requested expiry (required)</span>
          <input
            className={`w-full rounded-xl border bg-white px-3 py-2 text-sm ${
              expiryInvalid ? "border-red-300" : "border-slate-200"
            }`}
            type="datetime-local"
            value={toDatetimeLocalValue(draft.requestedExpiresAt)}
            onChange={(event) =>
              onDraftChange({ requestedExpiresAt: fromDatetimeLocalValue(event.target.value) })
            }
            required
            aria-invalid={expiryInvalid}
          />
          {expiryInvalid ? <p className="text-xs text-red-600">Expiry must be in the future.</p> : null}
        </label>

        <div className="grid gap-4 md:grid-cols-2">
          <label className="block space-y-1">
            <span className="text-sm font-medium text-brand-dark">Max uses (optional)</span>
            <input
              className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
              type="number"
              min={1}
              step={1}
              value={draft.maxUses}
              onChange={(event) => onDraftChange({ maxUses: event.target.value })}
              placeholder="e.g. 50"
            />
            <p className="text-xs text-slate-500">Appended to reason for reviewers. Not enforced locally.</p>
          </label>
          <label className="block space-y-1">
            <span className="text-sm font-medium text-brand-dark">Linked ticket (optional)</span>
            <input
              className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
              value={draft.linkedTicket}
              onChange={(event) => onDraftChange({ linkedTicket: event.target.value })}
              placeholder="ENG-123 or URL"
            />
            <p className="text-xs text-slate-500">Appended to reason for reviewers.</p>
          </label>
        </div>

        {(draft.scope === "harness" || draft.scope === "workspace") && (
          <div className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2 text-xs text-brand-dark/80">
            Broad scopes may require step-up authentication during Cloud review.
          </div>
        )}
      </div>

      <SafetyPreview
        scope={draft.scope}
        harness={draft.harness}
        artifactId={draft.artifactId}
        publisher={draft.publisher}
        workingDirectory={draft.workingDirectory}
        reason={draft.reason}
        expiresLabel={expiryLabel}
        compact
      />
    </div>
  );
}

type CloudExceptionReviewStepProps = {
  draft: CloudExceptionRequestDraft;
  snapshot: GuardRuntimeSnapshot;
  receipts: GuardReceipt[];
  expiryLabel: string;
  actionLabel: string;
  error: string | null;
  onEditStep: (stepIndex: number) => void;
};

export function CloudExceptionReviewStep({
  draft,
  snapshot,
  receipts,
  expiryLabel,
  actionLabel,
  error,
  onEditStep,
}: CloudExceptionReviewStepProps) {
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);
  const blast = resolveRequestScopeBlastRadius(draft.scope);
  const sourceDetail = selectedReceipt
    ? `Evidence receipt · ${selectedReceipt.receipt_id}`
    : selectedApproval
      ? `Approval record · ${selectedApproval.request_id}`
      : draft.pastedRequestId.trim();

  const rows: Array<{ label: string; value: string; detail?: string; stepIndex: number }> = [
    {
      label: "Source",
      value: selectedApproval?.artifact_name || selectedApproval?.artifact_id || selectedReceipt?.artifact_name || selectedReceipt?.artifact_id || "—",
      detail: sourceDetail,
      stepIndex: 0,
    },
    {
      label: "Scope",
      value:
        draft.scope === "workspace"
          ? "This project"
          : draft.scope === "publisher"
            ? "This cwd"
            : draft.scope === "artifact"
              ? "Exact action"
              : draft.scope === "harness"
                ? "This harness"
                : "Team policy",
      detail: draft.workingDirectory || draft.publisher || draft.artifactId || draft.harness,
      stepIndex: 1,
    },
    { label: "Owner", value: draft.owner.trim() || "—", stepIndex: 2 },
    { label: "Requested by", value: draft.requestedBy.trim() || "—", stepIndex: 2 },
    { label: "Reason", value: draft.reason.trim() || "—", stepIndex: 2 },
    { label: "Expiry", value: expiryLabel, stepIndex: 2 },
  ];

  return (
    <div className="space-y-4">
      <ResultPreview
        scope={draft.scope}
        harness={draft.harness}
        expiresLabel={expiryLabel}
        actionLabel={actionLabel}
      />

      <dl className="divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white">
        {rows.map((row) => (
          <div key={row.label} className="flex items-start justify-between gap-3 px-4 py-3">
            <div className="min-w-0">
              <dt className="text-xs uppercase tracking-wide text-slate-500">{row.label}</dt>
              <dd className="mt-1 text-sm font-medium text-brand-dark">{row.value}</dd>
              {row.detail ? <dd className="mt-0.5 break-all text-xs text-slate-500">{row.detail}</dd> : null}
            </div>
            <button
              type="button"
              onClick={() => onEditStep(row.stepIndex)}
              className="shrink-0 text-xs font-medium text-brand-blue hover:underline"
            >
              Edit
            </button>
          </div>
        ))}
        <div className="px-4 py-3">
          <dt className="text-xs uppercase tracking-wide text-slate-500">Blast radius</dt>
          <dd className="mt-1 text-sm font-medium text-brand-dark">{blast.label}</dd>
        </div>
      </dl>

      <details className="rounded-xl border border-slate-200 bg-slate-50/50 p-3">
        <summary className="cursor-pointer text-sm font-medium text-brand-dark">Technical details</summary>
        <dl className="mt-3 space-y-2 text-xs text-slate-600">
          {draft.artifactId ? (
            <div>
              <dt>Artifact ID</dt>
              <dd className="break-all font-mono">{draft.artifactId}</dd>
            </div>
          ) : null}
          {selectedReceipt ? (
            <div>
              <dt>Receipt ID</dt>
              <dd className="break-all font-mono">{selectedReceipt.receipt_id}</dd>
            </div>
          ) : null}
          {selectedApproval ? (
            <div>
              <dt>Request ID</dt>
              <dd className="break-all font-mono">{selectedApproval.request_id}</dd>
            </div>
          ) : null}
        </dl>
      </details>

      <div className="rounded-xl border border-amber-200 bg-amber-50/70 p-3 text-sm text-amber-900">
        <p className="font-medium">This does not change local remembered approvals.</p>
        <p className="mt-1 text-xs leading-relaxed">
          Review still handles normal reusable decisions. This request is only for a Cloud exception override.
        </p>
      </div>

      {error ? (
        <p className="text-sm text-red-600" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

type CloudExceptionSubmittedStepProps = {
  draft: CloudExceptionRequestDraft;
  snapshot: GuardRuntimeSnapshot;
  receipts: GuardReceipt[];
  submitted: SubmittedRequestState;
  expiryLabel: string;
  cloudControlsUrl: string | null;
  onViewPending: () => void;
  onDone: () => void;
};

export function CloudExceptionSubmittedStep({
  draft,
  snapshot,
  receipts,
  submitted,
  expiryLabel,
  cloudControlsUrl,
  onViewPending,
  onDone,
}: CloudExceptionSubmittedStepProps) {
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);
  const blast = resolveRequestScopeBlastRadius(draft.scope);
  const submittedLabel = new Date(submitted.submittedAt).toLocaleString();

  const handleCopyRequestId = () => {
    if (!submitted.requestId || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(submitted.requestId);
  };

  return (
    <div className="space-y-5 text-center sm:text-left">
      <div className="flex flex-col items-center sm:items-start">
        <span className="inline-flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 text-emerald-700">
          <HiMiniCheckCircle className="h-7 w-7" aria-hidden="true" />
        </span>
        <h3 className="mt-4 text-xl font-semibold text-brand-dark">Exception request sent</h3>
        <p className="mt-1 text-sm text-slate-600">
          Guard Cloud will review it before local enforcement changes.
        </p>
      </div>

      <div className="grid gap-3 rounded-xl border border-slate-200 bg-slate-50/60 p-4 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Request id</p>
          <div className="mt-1 flex items-center gap-1">
            <p className="break-all font-mono text-sm text-brand-dark">{submitted.requestId}</p>
            <button
              type="button"
              onClick={handleCopyRequestId}
              className="rounded-md p-1 text-slate-400 hover:bg-slate-100"
              aria-label="Copy request id"
            >
              <HiMiniClipboardDocument className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Status</p>
          <p className="mt-1">
            <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800">
              Pending Guard Cloud review
            </span>
          </p>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Submitted</p>
          <p className="mt-1 text-sm text-brand-dark">{submittedLabel}</p>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Request type</p>
          <p className="mt-1 text-sm text-brand-dark">Cloud exception</p>
        </div>
      </div>

      <div className="grid gap-3 rounded-xl border border-slate-200 p-4 sm:grid-cols-2">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Source</p>
          <p className="mt-1 text-sm font-medium text-brand-dark">
            {selectedApproval?.artifact_name ||
              selectedApproval?.artifact_id ||
              selectedReceipt?.artifact_name ||
              selectedReceipt?.artifact_id}
          </p>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Scope</p>
          <p className="mt-1 text-sm font-medium text-brand-dark">
            {scopeLabel(draft.scope === "team-policy" ? "global" : draft.scope, "policy")}
          </p>
          <p className="text-xs text-slate-500">{draft.workingDirectory || draft.publisher}</p>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Blast radius</p>
          <p className="mt-1 text-sm font-medium text-brand-dark">{blast.label}</p>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Requested expiry</p>
          <p className="mt-1 text-sm font-medium text-brand-dark">{expiryLabel}</p>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-200 p-4 text-left">
          <HiMiniUsers className="h-5 w-5 text-brand-blue" aria-hidden="true" />
          <p className="mt-2 text-sm font-semibold text-brand-dark">Cloud reviewer decides</p>
          <p className="mt-1 text-xs text-slate-600">
            A teammate reviews and approves or rejects your request.
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 p-4 text-left">
          <HiMiniCloudArrowDown className="h-5 w-5 text-brand-blue" aria-hidden="true" />
          <p className="mt-2 text-sm font-semibold text-brand-dark">Signed bundle syncs to this machine</p>
          <p className="mt-1 text-xs text-slate-600">
            If approved, Guard Cloud adds the exception to the signed policy bundle.
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 p-4 text-left">
          <HiMiniShieldCheck className="h-5 w-5 text-brand-blue" aria-hidden="true" />
          <p className="mt-2 text-sm font-semibold text-brand-dark">Local daemon acknowledges before enforcement</p>
          <p className="mt-1 text-xs text-slate-600">
            Guard applies the exception after local daemon ack.
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2 text-xs text-brand-dark/80">
        Until approved, Guard keeps using existing local remembered rules and strict config.
      </div>

      <div className="flex flex-wrap items-center justify-center gap-2 sm:justify-start">
        <ActionButton variant="secondary" type="button" onClick={onViewPending}>
          View pending request
        </ActionButton>
        {cloudControlsUrl ? (
          <ActionButton variant="secondary" href={cloudControlsUrl} target="_blank" rel="noreferrer">
            Open Guard Cloud
            <HiMiniArrowTopRightOnSquare className="ml-1 inline h-3.5 w-3.5" aria-hidden="true" />
          </ActionButton>
        ) : null}
        <ActionButton variant="primary" type="button" onClick={onDone}>
          Done
        </ActionButton>
      </div>
    </div>
  );
}
