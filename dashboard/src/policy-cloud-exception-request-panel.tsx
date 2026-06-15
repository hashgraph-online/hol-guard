import { useCallback, useMemo, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import { createCloudExceptionRequest } from "./guard-api";
import type { GuardCloudExceptionRequestCreateInput } from "./guard-api";
import type { GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import {
  RequestModalShell,
  RequestStepper,
  REQUEST_STEPS,
  ResultPreview,
  SafetyPreview,
  ScopeCardGrid,
  SourceReceiptSummary,
} from "./policy-cloud-exception-request-layout";

const SCOPE_OPTIONS: Array<{
  value: GuardCloudExceptionRequestCreateInput["scope"];
  label: string;
  description: string;
}> = [
  {
    value: "artifact",
    label: "Exact action",
    description: "Limit the exception to one specific action fingerprint.",
  },
  {
    value: "publisher",
    label: "This cwd",
    description: "Reuse within the current working directory scope.",
  },
  {
    value: "workspace",
    label: "This project",
    description: "Apply within the current project folder on this device.",
  },
  {
    value: "harness",
    label: "This harness",
    description: "Apply across one harness such as Codex or Cursor.",
  },
];

type PolicyCloudExceptionRequestPanelProps = {
  snapshot: GuardRuntimeSnapshot;
  onSubmitted: () => void;
  onCancel: () => void;
};

function defaultExpiryIso(): string {
  const date = new Date();
  date.setDate(date.getDate() + 30);
  return date.toISOString();
}

function toDatetimeLocalValue(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function fromDatetimeLocalValue(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return new Date().toISOString();
  }
  return date.toISOString();
}

function resolveDefaultWorkingDirectory(snapshot: GuardRuntimeSnapshot): string {
  const install = snapshot.managed_installs?.find((entry) => entry.workspace?.trim());
  return install?.workspace?.trim() ?? "";
}

export function PolicyCloudExceptionRequestPanel({
  snapshot,
  onSubmitted,
  onCancel,
}: PolicyCloudExceptionRequestPanelProps) {
  const receiptOptions = snapshot.latest_receipts ?? [];
  const harnessOptions = useMemo(() => {
    const fromReceipts = receiptOptions.map((receipt) => receipt.harness).filter(Boolean);
    const fromInstalls = (snapshot.managed_installs ?? []).map((entry) => entry.harness).filter(Boolean);
    return [...new Set([...fromReceipts, ...fromInstalls, "codex", "cursor"])].sort();
  }, [receiptOptions, snapshot.managed_installs]);

  const [scope, setScope] = useState<GuardCloudExceptionRequestCreateInput["scope"]>("artifact");
  const [harness, setHarness] = useState(harnessOptions[0] ?? "codex");
  const [artifactId, setArtifactId] = useState(receiptOptions[0]?.artifact_id ?? "");
  const [publisher, setPublisher] = useState("");
  const [workingDirectory, setWorkingDirectory] = useState(resolveDefaultWorkingDirectory(snapshot));
  const [sourceReceiptId, setSourceReceiptId] = useState(receiptOptions[0]?.receipt_id ?? "");
  const [requestedBy, setRequestedBy] = useState("");
  const [owner, setOwner] = useState("");
  const [reason, setReason] = useState("");
  const [requestedExpiresAt, setRequestedExpiresAt] = useState(defaultExpiryIso());
  const [linkedTicket, setLinkedTicket] = useState("");
  const [maxUses, setMaxUses] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [stepIndex, setStepIndex] = useState(0);

  const activeStep = REQUEST_STEPS[stepIndex] ?? "Source";
  const selectedReceipt = useMemo(
    () => receiptOptions.find((entry) => entry.receipt_id === sourceReceiptId) ?? null,
    [receiptOptions, sourceReceiptId],
  );
  const expiryLabel = useMemo(() => {
    const date = new Date(requestedExpiresAt);
    return Number.isNaN(date.getTime()) ? "Not set" : date.toLocaleString();
  }, [requestedExpiresAt]);

  const handleReceiptChange = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => {
      const receiptId = event.target.value;
      setSourceReceiptId(receiptId);
      const receipt = receiptOptions.find((entry) => entry.receipt_id === receiptId);
      if (!receipt) {
        return;
      }
      setHarness(receipt.harness);
      setArtifactId(receipt.artifact_id);
    },
    [receiptOptions],
  );

  const handleArtifactIdChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setArtifactId(event.target.value);
  }, []);

  const handlePublisherChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPublisher(event.target.value);
  }, []);

  const handleHarnessChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setHarness(event.target.value);
  }, []);

  const handleWorkingDirectoryChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setWorkingDirectory(event.target.value);
  }, []);

  const handleRequestedByChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setRequestedBy(event.target.value);
  }, []);

  const handleOwnerChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setOwner(event.target.value);
  }, []);

  const handleReasonChange = useCallback((event: ChangeEvent<HTMLTextAreaElement>) => {
    setReason(event.target.value);
  }, []);

  const handleExpiryChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setRequestedExpiresAt(fromDatetimeLocalValue(event.target.value));
  }, []);

  const handleLinkedTicketChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setLinkedTicket(event.target.value);
  }, []);

  const handleMaxUsesChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setMaxUses(event.target.value);
  }, []);

  const buildReasonForSubmit = useCallback(() => {
    const parts = [reason.trim()];
    if (linkedTicket.trim()) {
      parts.push(`Ticket: ${linkedTicket.trim()}`);
    }
    if (maxUses.trim()) {
      parts.push(`Max uses: ${maxUses.trim()}`);
    }
    return parts.filter(Boolean).join("\n");
  }, [linkedTicket, maxUses, reason]);

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      setSubmitting(true);
      setError(null);
      setSuccessMessage(null);
      const payload: GuardCloudExceptionRequestCreateInput = {
        scope,
        requestedBy: requestedBy.trim(),
        owner: owner.trim(),
        reason: buildReasonForSubmit(),
        requestedExpiresAt,
        sourceReceiptId: sourceReceiptId.trim() || null,
      };
      if (scope === "artifact") {
        payload.harness = harness.trim() || null;
        payload.artifactId = artifactId.trim() || null;
      } else if (scope === "publisher") {
        payload.publisher = publisher.trim() || null;
      } else if (scope === "harness") {
        payload.harness = harness.trim() || null;
      } else if (scope === "workspace") {
        payload.workingDirectory = workingDirectory.trim() || null;
      }
      try {
        const response = await createCloudExceptionRequest(payload);
        const created = response.items.find((item) => item.status === "pending") ?? response.items[0];
        setSuccessMessage(
          created
            ? `Cloud exception request ${created.requestId} is pending Guard Cloud review.`
            : "Cloud exception request submitted.",
        );
      } catch (submitError) {
        const message =
          submitError instanceof Error && submitError.message.trim()
            ? submitError.message
            : "Unable to submit the Cloud exception request.";
        setError(message);
      } finally {
        setSubmitting(false);
      }
    },
    [
      artifactId,
      buildReasonForSubmit,
      harness,
      owner,
      publisher,
      requestedBy,
      requestedExpiresAt,
      scope,
      sourceReceiptId,
      workingDirectory,
    ],
  );

  const handleDone = useCallback(() => {
    onSubmitted();
  }, [onSubmitted]);

  const canAdvanceFromSource = Boolean(sourceReceiptId.trim());
  const canAdvanceFromScope =
    (scope !== "artifact" || artifactId.trim()) &&
    (scope !== "publisher" || publisher.trim()) &&
    (scope !== "workspace" || workingDirectory.trim()) &&
    ((scope === "harness" || scope === "artifact") ? harness.trim() : true) &&
    reason.trim().length > 0 &&
    owner.trim().length > 0 &&
    requestedExpiresAt.trim().length > 0;
  const canAdvanceFromGuardrails = requestedBy.trim().length > 0;
  const canSubmit = canAdvanceFromSource && canAdvanceFromScope && canAdvanceFromGuardrails;

  const handleBack = useCallback(() => {
    setStepIndex((current) => Math.max(0, current - 1));
  }, []);

  const handleNext = useCallback(() => {
    setStepIndex((current) => Math.min(REQUEST_STEPS.length - 1, current + 1));
  }, []);

  if (receiptOptions.length === 0) {
    return (
      <RequestModalShell
        title="Request cloud exception"
        stepper={<RequestStepper activeStep="Source" />}
        onCancel={onCancel}
        footer={
          <ActionButton variant="secondary" onClick={onCancel}>
            Back
          </ActionButton>
        }
      >
        <SectionLabel>Source receipt required</SectionLabel>
        <p className="mt-2 text-sm text-brand-dark/75">
          Guard needs at least one receipt on this device to anchor a Cloud exception request.
          Run a protected action first, then return here from Evidence or Inbox.
        </p>
      </RequestModalShell>
    );
  }

  if (successMessage) {
    return (
      <RequestModalShell
        title="Request submitted"
        stepper={<RequestStepper activeStep="Submit" />}
        onCancel={onCancel}
        footer={
          <ActionButton variant="primary" onClick={handleDone}>
            Done
          </ActionButton>
        }
      >
        <p className="text-sm text-emerald-800">{successMessage}</p>
      </RequestModalShell>
    );
  }

  return (
    <RequestModalShell
      title="Request cloud exception"
      stepper={<RequestStepper activeStep={activeStep} />}
      onCancel={onCancel}
      footer={
        <div className="flex flex-wrap items-center justify-between gap-2">
          <ActionButton variant="secondary" type="button" onClick={onCancel} disabled={submitting}>
            Cancel
          </ActionButton>
          <div className="flex flex-wrap gap-2">
            {stepIndex > 0 ? (
              <ActionButton variant="secondary" type="button" onClick={handleBack} disabled={submitting}>
                Back
              </ActionButton>
            ) : null}
            {activeStep !== "Submit" ? (
              <ActionButton
                variant="primary"
                type="button"
                onClick={handleNext}
                disabled={
                  submitting ||
                  (activeStep === "Source" && !canAdvanceFromSource) ||
                  (activeStep === "Scope" && !canAdvanceFromScope) ||
                  (activeStep === "Guardrails" && !canAdvanceFromGuardrails)
                }
              >
                Next
              </ActionButton>
            ) : (
              <form onSubmit={handleSubmit}>
                <ActionButton variant="primary" type="submit" disabled={submitting || !canSubmit}>
                  {submitting ? "Submitting…" : "Submit to Guard Cloud"}
                </ActionButton>
              </form>
            )}
          </div>
        </div>
      }
    >
      <p className="mb-4 text-sm text-brand-dark/75">
        Ask Guard Cloud to create a policy override. Local Review handles reusable approvals.
      </p>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_280px] lg:items-start">
        {activeStep === "Source" ? (
          <div className="space-y-4 lg:col-span-3">
            <SectionLabel>Source</SectionLabel>
            {selectedReceipt ? <SourceReceiptSummary receipt={selectedReceipt} /> : null}
            <label className="block space-y-1">
              <span className="text-sm font-medium text-brand-dark">Or choose a different record</span>
              <select
                className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                value={sourceReceiptId}
                onChange={handleReceiptChange}
                required
              >
                {receiptOptions.map((receipt: GuardReceipt) => (
                  <option key={receipt.receipt_id} value={receipt.receipt_id}>
                    {harnessDisplayName(receipt.harness)} · {receipt.artifact_name ?? receipt.artifact_id}
                  </option>
                ))}
              </select>
            </label>
          </div>
        ) : null}

        {activeStep === "Scope" ? (
          <>
            <div className="space-y-4 lg:col-start-1">
              {selectedReceipt ? <SourceReceiptSummary receipt={selectedReceipt} /> : null}
            </div>
            <div className="space-y-4 rounded-xl border border-slate-100 bg-slate-50/50 p-4 lg:col-start-2">
              <SectionLabel>Scope</SectionLabel>
              <p className="text-sm text-slate-600">Choose the narrowest scope that solves the problem.</p>
              <ScopeCardGrid options={SCOPE_OPTIONS} value={scope} onChange={setScope} />

              {scope === "artifact" ? (
                <label className="block space-y-1">
                  <span className="text-sm font-medium text-brand-dark">Artifact fingerprint</span>
                  <input
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                    value={artifactId}
                    onChange={handleArtifactIdChange}
                    required
                  />
                </label>
              ) : null}

              {scope === "publisher" ? (
                <label className="block space-y-1">
                  <span className="text-sm font-medium text-brand-dark">Publisher</span>
                  <input
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                    value={publisher}
                    onChange={handlePublisherChange}
                    required
                  />
                </label>
              ) : null}

              {scope === "harness" || scope === "artifact" ? (
                <label className="block space-y-1">
                  <span className="text-sm font-medium text-brand-dark">App</span>
                  <select
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                    value={harness}
                    onChange={handleHarnessChange}
                    required
                  >
                    {harnessOptions.map((option) => (
                      <option key={option} value={option}>
                        {harnessDisplayName(option)}
                      </option>
                    ))}
                  </select>
                </label>
              ) : null}

              {scope === "workspace" ? (
                <label className="block space-y-1">
                  <span className="text-sm font-medium text-brand-dark">Project folder</span>
                  <input
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                    value={workingDirectory}
                    onChange={handleWorkingDirectoryChange}
                    required
                  />
                </label>
              ) : null}

              <label className="block space-y-1">
                <span className="text-sm font-medium text-brand-dark">Risk owner</span>
                <input
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                  type="email"
                  value={owner}
                  onChange={handleOwnerChange}
                  required
                />
              </label>

              <label className="block space-y-1">
                <span className="text-sm font-medium text-brand-dark">Reason (required)</span>
                <textarea
                  className="min-h-24 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                  value={reason}
                  onChange={handleReasonChange}
                  maxLength={280}
                  required
                />
                <p className="text-xs text-slate-500">{reason.trim().length}/280</p>
                {!reason.trim() ? <p className="text-xs text-red-600">Reason is required.</p> : null}
              </label>

              <label className="block space-y-1 md:max-w-sm">
                <span className="text-sm font-medium text-brand-dark">Requested expiry (required)</span>
                <input
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                  type="datetime-local"
                  value={toDatetimeLocalValue(requestedExpiresAt)}
                  onChange={handleExpiryChange}
                  required
                />
              </label>

              <div className="grid gap-4 md:grid-cols-2">
                <label className="block space-y-1">
                  <span className="text-sm font-medium text-brand-dark">Max uses (optional)</span>
                  <input
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                    type="number"
                    min={1}
                    step={1}
                    value={maxUses}
                    onChange={handleMaxUsesChange}
                    placeholder="50"
                  />
                </label>
                <label className="block space-y-1">
                  <span className="text-sm font-medium text-brand-dark">Linked ticket (optional)</span>
                  <input
                    className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                    value={linkedTicket}
                    onChange={handleLinkedTicketChange}
                    placeholder="ENG-123 or URL"
                  />
                </label>
              </div>

              {scope === "harness" || scope === "workspace" ? (
                <div className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2 text-xs text-brand-dark/80">
                  Broad scopes require step-up authentication and Cloud approval.
                </div>
              ) : null}
            </div>
            <div className="space-y-4 lg:col-start-3">
              <SafetyPreview
                scope={scope}
                harness={harness}
                artifactId={artifactId}
                publisher={publisher}
                workingDirectory={workingDirectory}
                reason={reason}
                expiresLabel={expiryLabel}
              />
              <ResultPreview scope={scope} harness={harness} expiresLabel={expiryLabel} />
            </div>
          </>
        ) : null}

        {activeStep === "Guardrails" ? (
          <div className="space-y-4 rounded-xl border border-slate-100 bg-white p-4 lg:col-span-2">
            <SectionLabel>Guardrails</SectionLabel>
            <label className="block space-y-1 md:max-w-md">
              <span className="text-sm font-medium text-brand-dark">Requested by</span>
              <input
                className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
                type="email"
                value={requestedBy}
                onChange={handleRequestedByChange}
                required
              />
              {!requestedBy.trim() ? <p className="text-xs text-red-600">Requested by is required.</p> : null}
            </label>
          </div>
        ) : null}

        {activeStep === "Submit" ? (
          <div className="space-y-3 rounded-xl border border-slate-100 bg-slate-50/50 p-4 lg:col-span-2">
            <SectionLabel>Review and submit</SectionLabel>
            <p className="text-sm text-brand-dark">
              Guard Cloud will review this request. If approved, the exception syncs as a signed bundle entry on this
              device.
            </p>
            <dl className="grid gap-2 text-sm text-slate-600">
              <div>
                <dt className="text-xs uppercase tracking-wide text-slate-500">Scope</dt>
                <dd className="font-medium text-brand-dark">{scope}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wide text-slate-500">Reason</dt>
                <dd className="text-brand-dark">{reason.trim()}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wide text-slate-500">Expires</dt>
                <dd className="text-brand-dark">{expiryLabel}</dd>
              </div>
            </dl>
          </div>
        ) : null}

        {activeStep === "Guardrails" || activeStep === "Submit" ? (
          <SafetyPreview
            scope={scope}
            harness={harness}
            artifactId={artifactId}
            publisher={publisher}
            workingDirectory={workingDirectory}
            reason={reason}
            expiresLabel={expiryLabel}
          />
        ) : null}
        {activeStep === "Submit" ? (
          <ResultPreview scope={scope} harness={harness} expiresLabel={expiryLabel} />
        ) : null}
      </div>

      {error ? <p className="mt-3 text-sm text-red-600">{error}</p> : null}
    </RequestModalShell>
  );
}
