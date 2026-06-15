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
  SafetyPreview,
  ScopeCardGrid,
  type RequestStep,
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

function resolveActiveStep(
  sourceReceiptId: string,
  scope: GuardCloudExceptionRequestCreateInput["scope"],
  reason: string,
  owner: string,
  requestedBy: string,
): RequestStep {
  if (!sourceReceiptId.trim()) {
    return "Source";
  }
  if (!scope) {
    return "Scope";
  }
  if (!reason.trim() || !owner.trim() || !requestedBy.trim()) {
    return "Guardrails";
  }
  return "Submit";
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
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const activeStep = resolveActiveStep(sourceReceiptId, scope, reason, owner, requestedBy);
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
        reason: reason.trim(),
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
      harness,
      owner,
      publisher,
      reason,
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
        <form className="flex flex-wrap gap-2" onSubmit={handleSubmit}>
          <ActionButton variant="primary" type="submit" disabled={submitting}>
            {submitting ? "Submitting…" : "Submit to Guard Cloud"}
          </ActionButton>
          <ActionButton variant="secondary" type="button" onClick={onCancel} disabled={submitting}>
            Cancel
          </ActionButton>
        </form>
      }
    >
      <p className="mb-4 text-sm text-brand-dark/75">
        Ask Guard Cloud to create a policy override. Local Review handles reusable approvals.
      </p>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_280px] lg:items-start">
        <div className="space-y-4 rounded-xl border border-slate-100 bg-slate-50/50 p-4">
          <SectionLabel>Source</SectionLabel>
          <label className="block space-y-1">
            <span className="text-sm font-medium text-brand-dark">Source receipt</span>
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

        <div className="space-y-4 rounded-xl border border-slate-100 bg-slate-50/50 p-4">
          <SectionLabel>Scope</SectionLabel>
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
        </div>

        <SafetyPreview
          scope={scope}
          harness={harness}
          artifactId={artifactId}
          publisher={publisher}
          workingDirectory={workingDirectory}
          reason={reason}
          expiresLabel={expiryLabel}
        />
      </div>

      <div className="mt-4 space-y-4 rounded-xl border border-slate-100 bg-white p-4">
        <SectionLabel>Guardrails</SectionLabel>
        <div className="grid gap-4 md:grid-cols-2">
          <label className="block space-y-1">
            <span className="text-sm font-medium text-brand-dark">Requested by</span>
            <input
              className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
              type="email"
              value={requestedBy}
              onChange={handleRequestedByChange}
              required
            />
          </label>
          <label className="block space-y-1">
            <span className="text-sm font-medium text-brand-dark">Risk owner</span>
            <input
              className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
              type="email"
              value={owner}
              onChange={handleOwnerChange}
              required
            />
          </label>
        </div>
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Reason</span>
          <textarea
            className="min-h-24 w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
            value={reason}
            onChange={handleReasonChange}
            required
          />
        </label>
        <label className="block space-y-1 md:max-w-sm">
          <span className="text-sm font-medium text-brand-dark">Expires</span>
          <input
            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
            type="datetime-local"
            value={toDatetimeLocalValue(requestedExpiresAt)}
            onChange={handleExpiryChange}
            required
          />
        </label>
      </div>

      {error ? <p className="mt-3 text-sm text-red-600">{error}</p> : null}
    </RequestModalShell>
  );
}
