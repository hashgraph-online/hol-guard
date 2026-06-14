import { useCallback, useMemo, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import { createCloudExceptionRequest } from "./guard-api";
import type { GuardCloudExceptionRequestCreateInput } from "./guard-api";
import type { GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

const SCOPE_OPTIONS: Array<{
  value: GuardCloudExceptionRequestCreateInput["scope"];
  label: string;
  description: string;
}> = [
  {
    value: "artifact",
    label: "One specific action",
    description: "Limit the exception to a single artifact fingerprint.",
  },
  {
    value: "publisher",
    label: "Publisher",
    description: "Apply to packages or plugins from one publisher.",
  },
  {
    value: "harness",
    label: "App",
    description: "Apply across one harness such as Codex or Cursor.",
  },
  {
    value: "workspace",
    label: "Project",
    description: "Apply within the current project folder on this device.",
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
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleScopeChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setScope(event.target.value as GuardCloudExceptionRequestCreateInput["scope"]);
  }, []);

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
        onSubmitted();
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
      onSubmitted,
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

  if (receiptOptions.length === 0) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <SectionLabel>Request cloud exception</SectionLabel>
        <p className="mt-2 text-sm text-brand-dark/75">
          Guard needs at least one receipt on this device to anchor a Cloud exception request.
          Run a protected action first, then return here from Evidence or Inbox.
        </p>
        <div className="mt-4">
          <ActionButton variant="secondary" onClick={onCancel}>
            Back
          </ActionButton>
        </div>
      </div>
    );
  }

  return (
    <form className="space-y-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm" onSubmit={handleSubmit}>
      <div>
        <SectionLabel>Request cloud exception</SectionLabel>
        <p className="mt-2 text-sm text-brand-dark/75">
          Submit a governed risk acceptance to Guard Cloud. This does not create a local remembered rule.
        </p>
      </div>

      <label className="block space-y-1">
        <span className="text-sm font-medium text-brand-dark">Source receipt</span>
        <select
          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
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

      <label className="block space-y-1">
        <span className="text-sm font-medium text-brand-dark">Scope</span>
        <select className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm" value={scope} onChange={handleScopeChange}>
          {SCOPE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <p className="text-xs text-slate-500">
          {SCOPE_OPTIONS.find((option) => option.value === scope)?.description}
        </p>
      </label>

      {scope === "artifact" ? (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Artifact fingerprint</span>
          <input
            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
            value={artifactId}
            onChange={(event) => setArtifactId(event.target.value)}
            required
          />
        </label>
      ) : null}

      {scope === "publisher" ? (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">Publisher</span>
          <input
            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
            value={publisher}
            onChange={(event) => setPublisher(event.target.value)}
            required
          />
        </label>
      ) : null}

      {scope === "harness" || scope === "artifact" ? (
        <label className="block space-y-1">
          <span className="text-sm font-medium text-brand-dark">App</span>
          <select
            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
            value={harness}
            onChange={(event) => setHarness(event.target.value)}
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
            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
            value={workingDirectory}
            onChange={(event) => setWorkingDirectory(event.target.value)}
            required
          />
        </label>
      ) : null}

      <label className="block space-y-1">
        <span className="text-sm font-medium text-brand-dark">Requested by</span>
        <input
          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
          type="email"
          value={requestedBy}
          onChange={(event) => setRequestedBy(event.target.value)}
          required
        />
      </label>

      <label className="block space-y-1">
        <span className="text-sm font-medium text-brand-dark">Risk owner</span>
        <input
          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
          type="email"
          value={owner}
          onChange={(event) => setOwner(event.target.value)}
          required
        />
      </label>

      <label className="block space-y-1">
        <span className="text-sm font-medium text-brand-dark">Reason</span>
        <textarea
          className="min-h-24 w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          required
        />
      </label>

      <label className="block space-y-1">
        <span className="text-sm font-medium text-brand-dark">Expires</span>
        <input
          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
          type="datetime-local"
          value={requestedExpiresAt.slice(0, 16)}
          onChange={(event) => setRequestedExpiresAt(new Date(event.target.value).toISOString())}
          required
        />
      </label>

      {error ? <p className="text-sm text-red-600">{error}</p> : null}
      {successMessage ? <p className="text-sm text-emerald-700">{successMessage}</p> : null}

      <div className="flex flex-wrap gap-2">
        <ActionButton variant="primary" type="submit" disabled={submitting}>
          {submitting ? "Submitting…" : "Submit to Guard Cloud"}
        </ActionButton>
        <ActionButton variant="secondary" type="button" onClick={onCancel} disabled={submitting}>
          Cancel
        </ActionButton>
      </div>
    </form>
  );
}
