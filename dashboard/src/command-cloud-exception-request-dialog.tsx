import { useCallback, useState } from "react";
import { createCommandPolicyExceptionRequest } from "./guard-api";
import type {
  GuardCommandPolicyExceptionRequestInput,
  GuardCommandPolicyExceptionRequestResult,
  GuardCommandPolicyRequestedDuration,
} from "./guard-api";

const DURATION_OPTIONS: ReadonlyArray<{ value: GuardCommandPolicyRequestedDuration; label: string }> = [
  { value: "once", label: "Once" },
  { value: "session", label: "This session" },
  { value: "machine", label: "This machine" },
  { value: "workspace", label: "This workspace" },
  { value: "30d", label: "30 days" },
  { value: "90d", label: "90 days" },
];

const MIN_REASON_LENGTH = 8;
const MAX_REASON_LENGTH = 500;

export interface CommandCloudExceptionRequestDialogProps {
  /** The exact command, shown read-only. */
  readonly command: string;
  readonly sourceLocalRequestId: string;
  readonly sourceMachineInstallationId: string;
  readonly workspaceId: string;
  readonly onClose: () => void;
  readonly onSubmitted: (result: GuardCommandPolicyExceptionRequestResult) => void;
}

/**
 * Dialog for requesting a Cloud exception for a pending command.
 *
 * Sends ONLY correlation identifiers to the Cloud — never the raw
 * command, regex, graph, or policy action. The Cloud re-fetches the
 * bound pending command server-side.
 *
 * Nothing is approved until an owner/admin publishes in Cloud.
 */
export function CommandCloudExceptionRequestDialog({
  command,
  sourceLocalRequestId,
  sourceMachineInstallationId,
  workspaceId,
  onClose,
  onSubmitted,
}: CommandCloudExceptionRequestDialogProps) {
  const [reason, setReason] = useState("");
  const [duration, setDuration] = useState<GuardCommandPolicyRequestedDuration>("once");
  const [note, setNote] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const trimmedReason = reason.trim();
  const canSubmit = trimmedReason.length >= MIN_REASON_LENGTH && !submitting;

  const handleSubmit = useCallback(async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const payload: GuardCommandPolicyExceptionRequestInput = {
        kind: "command-policy",
        sourceLocalRequestId,
        sourceMachineInstallationId,
        workspaceId,
        requestedDuration: duration,
        reason: trimmedReason,
      };
      if (note.trim()) {
        payload.note = note.trim();
      }
      const result = await createCommandPolicyExceptionRequest(payload);
      onSubmitted(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to submit cloud exception request.");
    } finally {
      setSubmitting(false);
    }
  }, [canSubmit, sourceLocalRequestId, sourceMachineInstallationId, workspaceId, duration, trimmedReason, note, onSubmitted]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Request cloud exception for command"
      onKeyDown={(e) => {
        if (e.key === "Escape" && !submitting) onClose();
      }}
    >
      <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-2xl dark:bg-slate-900">
        <h2 className="mb-3 text-lg font-semibold text-slate-900 dark:text-white">
          Request cloud exception
        </h2>
        <p className="mb-4 text-sm text-slate-600 dark:text-slate-300">
          Authorized Cloud reviewers can see the command already synced for this request.
          Nothing is approved until an owner or admin publishes a policy in Cloud.
        </p>

        {/* Exact command, read-only. Never sent to Cloud by this dialog. */}
        <div className="mb-4">
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
            Command
          </label>
          <pre className="max-h-32 overflow-auto rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <code>{command}</code>
          </pre>
        </div>

        {/* Reason */}
        <div className="mb-4">
          <label htmlFor="command-exception-reason" className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
            Reason ({trimmedReason.length}/{MAX_REASON_LENGTH})
          </label>
          <textarea
            id="command-exception-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value.slice(0, MAX_REASON_LENGTH))}
            placeholder="Explain why this command needs a cloud exception..."
            rows={3}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
            autoFocus
          />
          {trimmedReason.length > 0 && trimmedReason.length < MIN_REASON_LENGTH && (
            <p className="mt-1 text-xs text-amber-600">Reason must be at least {MIN_REASON_LENGTH} characters.</p>
          )}
        </div>

        {/* Duration */}
        <div className="mb-4">
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Duration</label>
          <select
            value={duration}
            onChange={(e) => setDuration(e.target.value as GuardCommandPolicyRequestedDuration)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
          >
            {DURATION_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        {error ? (
          <p className="mb-4 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">{error}</p>
        ) : null}

        <div className="flex justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-100 disabled:opacity-50 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={!canSubmit}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
          >
            {submitting ? "Submitting..." : "Request exception"}
          </button>
        </div>
      </div>
    </div>
  );
}
