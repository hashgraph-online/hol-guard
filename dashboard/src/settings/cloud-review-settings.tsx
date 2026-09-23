import { useCallback, useEffect, useRef, useState } from "react";
import { HiMiniArrowPath, HiMiniCloud, HiMiniXMark } from "react-icons/hi2";
import {
  changeCloudReviewSettings,
  fetchCloudReviewSettings,
  type CloudReviewSettingsStatus,
} from "../guard-api";
import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import { useFocusTrap } from "../use-focus-trap";
import { ConnectGuardCloudButton } from "../connect-guard-cloud-button";

export function cloudReviewProofIncomplete(
  gate: CloudReviewSettingsStatus["approval_gate"] | null | undefined,
  password: string,
  totp: string,
  requireFreshTotp: boolean,
): boolean {
  if (!gate?.enabled) return false;
  if (isApprovalProofSubmitDisabled(
    gate, { approvalPassword: password, approvalTotpCode: totp }, false, requireFreshTotp,
  )) return true;
  return requireFreshTotp && totp.trim().length !== 6;
}

export function cloudReviewConfirmationError(message: string): string {
  if (message === "TOTP code is required.") {
    return "Enter the current six-digit code from your authenticator.";
  }
  if (message === "Approval password is required.") {
    return "Enter your approval password to continue.";
  }
  return message;
}

export function cloudReviewStatusCopy(status: CloudReviewSettingsStatus): string {
  if (!status.connected) return "Connect Guard Cloud on this device to review its requests in the cloud.";
  if (!status.enabled) return "Cloud sync is connected. Cloud decisions still need this device's authorization. Confirm it here to update pending requests; you do not need to reconnect.";
  if (status.activation_error) return "Authorization is saved. Request delivery needs another attempt.";
  if (status.held_events > 0) return "Cloud Review is enabled. Some earlier requests need your confirmation before upload.";
  if (status.isolated_events > 0) return "Cloud Review is enabled. Requests tied to another identity stay in local Review.";
  if (status.delivery_state === "error") return "Cloud Review is enabled. Uploads are retrying; local review is still available.";
  if (status.pending_uploads > 0) return "Cloud Review is enabled. Pending requests are being uploaded.";
  return "Cloud Review is enabled for this device. Each cloud decision applies only to its exact request.";
}

export function CloudReviewSettings() {
  const [status, setStatus] = useState<CloudReviewSettingsStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState<"enable" | "disable" | null>(null);
  const [pending, setPending] = useState(false);
  const [includeHeld, setIncludeHeld] = useState(false);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const dialog = useRef<HTMLDivElement>(null);
  const revision = useRef(0);
  useFocusTrap(action !== null, dialog);

  const refresh = useCallback(async (showLoading = true) => {
    const current = ++revision.current;
    if (showLoading) setLoading(true);
    try {
      const result = await fetchCloudReviewSettings();
      if (current !== revision.current) return;
      setStatus(result);
      setError(null);
    } catch {
      if (current !== revision.current) return;
      setStatus(null);
      setError("Cloud Review status is unavailable. Refresh to check again; local review remains available.");
    } finally {
      if (current === revision.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    return () => { revision.current += 1; };
  }, [refresh]);

  useEffect(() => {
    const onFocus = () => { if (action === null && !document.hidden) void refresh(false); };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onFocus);
    const timer = window.setInterval(onFocus, 15_000);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onFocus);
      window.clearInterval(timer);
    };
  }, [refresh, action]);

  function openConfirmation(nextAction: "enable" | "disable") {
    revision.current += 1;
    setAction(nextAction);
    setError(null);
  }

  function close() {
    if (pending) return;
    setAction(null);
    setPassword("");
    setTotp("");
    setIncludeHeld(false);
  }

  async function confirm() {
    if (!status || !action || pending) return;
    const requireFreshTotp = status.approval_gate.totp_enabled === true;
    if (cloudReviewProofIncomplete(status.approval_gate, password, totp, requireFreshTotp)) return;
    const proof = status.approval_gate.enabled
      ? buildApprovalProofCredentials(
        status.approval_gate, { approvalPassword: password, approvalTotpCode: totp }, requireFreshTotp,
      )
      : {};
    revision.current += 1;
    setPending(true);
    setError(null);
    try {
      const result = await changeCloudReviewSettings({
        action, workspace_id: status.workspace_id, source: status.source,
        include_held_requests: action === "enable" && includeHeld,
        ...proof,
      });
      setStatus(result);
      setAction(null);
      setIncludeHeld(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The change was not saved. Try again.");
    } finally {
      setPassword("");
      setTotp("");
      setPending(false);
    }
  }

  const needsRecovery = Boolean(status?.activation_error || status?.held_events || status?.delivery_state === "error");
  const requireFreshTotp = status?.approval_gate.totp_enabled === true;
  const disabled = pending || cloudReviewProofIncomplete(status?.approval_gate, password, totp, requireFreshTotp);
  let confirmLabel = "Turn off Cloud Review";
  if (action === "enable") confirmLabel = "Authorize this device";
  if (pending) confirmLabel = "Saving...";
  let statusCopy = error;
  if (status) statusCopy = cloudReviewStatusCopy(status);
  if (loading) statusCopy = "Checking device authorization...";
  const deliveredAt = status?.last_synced_at && Number.isFinite(Date.parse(status.last_synced_at))
    ? new Date(status.last_synced_at) : null;
  return (
    <section aria-labelledby="cloud-review-heading" className="border-t border-slate-200 pt-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 id="cloud-review-heading" className="flex items-center gap-2 text-sm font-semibold text-brand-dark">
            <HiMiniCloud aria-hidden="true" className="h-5 w-5 shrink-0" /> Cloud Review
          </h3>
          <p className="mt-1 text-sm text-slate-600" role="status">
            {statusCopy}
          </p>
          {status?.enabled && status.expires_at ? (
            <p className="mt-1 text-xs text-slate-600">Authorized until {new Date(status.expires_at).toLocaleDateString()}.</p>
          ) : null}
        </div>
        <button type="button" disabled={loading || pending} onClick={() => void refresh()} title="Refresh Cloud Review status"
          aria-label="Refresh Cloud Review status" className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-md text-brand-dark hover:bg-slate-100 disabled:opacity-50">
          <HiMiniArrowPath aria-hidden="true" className="h-4 w-4" />
        </button>
      </div>
      {status ? (
        <dl className="mt-3 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
          <div className="min-w-0">
            <dt className="text-xs text-slate-600">Cloud connection</dt>
            <dd className="mt-1 font-medium text-brand-dark">{status.connected ? "Connected" : "Not connected"}</dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-slate-600">Cloud decisions</dt>
            <dd className="mt-1 font-medium text-brand-dark">{status.enabled ? "Enabled" : "Confirmation needed"}</dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-slate-600">Last activity delivered</dt>
            <dd className="mt-1 font-medium text-brand-dark">
              {deliveredAt ? <time dateTime={deliveredAt.toISOString()}>{deliveredAt.toLocaleString(undefined, {
                month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
              })}</time> : "Not recorded yet"}
            </dd>
          </div>
        </dl>
      ) : null}
      {status?.connected ? (
        <div className="mt-3 flex flex-wrap gap-2">
          {!status.enabled || needsRecovery ? (
            <button type="button" disabled={loading || pending} onClick={() => openConfirmation("enable")}
              className="min-h-10 rounded-md bg-brand-blue px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">
              {status.enabled ? "Restore Cloud Review" : "Enable Cloud Review"}
            </button>
          ) : null}
          {status.enabled ? (
            <button type="button" disabled={loading || pending} onClick={() => openConfirmation("disable")}
              className="min-h-10 rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark hover:bg-slate-50 disabled:opacity-50">
              Turn off Cloud Review
            </button>
          ) : null}
        </div>
      ) : null}
      {status && !status.connected ? <ConnectGuardCloudButton className="mt-3" /> : null}
      {action && status ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/30 p-4"
          onKeyDown={(event) => { if (event.key === "Escape") close(); }}>
          <div ref={dialog} role="dialog" aria-modal="true" aria-labelledby="cloud-review-confirm-title"
            className="max-h-[90dvh] w-full max-w-lg overflow-y-auto rounded-lg bg-white p-5 shadow-xl">
            <div className="flex items-start justify-between gap-3">
              <h2 id="cloud-review-confirm-title" className="text-base font-semibold text-brand-dark">
                {action === "enable" ? "Authorize Cloud Review" : "Turn off Cloud Review?"}
              </h2>
              <button type="button" onClick={close} disabled={pending} aria-label="Close Cloud Review dialog"
                className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md hover:bg-slate-100">
                <HiMiniXMark aria-hidden="true" className="h-5 w-5" />
              </button>
            </div>
            <p className="mt-3 text-sm text-slate-600">
              {action === "enable"
                ? "Allow signed cloud decisions for exact requests from this device for 30 days. Existing pending requests will be refreshed automatically. Local protection stays on."
                : "Cloud decisions will stop on this device. You can still review requests locally; Cloud sync stays connected."}
            </p>
            {action === "enable" && status.held_events > 0 ? (
              <label className="mt-4 flex items-start gap-3 text-sm text-brand-dark">
                <input type="checkbox" checked={includeHeld} onChange={(event) => setIncludeHeld(event.target.checked)} disabled={pending} className="mt-1" />
                <span>Also send {status.held_events.toLocaleString()} previously unassigned events to the connected workspace.
                  <span className="mt-1 block text-xs text-slate-600">Requests tied to another account or workspace stay isolated.</span>
                  <span className="mt-1 block break-all text-xs text-slate-600">Workspace: {status.workspace_id ?? "Not connected"}</span>
                </span>
              </label>
            ) : null}
            {status.approval_gate.enabled ? (
              <div className="mt-4">
                <ApprovalProofFieldInputs approvalGate={status.approval_gate} approvalPassword={password} approvalTotpCode={totp}
                  requireFreshTotp={requireFreshTotp}
                  onApprovalPasswordChange={(event) => setPassword(event.target.value)} onApprovalTotpCodeChange={(event) => setTotp(event.target.value)} />
              </div>
            ) : null}
            {error ? <p role="alert" className="mt-3 text-sm text-red-700">{cloudReviewConfirmationError(error)}</p> : null}
            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button type="button" onClick={close} disabled={pending} className="min-h-10 rounded-md border border-slate-200 px-4 py-2 text-sm text-brand-dark">Cancel</button>
              <button type="button" onClick={() => void confirm()} disabled={disabled}
                className="min-h-10 rounded-md bg-brand-blue px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">
                {confirmLabel}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
