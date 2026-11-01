import { useCallback, useEffect, useRef, useState } from "react";
import { controlContextAssistance, fetchContextAssistance } from "./api";
import { contextStatusCopy } from "./status";
import type { ContextAssistanceStatus } from "./types";

const button = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
type ViewProps = {
  status: ContextAssistanceStatus | null;
  loading: boolean;
  stopping: boolean;
  error: boolean;
  stopAvailable?: boolean;
  onRefresh: () => void;
  onStop: () => void;
  onOpenSettings: () => void;
};

export function ContextHomeStatusView(props: ViewProps) {
  const copy = props.status ? contextStatusCopy(props.status) : {
    label: props.loading ? "Checking status" : "Status unavailable",
    detail: props.loading ? "Reading local context assistance status."
      : "Refresh this status or open CIGAR to check context assistance.",
  };
  return <section aria-label="Context assistance overview" className="space-y-3 rounded-xl border border-slate-200 p-4">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 className="text-sm font-semibold text-brand-dark">CIGAR context assistance</h3>
      <span role="status" className="text-sm text-slate-600">{props.stopping ? "Stopping" : copy.label}</span>
    </div>
    <p className="text-sm text-slate-600">{copy.detail}</p>
    {props.status?.effective_enabled ? <p className="text-sm text-slate-600">Local context is available for workspaces you authorize. Prepared context supplies supporting data; it does not approve or confirm execution.</p> : null}
    {props.error ? <p role="alert" className="text-sm text-slate-600">The context request did not return a verified result. Guard protection and existing approvals remain available.</p> : null}
    <div className="flex flex-wrap gap-2">
      <button className={button} type="button" onClick={props.onOpenSettings}>Open CIGAR</button>
      <button className={button} type="button" disabled={props.loading || props.stopping} onClick={props.onRefresh}>Refresh context status</button>
      {(props.stopAvailable ?? Boolean(props.status?.requested_enabled || props.status?.effective_enabled || props.status?.job)) ? <button className={button} type="button" disabled={props.stopping} onClick={props.onStop}>Turn off context assistance</button> : null}
    </div>
  </section>;
}

/** Independent metadata-only reads. Mount/focus never discovers, imports or
 * starts CIGAR. Only a human opt-out calls the stop control. */
export function ContextHomeStatus({ onOpenSettings }: { onOpenSettings: () => void }) {
  const [status, setStatus] = useState<ContextAssistanceStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState(false);
  const [stopAvailable, setStopAvailable] = useState(false);
  const request = useRef<AbortController | null>(null);
  const revision = useRef(0);
  const pendingStop = useRef(false);

  const refresh = useCallback(async () => {
    if (pendingStop.current) return;
    const generation = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setLoading(true);
    try {
      const result = await fetchContextAssistance(controller.signal);
      if (generation === revision.current) {
        setStatus(result); setError(false);
        setStopAvailable(Boolean(result.requested_enabled || result.effective_enabled || result.job));
      }
    } catch {
      if (generation === revision.current) { setStatus(null); setError(true); }
    } finally {
      if (generation === revision.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const visible = () => { if (!document.hidden) void refresh(); };
    window.addEventListener("focus", visible);
    document.addEventListener("visibilitychange", visible);
    return () => {
      revision.current += 1;
      request.current?.abort();
      window.removeEventListener("focus", visible);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [refresh]);

  useEffect(() => {
    if (!status?.effective_enabled && !status?.job) return;
    const timer = window.setTimeout(() => { if (!document.hidden) void refresh(); }, status.job ? 1_000 : 10_000);
    return () => window.clearTimeout(timer);
  }, [refresh, status]);

  async function stop() {
    if (pendingStop.current) return;
    pendingStop.current = true;
    const generation = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setStopping(true); setLoading(false); setError(false);
    try {
      const result = await controlContextAssistance("stop", controller.signal);
      if (generation === revision.current) {
        setStatus(result);
        setStopAvailable(Boolean(result.requested_enabled || result.effective_enabled || result.job));
      }
    } catch {
      if (generation === revision.current) { setStatus(null); setError(true); }
    } finally {
      pendingStop.current = false;
      if (generation === revision.current) setStopping(false);
    }
  }

  return <ContextHomeStatusView status={status} loading={loading} stopping={stopping} error={error}
    stopAvailable={stopAvailable}
    onRefresh={() => void refresh()} onStop={() => void stop()} onOpenSettings={onOpenSettings} />;
}
