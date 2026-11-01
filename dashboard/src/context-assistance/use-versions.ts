import { useCallback, useEffect, useRef, useState } from "react";
import type { ContextAssistanceStatus } from "./types";
import { requestCigarVersions, type CigarVersionsRequest } from "./versions-api";
import { cigarJobPending } from "./versions-actions";
import { loadCigarVersionsData, type CigarVersionsData } from "./versions-data";
import type { ContextProof } from "./workspaces-api";
export type CaptureCigarStatus = () => (state: ContextAssistanceStatus) => void;
const message = (cause: unknown) => cause instanceof Error ? cause.message : "Refresh CIGAR status and jobs before trying again.";
export function useCigarVersions(capture: CaptureCigarStatus) {
  const [data, setData] = useState<CigarVersionsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uncertain, setUncertain] = useState(false);
  const [tracking, setTracking] = useState<string | null>(null);
  const revision = useRef(0), pending = useRef(false), mounted = useRef(false);
  const request = useRef<AbortController | null>(null);
  const captureRef = useRef(capture); captureRef.current = capture;
  const refresh = useCallback(async () => {
    if (pending.current) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    const publish = captureRef.current();
    setLoading(true);
    try {
      const value = await loadCigarVersionsData(controller.signal);
      if (current !== revision.current || !mounted.current) return;
      setData(value); publish(value.state); setError(null); setUncertain(false);
    } catch (cause) {
      if (current === revision.current && mounted.current && !controller.signal.aborted) {
        setError(message(cause)); setUncertain(true);
      }
    } finally {
      if (current === revision.current && mounted.current) setLoading(false);
    }
  }, []);
  useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => { mounted.current = false; ++revision.current; request.current?.abort(); };
  }, [refresh]);
  useEffect(() => {
    const focus = () => { if (!document.hidden) void refresh(); };
    window.addEventListener("focus", focus); document.addEventListener("visibilitychange", focus);
    return () => { window.removeEventListener("focus", focus); document.removeEventListener("visibilitychange", focus); };
  }, [refresh]);
  useEffect(() => {
    if (busy || loading || !data?.jobs.some(cigarJobPending)) return;
    const timer = window.setTimeout(() => { if (!document.hidden) void refresh(); }, 1500);
    return () => window.clearTimeout(timer);
  }, [data, busy, loading, refresh]);
  async function perform(input: CigarVersionsRequest, proof?: ContextProof) {
    if (pending.current) return;
    pending.current = true;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    const publish = captureRef.current();
    setBusy(true); setLoading(false); setError(null);
    if ("job_id" in input) setTracking(input.job_id);
    try {
      const reply = await requestCigarVersions(input, proof, controller.signal);
      if (current !== revision.current || !mounted.current) return;
      publish(reply.state);
      // A successful effect is never sent again when the following metadata read fails.
      const value = await loadCigarVersionsData(controller.signal);
      if (current !== revision.current || !mounted.current) return;
      setData(value); publish(value.state); setUncertain(false);
    } catch (cause) {
      if (current === revision.current && mounted.current && !controller.signal.aborted) {
        setError(message(cause)); setUncertain(true);
      }
    } finally {
      pending.current = false;
      if (current === revision.current && mounted.current) setBusy(false);
    }
  }
  return { data, loading, busy, error, uncertain, tracking, refresh, perform };
}
