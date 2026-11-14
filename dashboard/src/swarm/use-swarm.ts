import { useCallback, useEffect, useRef, useState } from "react";
import { fetchContextAssistance } from "../context-assistance/api";
import { listContextWorkspaces, type ContextWorkspaceScope } from "../context-assistance/workspaces-api";
import { readSwarm } from "./api";
import type { Agent, SwarmSnapshot } from "./types";

export function useSwarm() {
  const [snapshot, setSnapshot] = useState<SwarmSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [context, setContext] = useState<{ enabled: boolean | null; scopes: ContextWorkspaceScope[] | null }>({ enabled: null, scopes: null });
  const generation = useRef(0);
  const refreshNow = useCallback(() => setRefresh((n) => n + 1), []);
  const acceptAgent = useCallback((agent: Agent) => setSnapshot((old) => old ? { ...old, agents: [...old.agents.filter((a) => a.id !== agent.id), agent] } : old), []);

  useEffect(() => {
    const current = ++generation.current;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    let inFlight = false;
    async function poll() {
      if (abort.signal.aborted || inFlight) return;
      if (document.hidden) { timer = setTimeout(poll, 3000); return; }
      inFlight = true;
      try {
        const next = await readSwarm(abort.signal);
        if (generation.current === current && !abort.signal.aborted) {
          setSnapshot((old) => old && old.epoch === next.epoch && old.observed_at_ms > next.observed_at_ms ? old : next);
          setError(null);
        }
      } catch (e) {
        if (!abort.signal.aborted && generation.current === current) setError(e instanceof Error ? e.message : "Swarm is unavailable.");
      } finally {
        inFlight = false;
        if (!abort.signal.aborted) { setLoading(false); timer = setTimeout(poll, 3000); }
      }
    }
    function visible() { if (!document.hidden) { clearTimeout(timer); void poll(); } }
    void poll(); document.addEventListener("visibilitychange", visible);
    return () => { abort.abort(); clearTimeout(timer); document.removeEventListener("visibilitychange", visible); };
  }, [refresh]);

  useEffect(() => {
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      if (abort.signal.aborted) return;
      try {
        if (!document.hidden) {
          const status = await fetchContextAssistance(abort.signal);
          const scopes = status.effective_enabled ? await listContextWorkspaces(abort.signal) : [];
          if (!abort.signal.aborted) setContext({ enabled: status.effective_enabled, scopes });
        }
      } catch { if (!abort.signal.aborted) setContext({ enabled: null, scopes: null }); }
      finally { if (!abort.signal.aborted) timer = setTimeout(poll, 15_000); }
    }
    void poll();
    return () => { abort.abort(); clearTimeout(timer); };
  }, [refresh]);
  return { snapshot, loading, error, stale: error !== null, context, refresh: refreshNow, acceptAgent };
}
