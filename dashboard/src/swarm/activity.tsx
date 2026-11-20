import { useEffect, useState } from "react";
import { readEvents } from "./api";
import { relativeTime } from "./model";
import type { Agent, SwarmEvent } from "./types";

export function Activity({ agent, stale }: { agent: Agent; stale: boolean }) {
  const [events, setEvents] = useState<SwarmEvent[]>([]);
  const [error, setError] = useState(false);
  useEffect(() => {
    if (agent.origin !== "managed") return;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        if (!document.hidden) {
          const next = await readEvents(agent.id, abort.signal);
          if (!abort.signal.aborted) { setEvents(next); setError(false); }
        }
      } catch { if (!abort.signal.aborted) setError(true); }
      finally { if (!abort.signal.aborted) timer = setTimeout(poll, 2000); }
    }
    void poll();
    return () => { abort.abort(); clearTimeout(timer); };
  }, [agent.id, agent.origin]);
  const entries = agent.origin === "observed" ? [
    { sequence: 1, kind: "lifecycle", text: "Observed on this computer", at_ms: agent.updated_at_ms },
  ] : [...events].reverse();
  return <section className="swarm-activity"><div className="swarm-section-heading"><h3>Activity</h3><span>{entries.length ? `${entries.length} recent` : "Waiting for output"}</span></div>
    {error || stale ? <p className="swarm-muted" role="status">Activity may be out of date. Reconnecting…</p> : null}
    <ol aria-label="Recent agent activity">{entries.map((event) => <li key={event.sequence} className={`swarm-event--${event.kind}`}><i aria-hidden="true" /><div>
      <div className="swarm-event-meta"><span>{event.kind}</span><time dateTime={new Date(event.at_ms).toISOString()}>{relativeTime(event.at_ms)}</time></div>
      {event.kind === "command" ? <code>{event.text}</code> : <p>{event.text}</p>}
    </div></li>)}</ol>
    {agent.origin === "observed" ? <p className="swarm-muted">Task output stays in this agent’s app. Start an agent here to follow its activity.</p> : <p className="swarm-muted">Latest 200 events; long output is shortened for this view. CLI transcripts stay in the harness.</p>}
  </section>;
}
