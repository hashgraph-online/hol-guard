import { useEffect, useId, useState } from "react";

import { filterCodexHostApps, type CodexHostInventory, type CodexHostAppSummary } from "../codex-host-inventory";

const PAGE_SIZE = 25;

function HostAppTools({ app }: { app: CodexHostAppSummary }) {
  const [shown, setShown] = useState(PAGE_SIZE);
  if (!app.metadata_available) {
    return <p className="mt-2 text-sm text-brand-dark/80">Tool summaries are unavailable for this app.</p>;
  }
  if (app.tools.length === 0) {
    return <p className="mt-2 text-sm text-brand-dark/80">Codex provided no tool summaries.</p>;
  }
  return (
    <>
      <ul className="mt-2 divide-y divide-brand-dark/10">
        {app.tools.slice(0, shown).map((tool) => (
          <li key={tool.name} className="py-2 text-sm text-brand-dark">
            <p className="break-words font-medium">{tool.title ?? tool.name}</p>
            {tool.description ? <p className="mt-1 max-w-prose break-words leading-6 text-brand-dark/80">{tool.description}</p> : null}
          </li>
        ))}
      </ul>
      {shown < app.tools.length ? (
        <button type="button" className="guard-extensions-chip mt-2" onClick={() => setShown((value) => value + PAGE_SIZE)}>
          Show more tools for {app.name}
        </button>
      ) : null}
    </>
  );
}

function HostAppRow({ app }: { app: CodexHostAppSummary }) {
  return (
    <details className="border-b border-brand-dark/10 py-3">
      <summary className="cursor-pointer rounded-lg px-1 py-1 text-sm text-brand-dark focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue">
        <span className="break-words font-semibold">{app.name}</span>
        <span className="ml-2 text-xs text-brand-dark/70">{app.enabled ? "Enabled in Codex" : "Disabled in Codex"}</span>
      </summary>
      <div className="mt-2 pl-4">
        <p className="text-xs leading-5 text-brand-dark/80">
          {app.callable ? "Codex reports tools available." : "Codex does not report callable tools."}
          {" "}Permissions in Guard are unchanged.
        </p>
        <HostAppTools app={app} />
      </div>
    </details>
  );
}

function HostInventoryApps({ inventory }: { inventory: CodexHostInventory }) {
  const searchId = useId();
  const [query, setQuery] = useState("");
  const [shown, setShown] = useState(PAGE_SIZE);
  if (inventory.apps.length === 0) {
    return <p className="mt-3 text-sm text-brand-dark/80">Codex did not report any apps. Check host connections again after using an app in Codex.</p>;
  }
  const matches = filterCodexHostApps(inventory.apps, query);
  return (
    <>
      <label htmlFor={searchId} className="mt-4 block text-sm font-medium text-brand-dark">Search Codex apps and tool summaries</label>
      <input id={searchId} type="search" value={query} maxLength={128}
        onChange={(event) => { setQuery(event.target.value); setShown(PAGE_SIZE); }}
        className="mt-1 w-full rounded-xl border border-brand-dark/20 bg-white px-3 py-2 text-sm text-brand-dark focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue" />
      <p className="mt-2 text-xs text-brand-dark/80" role="status">
        {matches.length} {matches.length === 1 ? "app" : "apps"}{query.trim() ? " match this search" : " in the host snapshot"} · Tool summaries only
      </p>
      {matches.slice(0, shown).map((app) => <HostAppRow key={`${inventory.connection_id}:${app.app_id}`} app={app} />)}
      {matches.length === 0 ? <p className="mt-3 text-sm text-brand-dark/80">No Codex apps or tool summaries match this search.</p> : null}
      {shown < matches.length ? (
        <button type="button" className="guard-extensions-chip mt-3" onClick={() => setShown((value) => value + PAGE_SIZE)}>Show more Codex apps</button>
      ) : null}
    </>
  );
}

export function CodexHostConnectors({ inventory }: { inventory?: CodexHostInventory }) {
  const headingId = useId();
  const [reported, setReported] = useState(Boolean(inventory));
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    if (!inventory) return;
    setReported(true);
    setNow(Date.now());
    const remaining = Math.max(0, Math.min(30_000, inventory.expires_at_ms - Date.now()));
    const timer = window.setTimeout(() => setNow(inventory.expires_at_ms), remaining);
    return () => window.clearTimeout(timer);
  }, [inventory?.expires_at_ms]);
  if (!inventory && !reported) return null;
  let content;
  if (!inventory || inventory.expires_at_ms <= now) {
    content = <p className="mt-3 text-sm text-brand-dark/80" role="status">Host summaries expired or are unavailable. Check host connections again.</p>;
  } else {
    content = <HostInventoryApps inventory={inventory} />;
  }
  return (
    <section className="mt-8" aria-labelledby={headingId}>
      <h2 id={headingId} className="text-xl font-semibold tracking-tight text-brand-dark">Apps reported by Codex</h2>
      <p className="mt-1 max-w-prose text-sm leading-6 text-brand-dark/80">
        Inspect apps and tool summaries from your existing Codex host. Guard has not verified their accounts or tool permissions.
        Manage tools Guard has observed under Custom extensions.
      </p>
      {content}
    </section>
  );
}
