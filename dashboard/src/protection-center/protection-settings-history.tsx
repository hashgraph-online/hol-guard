import { useEffect, useState } from "react";

import { fetchExtensionControlHistory, type ExtensionControlLayer } from "../extension-controls-api";

export function ProtectionSettingsHistory(props: {
  catalogDigest: string;
  disabled?: boolean;
  onUse: (layers: ExtensionControlLayer[], revision: number) => void;
}) {
  const [items, setItems] = useState<Awaited<ReturnType<typeof fetchExtensionControlHistory>>["items"]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    setLoading(true);
    fetchExtensionControlHistory().then((history) => {
      if (!active) return;
      setItems(history.items.filter((item) => item.catalog_digest === props.catalogDigest));
      setError(null);
    }).catch(() => { if (active) setError("Local settings history is unavailable until Guard verifies settings integrity."); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [props.catalogDigest]);
  return <details className="mt-5"><summary className="cursor-pointer text-sm font-semibold text-brand-dark">Settings history</summary><p className="mt-2 text-xs leading-5 text-brand-dark/80">Guard verifies the authenticated local history before showing it. Restoring a version only prepares the device layer as a draft. Current organization policy stays in force, and nothing changes until you review and approve it.</p>{loading ? <p className="mt-3 text-xs text-brand-dark/70">Loading verified history…</p> : error ? <p className="mt-3 text-xs text-amber-950">{error}</p> : items.length ? <div className="mt-3 space-y-2">{items.slice(0, 10).map((item) => <div key={item.revision} className="flex flex-col gap-2 py-2 sm:flex-row sm:items-center sm:justify-between"><div><div className="text-sm font-medium text-brand-dark">Device settings revision {item.revision}</div><time className="text-xs text-brand-dark/70" dateTime={item.occurred_at}>{new Date(item.occurred_at).toLocaleString()}</time></div><button type="button" disabled={props.disabled} onClick={() => props.onUse(item.layers, item.revision)} className="min-h-10 px-1 text-xs font-semibold text-brand-blue disabled:opacity-40">Use this version as draft</button></div>)}</div> : <p className="mt-3 text-xs text-brand-dark/70">No earlier authenticated device settings are available yet.</p>}</details>;
}
