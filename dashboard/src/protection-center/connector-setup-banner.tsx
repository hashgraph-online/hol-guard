import type { ConnectorSetupMatch } from "./custom-extension-profile";
import { shortIdentity } from "./custom-extension-profile";
import { connectorSetupCopy } from "./local-cli-panel-copy";

/** Shown on Protect when it was opened from a request held on this connector. */
export function ConnectorSetupBanner(props: {
  name: string;
  heldIdentityHash: string;
  currentIdentityHash: string;
  match: ConnectorSetupMatch;
  busy: boolean;
  outcome: string | null;
  onSetUp: () => void;
}) {
  // After a setup from this page the item is decided; keep the outcome, not the "already decided" note.
  const copy = props.outcome ? { title: `${props.name} is set up`, body: "" } : connectorSetupCopy(props.match, props.name);
  const ready = props.outcome !== null || props.match === "ready";
  return (
    <section
      data-testid="connector-setup-banner"
      aria-labelledby="connector-setup-heading"
      className={`mt-4 max-w-2xl rounded-xl border p-4 ${ready ? "border-brand-blue/30 bg-brand-blue/5" : "border-amber-300 bg-amber-50"}`}
    >
      <h2 id="connector-setup-heading" className="text-sm font-semibold text-brand-dark">{copy.title}</h2>
      {copy.body ? <p className="mt-1 text-sm leading-6 text-slate-700">{copy.body}</p> : null}
      <p className="mt-2 text-xs text-slate-600">
        Held identity <code className="rounded bg-slate-100 px-1 font-mono text-brand-dark">{shortIdentity(props.heldIdentityHash)}</code>
      </p>
      {props.currentIdentityHash !== props.heldIdentityHash ? (
        <p className="mt-1 text-xs text-slate-600">
          Current identity <code className="rounded bg-slate-100 px-1 font-mono text-brand-dark">{shortIdentity(props.currentIdentityHash)}</code>
        </p>
      ) : null}
      {props.outcome ? (
        <p role="status" className="mt-2 text-sm font-medium text-emerald-800">{props.outcome}</p>
      ) : ready ? (
        <button
          type="button"
          className="mt-3 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-60"
          disabled={props.busy}
          onClick={props.onSetUp}
        >
          Set up with recommended
        </button>
      ) : null}
    </section>
  );
}
