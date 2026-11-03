import type { ExtensionCatalogItem } from "../extension-controls-api";

/**
 * Where an Extension takes effect. Guard's local catalog only describes what
 * Guard checks on this computer; it never knows whether a Guard Cloud
 * workspace has connected an account and turned an Extension's actions on.
 * So this view never presents an installed, enabled, verified or paid
 * Extension as able to run actions in Guard Cloud.
 */
export type ExtensionRunScopeCopy = {
  here: string;
  cloud: string;
  notes: string[];
};

type LocalState = "allowed" | "blocked" | "partial" | "required" | "lockdown";

const HERE: Record<LocalState, string> = {
  allowed: "On. Guard checks it for AI tools here.",
  partial: "Partly on. Guard checks the Permissions you left on.",
  required: "Always on. Guard requires it here.",
  lockdown: "Lockdown. Matching actions stay blocked here.",
  blocked: "Off. Guard does not check it here.",
};

const CLOUD = "Not turned on from this computer.";

const CLOUD_RULE =
  "Guard Cloud runs an Extension's actions only after a workspace connects the account it needs and turns those actions on there. Installing it, turning it on here, or a verified or paid listing does not do that.";

const CLOUD_POLICY =
  "Its settings here come from your Guard Cloud workspace's Policy. That Policy decides what Guard allows on this computer; it does not let Guard Cloud run anything.";

export function extensionRunScope(
  extension: Pick<ExtensionCatalogItem, "source">,
  localState: LocalState,
): ExtensionRunScopeCopy {
  const notes = [CLOUD_RULE];
  if (extension.source === "signed-cloud") notes.push(CLOUD_POLICY);
  return { here: HERE[localState], cloud: CLOUD, notes };
}

export function ExtensionRunScope({
  extension,
  localState,
}: {
  extension: Pick<ExtensionCatalogItem, "source">;
  localState: LocalState;
}) {
  const copy = extensionRunScope(extension, localState);
  return (
    <article aria-labelledby="extension-run-scope-heading" className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm lg:col-span-2" data-testid="extension-run-scope">
      <h2 id="extension-run-scope-heading" className="text-lg font-semibold text-brand-dark">Where it runs</h2>
      <dl className="mt-4 grid gap-4 sm:grid-cols-2">
        <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">On this computer</dt><dd className="mt-1 text-sm text-brand-dark">{copy.here}</dd></div>
        <div><dt className="text-xs font-semibold uppercase text-brand-dark/55">Cloud actions</dt><dd className="mt-1 text-sm text-brand-dark">{copy.cloud}</dd></div>
      </dl>
      {copy.notes.map((note) => <p key={note} className="mt-3 max-w-3xl text-sm leading-6 text-brand-dark/75">{note}</p>)}
    </article>
  );
}
