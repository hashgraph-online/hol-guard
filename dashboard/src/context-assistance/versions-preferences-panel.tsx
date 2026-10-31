import { useEffect, useId, useState } from "react";
import type { CigarUpdatePreferences } from "./versions-api";
import type { CigarCatalogBuild } from "./versions-catalog";
import type { CigarUpdateSettings } from "./versions-preferences";
import { versionButton, versionCard, versionField, type CigarVersionActionHandler } from "./versions-view";
type Props = { value: CigarUpdateSettings; builds: CigarCatalogBuild[]; disabled: boolean; onAction: CigarVersionActionHandler };
export function CigarUpdatePreferencesPanel({ value, builds, disabled, onAction }: Props) {
  const [draft, setDraft] = useState<CigarUpdatePreferences>(value.requested);
  const id = useId();
  useEffect(() => { setDraft(value.requested); }, [value.revision]);
  const locked = (key: string) => disabled || value.locked_settings.some((k) => k === "context_assistance_updates" || k === "context_assistance_updates." + key);
  const changed = JSON.stringify(draft) !== JSON.stringify(value.requested);
  return <section className={versionCard} aria-labelledby={id + "-heading"}>
    <h3 id={id + "-heading"} className="font-semibold text-brand-dark">Update preferences</h3>
    <p className="text-sm text-slate-600">Preparing a build leaves your current selection in place. This Guard build requires an explicit switch and keeps the last good build.</p>
    <label className="block text-sm text-slate-600">Update mode
      <select className={versionField} value={draft.mode} disabled={locked("mode")}
        onChange={(event) => setDraft({ ...draft, mode: event.target.value as CigarUpdatePreferences["mode"] })}>
        <option value="manual">Manual</option>
        <option value="notify" disabled>Notify · delivery unavailable</option>
        {draft.mode === "prepare" ? <option value="prepare" disabled>Automatic preparation · unavailable</option> : null}
      </select>
    </label>
    <p className="text-sm text-slate-600">Update notifications and automatic preparation are not available in this Guard build.</p>
    <label className="flex min-h-11 items-center gap-3 text-sm text-slate-600"><input type="checkbox" checked={draft.allow_preview}
      disabled={locked("allow_preview")} onChange={(event) => setDraft({ ...draft, allow_preview: event.target.checked })} />Allow preview selections</label>
    <p className="text-sm text-slate-600">Preview installation still needs release qualification and support in Guard.</p>
    <label className="block text-sm text-slate-600">Pin to a build
      <select className={versionField} value={draft.pinned_build ?? ""} disabled={locked("pinned_build")}
        onChange={(event) => { const { pinned_build: _pin, ...rest } = draft; setDraft(event.target.value ? { ...rest, pinned_build: event.target.value } : rest); }}>
        <option value="">No pin</option>
        {draft.pinned_build && !builds.some((b) => b.identity.build_id === draft.pinned_build)
          ? <option value={draft.pinned_build}>{draft.pinned_build} · unavailable in catalog</option> : null}
        {builds.map((b) => <option key={b.identity.build_id} value={b.identity.build_id}>{b.identity.sdk_version} · {b.identity.build_id}{b.withdrawn ? " · withdrawn" : ""}</option>)}
      </select>
    </label>
    <p className="break-all text-sm text-slate-600">Effective pin: {value.effective.pinned_build ?? "none"}. Last good build: {value.effective.retain_last_good ? "retained" : "retention disabled by saved policy"}.</p>
    {value.locked_settings.length ? <p className="text-sm text-slate-600">Your organization manages some update preferences. Effective values may differ from your saved choices.</p> : null}
    {value.diagnostic ? <p role="status" className="break-all text-sm text-amber-800">Update preference diagnostic: {value.diagnostic}</p> : null}
    <button type="button" className={versionButton} disabled={disabled || !changed} onClick={() => onAction({
      input: { action: "set_preferences", expected_revision: value.revision, preferences: draft },
      title: "Save CIGAR update preferences", detail: "Save these update choices without changing or starting the selected runtime.",
    })}>Save update preferences</button>
  </section>;
}
