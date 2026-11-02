import { useEffect, useId, useState } from "react";
import { SelectMenu } from "../select-menu";
import { SettingsToggleRow } from "../settings/settings-row-primitives";
import type { CigarUpdatePreferences } from "./versions-api";
import type { CigarCatalogBuild } from "./versions-catalog";
import type { CigarUpdateSettings } from "./versions-preferences";
import { versionButton, type CigarVersionActionHandler } from "./versions-view";
type Props = { value: CigarUpdateSettings; builds: CigarCatalogBuild[]; disabled: boolean; onAction: CigarVersionActionHandler };
const label = "text-sm font-medium text-brand-dark";
const hint = "mt-1 text-xs leading-5 text-brand-dark/60";
export function CigarUpdatePreferencesPanel({ value, builds, disabled, onAction }: Props) {
  const [draft, setDraft] = useState<CigarUpdatePreferences>(value.requested);
  const id = useId();
  useEffect(() => { setDraft(value.requested); }, [value.revision]);
  const locked = (key: string) => disabled || value.locked_settings.some((k) => k === "context_assistance_updates" || k === "context_assistance_updates." + key);
  const changed = JSON.stringify(draft) !== JSON.stringify(value.requested);
  const modes = [
    { value: "manual" as const, label: "Manual", description: "You decide when to prepare and switch." },
    { value: "notify" as const, label: "Notify", description: "Not available in this Guard version.", disabled: true },
    ...(draft.mode === "prepare" ? [{ value: "prepare" as const, label: "Automatic preparation", description: "Not available in this Guard version.", disabled: true }] : []),
  ];
  const pins = [
    { value: "", label: "No pin", description: "Any approved version can be prepared." },
    ...(draft.pinned_build && !builds.some((b) => b.identity.build_id === draft.pinned_build)
      ? [{ value: draft.pinned_build, label: draft.pinned_build, description: "No longer in the version list" }] : []),
    ...builds.map((b) => ({ value: b.identity.build_id, label: "CIGAR " + b.identity.sdk_version + (b.withdrawn ? " · withdrawn" : ""), description: b.identity.build_id })),
  ];
  return <section className="space-y-5" aria-labelledby={id + "-heading"}>
    <div><h4 id={id + "-heading"} className="font-semibold text-brand-dark">Update preferences</h4>
      <p className={hint}>Preparing a build leaves your current selection in place. This Guard build requires an explicit switch and keeps the last good build.</p></div>
    <div className="grid gap-5 sm:grid-cols-2">
      <div><span id={id + "-mode"} className={label}>Update mode</span>
        <SelectMenu labelledBy={id + "-mode"} className="mt-1.5 w-full" value={draft.mode} options={modes} disabled={locked("mode")}
          onChange={(mode) => setDraft({ ...draft, mode })} />
        <p className={hint}>Update notifications and automatic preparation are not available in this Guard build.</p></div>
      <div><span id={id + "-pin"} className={label}>Pin to a build</span>
        <SelectMenu labelledBy={id + "-pin"} className="mt-1.5 w-full" value={draft.pinned_build ?? ""} options={pins} disabled={locked("pinned_build")}
          onChange={(pin) => { const { pinned_build: _pin, ...rest } = draft; setDraft(pin ? { ...rest, pinned_build: pin } : rest); }} />
        <p className={hint + " break-all"}>Effective pin: {value.effective.pinned_build ?? "none"}. Last good build: {value.effective.retain_last_good ? "retained" : "retention disabled by saved policy"}.</p></div>
    </div>
    <div className="rounded-xl border border-brand-dark/10 px-4">
      <SettingsToggleRow label="Allow preview selections" checked={draft.allow_preview} disabled={locked("allow_preview")}
        description="Preview installation still needs release qualification and support in Guard."
        onChange={(allow_preview) => setDraft({ ...draft, allow_preview })} />
    </div>
    {value.locked_settings.length ? <p className="text-sm text-brand-dark/70">Your organization manages some update preferences. Effective values may differ from your saved choices.</p> : null}
    {value.diagnostic ? <p role="status" className="break-all text-sm text-amber-800">Update preference diagnostic: {value.diagnostic}</p> : null}
    <button type="button" className={versionButton} disabled={disabled || !changed} onClick={() => onAction({
      input: { action: "set_preferences", expected_revision: value.revision, preferences: draft },
      title: "Save CIGAR update preferences", detail: "Save these update choices without changing or starting the selected runtime.",
    })}>Save update preferences</button>
  </section>;
}
