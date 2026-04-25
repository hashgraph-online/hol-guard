import { useCallback, useEffect, useState, type ChangeEvent } from "react";

import {
  ActionButton,
  Badge,
  EmptyState,
  SectionLabel,
  Tag
} from "./approval-center-primitives";
import { fetchSettings, updateSettings } from "./guard-api";
import type { GuardSettings, GuardSettingsPayload } from "./guard-types";

type SettingsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; payload: GuardSettingsPayload };

const actionOptions = [
  { value: "allow", label: "Allow" },
  { value: "warn", label: "Warn" },
  { value: "review", label: "Review" },
  { value: "require-reapproval", label: "Ask again" },
  { value: "sandbox-required", label: "Require sandbox" },
  { value: "block", label: "Block" }
];

const surfacePolicyOptions = [
  { value: "auto-open-once", label: "Open approval center once" },
  { value: "approval-center", label: "Approval center only" },
  { value: "native-only", label: "Harness prompt only" }
];

export function SettingsWorkspace() {
  const [state, setState] = useState<SettingsState>({ kind: "loading" });
  const [draft, setDraft] = useState<GuardSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchSettings()
      .then((payload) => {
        if (!cancelled) {
          setState({ kind: "ready", payload });
          setDraft(payload.settings);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load Guard settings."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleStringChange = useCallback(
    (key: keyof GuardSettings) => (event: ChangeEvent<HTMLSelectElement>) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.value });
      setSavedMessage(null);
    },
    []
  );

  const handleTimeoutChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const nextValue = Number.parseInt(event.target.value, 10);
    setDraft((value) => value === null ? value : { ...value, approval_wait_timeout_seconds: Number.isNaN(nextValue) ? 0 : nextValue });
    setSavedMessage(null);
  }, []);

  const handleModeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setDraft((value) => value === null ? value : { ...value, mode: event.target.value as GuardSettings["mode"] });
    setSavedMessage(null);
  }, []);

  const handleBooleanChange = useCallback(
    (key: keyof GuardSettings) => (event: ChangeEvent<HTMLInputElement>) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.checked });
      setSavedMessage(null);
    },
    []
  );

  const handleSave = useCallback(async () => {
    if (draft === null) return;
    setSaving(true);
    setSavedMessage(null);
    try {
      const payload = await updateSettings(draft);
      setState({ kind: "ready", payload });
      setDraft(payload.settings);
      setSavedMessage("Settings saved. New Guard checks use these values immediately.");
    } catch (error) {
      setSavedMessage(error instanceof Error ? error.message : "Unable to save settings.");
    } finally {
      setSaving(false);
    }
  }, [draft]);

  if (state.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-10 w-64" />
        <div className="guard-skeleton h-72 w-full" />
      </div>
    );
  }
  if (state.kind === "error" || draft === null) {
    return <EmptyState title="Settings are unavailable" body={state.kind === "error" ? state.message : "Guard did not return editable settings."} />;
  }

  const modeHelp = draft.mode === "enforce"
    ? "Guard blocks risky actions until a saved decision allows them."
    : draft.mode === "observe"
      ? "Guard records what it sees without pausing actions."
      : "Guard asks before risky actions continue.";

  return (
    <div className="space-y-6">
      <section className="guard-surface-in rounded-[2rem] border border-brand-blue/15 bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_62%,rgba(181,108,255,0.08)_100%)] p-5 shadow-[0_20px_60px_rgba(63,65,116,0.08)] sm:p-6 lg:p-7">
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px] lg:items-start">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <Tag tone="blue">Local settings</Tag>
              <Badge tone="info">{draft.mode}</Badge>
            </div>
            <SectionLabel>Settings</SectionLabel>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-brand-dark">
              Tune how HOL Guard pauses risky actions.
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/70">
              These are the same local controls exposed by the CLI config. Use them when you want Guard to ask more often, run quietly, or wait longer for approval decisions.
            </p>
          </div>
          <div className="rounded-[1.65rem] border border-white/80 bg-white/80 p-4 shadow-[0_16px_40px_rgba(63,65,116,0.10)] backdrop-blur">
            <SectionLabel>Config file</SectionLabel>
            <p className="mt-2 break-words font-mono text-xs leading-5 text-brand-dark/75">{state.payload.config_path}</p>
            <p className="mt-3 text-xs leading-5 text-muted-foreground">
              Changes are saved locally and apply to the next Guard evaluation.
            </p>
          </div>
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-6">
          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Protection mode</SectionLabel>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              {(["prompt", "enforce", "observe"] as const).map((mode) => (
                <label
                  key={mode}
                  className={`cursor-pointer rounded-[1.25rem] border p-4 transition-all duration-150 ${
                    draft.mode === mode ? "border-brand-blue/30 bg-brand-blue/[0.06] shadow-sm" : "border-transparent bg-surface-1/80 hover:bg-white"
                  }`}
                >
                  <input
                    type="radio"
                    name="mode"
                    value={mode}
                    checked={draft.mode === mode}
                    onChange={handleModeChange}
                    className="sr-only"
                  />
                  <span className="text-sm font-semibold capitalize text-brand-dark">{mode}</span>
                </label>
              ))}
            </div>
            <p className="mt-3 text-sm leading-6 text-muted-foreground">{modeHelp}</p>
          </div>

          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Default decisions</SectionLabel>
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <SettingSelect label="New action" value={draft.default_action} options={actionOptions} onChange={handleStringChange("default_action")} />
              <SettingSelect label="Unknown source" value={draft.unknown_publisher_action} options={actionOptions} onChange={handleStringChange("unknown_publisher_action")} />
              <SettingSelect label="Changed command" value={draft.changed_hash_action} options={actionOptions} onChange={handleStringChange("changed_hash_action")} />
              <SettingSelect label="New network domain" value={draft.new_network_domain_action} options={actionOptions} onChange={handleStringChange("new_network_domain_action")} />
              <SettingSelect label="Subprocess action" value={draft.subprocess_action} options={actionOptions} onChange={handleStringChange("subprocess_action")} />
              <SettingSelect label="Approval surface" value={draft.approval_surface_policy} options={surfacePolicyOptions} onChange={handleStringChange("approval_surface_policy")} />
            </div>
          </div>
        </div>

        <aside className="space-y-4">
          <div className="rounded-[1.75rem] border border-brand-blue/15 bg-brand-blue/[0.04] p-5">
            <SectionLabel>Approval wait</SectionLabel>
            <label htmlFor="approval-wait" className="mt-3 block text-sm font-semibold text-brand-dark">
              Seconds to wait before returning to the harness
            </label>
            <input
              id="approval-wait"
              type="number"
              min={0}
              max={600}
              value={draft.approval_wait_timeout_seconds}
              onChange={handleTimeoutChange}
              className="mt-2 min-h-11 w-full rounded-full border border-border bg-white px-4 py-2 text-sm text-brand-dark transition-colors focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            />
          </div>
          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Local toggles</SectionLabel>
            <div className="mt-4 space-y-3">
              <SettingToggle label="Telemetry" checked={draft.telemetry} onChange={handleBooleanChange("telemetry")} />
              <SettingToggle label="Cloud sync" checked={draft.sync} onChange={handleBooleanChange("sync")} />
              <SettingToggle label="Billing features" checked={draft.billing} onChange={handleBooleanChange("billing")} />
            </div>
          </div>
          <div className="sticky top-24 rounded-[1.75rem] border border-white/80 bg-white/90 p-4 shadow-[0_16px_40px_rgba(63,65,116,0.10)] backdrop-blur">
            <ActionButton onClick={handleSave} disabled={saving}>
              {saving ? "Saving…" : "Save settings"}
            </ActionButton>
            {savedMessage ? (
              <p className="guard-fade-in mt-3 text-sm leading-6 text-brand-dark/70">{savedMessage}</p>
            ) : (
              <p className="mt-3 text-xs leading-5 text-muted-foreground">
                Use this for local tuning. Team policy from Guard Cloud may still override some decisions.
              </p>
            )}
          </div>
        </aside>
      </section>
    </div>
  );
}

function SettingSelect(props: {
  label: string;
  value: string;
  options: Array<{ value: string; label: string }>;
  onChange: (event: ChangeEvent<HTMLSelectElement>) => void;
}) {
  return (
    <label className="block">
      <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{props.label}</span>
      <select
        value={props.value}
        onChange={props.onChange}
        className="mt-2 min-h-11 w-full rounded-full border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors duration-150 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
      >
        {props.options.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}

function SettingToggle(props: {
  label: string;
  checked: boolean;
  onChange: (event: ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <label className="flex min-h-11 cursor-pointer items-center justify-between gap-3 rounded-full bg-surface-1 px-4 py-2">
      <span className="text-sm font-semibold text-brand-dark">{props.label}</span>
      <input type="checkbox" checked={props.checked} onChange={props.onChange} className="h-5 w-5 accent-brand-blue" />
    </label>
  );
}
