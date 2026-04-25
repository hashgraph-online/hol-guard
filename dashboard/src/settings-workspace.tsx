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

const securityLevels = [
  {
    value: "balanced",
    label: "Balanced",
    description: "Ask before secret access, hidden execution, exfiltration, and destructive actions."
  },
  {
    value: "strict",
    label: "Strict",
    description: "Ask more often, including new network destinations."
  },
  {
    value: "custom",
    label: "Custom",
    description: "Use the exact choices below for this machine and connected apps."
  }
] as const;

const riskControls = [
  {
    key: "local_secret_read",
    label: "Local secrets",
    description: "Files such as .env, .npmrc, .netrc, SSH keys, and cloud credentials."
  },
  {
    key: "credential_exfiltration",
    label: "Credential sharing",
    description: "Commands or scripts that appear to send keys, tokens, or credentials away."
  },
  {
    key: "destructive_shell",
    label: "Destructive commands",
    description: "Shell actions that delete, overwrite, or rewrite local files."
  },
  {
    key: "encoded_execution",
    label: "Hidden scripts",
    description: "Encoded, encrypted, or decoded-and-run command payloads."
  },
  {
    key: "network_egress",
    label: "New network destinations",
    description: "Outbound connections Guard has not seen in this context."
  }
] as const;

type RiskKey = (typeof riskControls)[number]["key"];

const riskProfileActions: Record<"balanced" | "strict" | "custom", Record<RiskKey, string>> = {
  balanced: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn"
  },
  strict: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "require-reapproval"
  },
  custom: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn"
  }
};

function normalizeSettingsPayload(payload: GuardSettingsPayload): GuardSettingsPayload {
  return {
    ...payload,
    settings: normalizeGuardSettings(payload.settings)
  };
}

function normalizeGuardSettings(settings: GuardSettings): GuardSettings {
  const defaults = riskProfileActions[settings.security_level];
  const explicitOverrides = settings.risk_action_overrides ?? {};
  const effectiveRiskActions = riskControls.reduce<Record<RiskKey, string>>((actions, risk) => {
    actions[risk.key] = settings.risk_actions?.[risk.key] ?? explicitOverrides[risk.key] ?? defaults[risk.key];
    return actions;
  }, {} as Record<RiskKey, string>);
  return {
    ...settings,
    risk_actions: effectiveRiskActions,
    risk_action_overrides: explicitOverrides,
    harness_risk_actions: settings.harness_risk_actions ?? {}
  };
}

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
          const normalizedPayload = normalizeSettingsPayload(payload);
          setState({ kind: "ready", payload: normalizedPayload });
          setDraft(normalizedPayload.settings);
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

  const handleSecurityLevelChange = useCallback((securityLevel: GuardSettings["security_level"]) => {
    setDraft((value) => {
      if (value === null) return value;
      if (securityLevel === "custom") {
        return { ...value, security_level: securityLevel };
      }
      return {
        ...value,
        security_level: securityLevel,
        risk_actions: riskProfileActions[securityLevel],
        risk_action_overrides: {},
        harness_risk_actions: {}
      };
    });
    setSavedMessage(null);
  }, []);

  const handleRiskActionChange = useCallback(
    (riskKey: string) => (event: ChangeEvent<HTMLSelectElement>) => {
      setDraft((value) => {
        if (value === null) return value;
        return {
          ...value,
          security_level: "custom",
          risk_actions: {
            ...value.risk_actions,
            [riskKey]: event.target.value
          },
          risk_action_overrides: {
            ...value.risk_action_overrides,
            [riskKey]: event.target.value
          }
        };
      });
      setSavedMessage(null);
    },
    []
  );

  const handleCodexSecretReadChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setDraft((value) => {
      if (value === null) return value;
      return {
        ...value,
        security_level: "custom",
        harness_risk_actions: {
          ...value.harness_risk_actions,
          codex: {
            ...(value.harness_risk_actions.codex ?? {}),
            local_secret_read: event.target.value
          }
        }
      };
    });
    setSavedMessage(null);
  }, []);

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
      const payload = await updateSettings({
        ...draft,
        risk_actions: draft.security_level === "custom" ? draft.risk_actions : draft.risk_action_overrides
      });
      const normalizedPayload = normalizeSettingsPayload(payload);
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
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
              Choose how protective HOL Guard should be.
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/70">
              Start with a simple security level, then tune exact risk types when a trusted app needs more room to work.
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
            <SectionLabel>Security level</SectionLabel>
            <div className="mt-4 grid gap-3 md:grid-cols-3">
              {securityLevels.map((level) => (
                <button
                  key={level.value}
                  type="button"
                  onClick={() => handleSecurityLevelChange(level.value)}
                  className={`min-h-32 rounded-[1.5rem] border p-4 text-left transition-all duration-150 ${
                    draft.security_level === level.value
                      ? "border-brand-blue/35 bg-brand-blue/[0.07] shadow-[0_12px_32px_rgba(85,153,254,0.14)]"
                      : "border-transparent bg-surface-1/80 hover:bg-white"
                  }`}
                >
                  <span className="text-base font-semibold text-brand-dark">{level.label}</span>
                  <span className="mt-2 block text-sm leading-6 text-muted-foreground">{level.description}</span>
                </button>
              ))}
            </div>
          </div>

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
            <SectionLabel>Risk choices</SectionLabel>
            <div className="mt-4 divide-y divide-slate-200/70 overflow-hidden rounded-[1.35rem] border border-slate-200/70 bg-white">
              {riskControls.map((risk) => (
                <div key={risk.key} className="grid gap-3 px-4 py-4 md:grid-cols-[minmax(0,1fr)_220px] md:items-center">
                  <div>
                    <p className="text-sm font-semibold text-brand-dark">{risk.label}</p>
                    <p className="mt-1 text-sm leading-6 text-muted-foreground">{risk.description}</p>
                  </div>
                  <SettingSelect
                    label="Guard should"
                    value={draft.risk_actions[risk.key] ?? "require-reapproval"}
                    options={actionOptions}
                    onChange={handleRiskActionChange(risk.key)}
                  />
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Codex override</SectionLabel>
            <div className="mt-4 grid gap-4 md:grid-cols-[minmax(0,1fr)_260px] md:items-center">
              <div>
                <p className="text-sm font-semibold text-brand-dark">Codex reading local secret files</p>
                <p className="mt-1 text-sm leading-6 text-muted-foreground">
                  Use this only for trusted projects where Codex should be allowed to open files such as .env or .npmrc.
                </p>
              </div>
              <SettingSelect
                label="Codex should"
                value={draft.harness_risk_actions.codex?.local_secret_read ?? draft.risk_actions.local_secret_read ?? "require-reapproval"}
                options={actionOptions}
                onChange={handleCodexSecretReadChange}
              />
            </div>
          </div>

          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Advanced defaults</SectionLabel>
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
