import { useCallback, useEffect, useMemo, useState } from "react";
import type { ChangeEvent } from "react";
import { ActionButton, EmptyState, SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime, policyActionLabel } from "./approval-center-utils";
import { fetchSettings, updateSettings } from "./guard-api";
import type { GuardRuntimeSnapshot, GuardSettings } from "./guard-types";
import {
  fingerprintLocalPolicySettings,
  resolveStrictFileWriteAction,
  simulateStrictPolicyOutcome,
  STRICT_POLICY_LAYER_OPTIONS,
  STRICT_POLICY_EVALUATION_ORDER,
} from "./policy-strict-config-utils";
import {
  applyStrictConfigPatch,
  resolveStrictConfigPatch,
  StrictConfigActionSegmented,
  type StrictConfigSettingKey,
} from "./policy-strict-config-segmented";
import { resolveCloudPolicyBundleCopy } from "./policy-workspace-helpers";

type PolicyStrictConfigTabProps = {
  snapshot: GuardRuntimeSnapshot;
  onOpenSettings?: () => void;
  onOpenInbox?: () => void;
};

type LoadState = "loading" | "ready" | "error";

type SimLayerSelectProps = {
  label: string;
  value: "allow" | "block" | "none";
  onChange: (value: "allow" | "block" | "none") => void;
};

function SimLayerSelect({ label, value, onChange }: SimLayerSelectProps) {
  const handleChange = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => {
      const nextValue = event.target.value;
      if (nextValue === "allow" || nextValue === "block" || nextValue === "none") {
        onChange(nextValue);
      }
    },
    [onChange],
  );

  return (
    <label className="block space-y-1.5">
      <span className="text-sm font-medium text-brand-dark">{label}</span>
      <select
        value={value}
        onChange={handleChange}
        className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark"
      >
        {STRICT_POLICY_LAYER_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function PolicyStrictConfigTab({
  snapshot,
  onOpenSettings,
  onOpenInbox,
}: PolicyStrictConfigTabProps) {
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [settings, setSettings] = useState<GuardSettings | null>(null);
  const [configPath, setConfigPath] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [simRemembered, setSimRemembered] = useState<"allow" | "block" | "none">("none");
  const [simCloudPolicy, setSimCloudPolicy] = useState<"allow" | "block" | "none">("none");
  const [simCloudException, setSimCloudException] = useState(false);

  const isStrict = settings?.security_level === "strict";
  const cloudBundleCopy = resolveCloudPolicyBundleCopy(snapshot);
  const pendingInboxCount = snapshot.queue_summary?.remaining_pending_count ?? snapshot.pending_count ?? 0;

  useEffect(() => {
    let cancelled = false;
    setLoadState("loading");
    setLoadError(null);
    void fetchSettings()
      .then((payload) => {
        if (cancelled) {
          return;
        }
        setSettings(payload.settings);
        setConfigPath(payload.config_path);
        setLoadState("ready");
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        setLoadState("error");
        setLoadError(error instanceof Error ? error.message : "Unable to load strict config.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const localPolicyHash = useMemo(
    () => (settings ? fingerprintLocalPolicySettings(settings) : null),
    [settings],
  );

  const simulation = useMemo(() => {
    if (!settings) {
      return null;
    }
    return simulateStrictPolicyOutcome({
      rememberedRuleAction: simRemembered,
      cloudPolicyAction: simCloudPolicy,
      cloudExceptionActive: simCloudException,
      fallbackAction: settings.default_action,
    });
  }, [settings, simRemembered, simCloudPolicy, simCloudException]);

  const persistSetting = useCallback(async (key: StrictConfigSettingKey, value: string) => {
    if (!settings) {
      return;
    }
    const previousSettings = settings;
    const updatedSettings = applyStrictConfigPatch(settings, key, value);

    setSettings(updatedSettings);
    setSavingKey(key);
    setSaveError(null);

    const nextSettings = resolveStrictConfigPatch(settings, key, value);

    try {
      const payload = await updateSettings(nextSettings);
      setSettings(payload.settings);
    } catch (error) {
      setSettings(previousSettings);
      setSaveError(error instanceof Error ? error.message : "Unable to save strict config.");
    } finally {
      setSavingKey(null);
    }
  }, [settings]);

  const handleStrictConfigChange = useCallback(
    (key: StrictConfigSettingKey, value: string) => {
      void persistSetting(key, value);
    },
    [persistSetting],
  );

  const handleSimCloudExceptionChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSimCloudException(event.target.checked);
  }, []);
  const handleSimRememberedChange = useCallback((value: "allow" | "block" | "none") => {
    setSimRemembered(value);
  }, []);
  const handleSimCloudPolicyChange = useCallback((value: "allow" | "block" | "none") => {
    setSimCloudPolicy(value);
  }, []);

  if (loadState === "loading") {
    return (
      <div className="space-y-3" aria-busy="true">
        {[0, 1, 2].map((index) => (
          <div key={index} className="h-24 animate-pulse rounded-2xl border border-slate-200 bg-slate-100" />
        ))}
      </div>
    );
  }

  if (loadState === "error" || !settings) {
    return (
      <EmptyState
        title="Could not load strict config"
        body={loadError ?? "Try again from Settings if the daemon is unavailable."}
      />
    );
  }

  const fileWriteAction = resolveStrictFileWriteAction(settings);
  const controlsDisabled = savingKey !== null;

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px] lg:items-start">
      <div className="space-y-4">
        <div
          className={`rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`}
        >
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SectionLabel>Strict mode</SectionLabel>
            <Tag tone={isStrict ? "green" : "slate"}>{isStrict ? "Enabled" : "Disabled"}</Tag>
          </div>
          <p className="text-sm text-brand-dark/75">
            Strict config tunes local fallback enforcement only. Authentication, MFA, and general Guard settings stay in
            Settings.
          </p>
          {!isStrict && onOpenSettings ? (
            <div className="mt-3">
              <ActionButton variant="secondary" onClick={onOpenSettings}>
                Enable strict mode in Settings
              </ActionButton>
            </div>
          ) : null}
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <SectionLabel>Local policy state</SectionLabel>
          <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Local policy hash</dt>
              <dd className="mt-1 font-mono text-xs text-brand-dark">{localPolicyHash}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Config file</dt>
              <dd className="mt-1 break-all text-brand-dark">{configPath ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Daemon last reload</dt>
              <dd className="mt-1 text-brand-dark">
                {snapshot.runtime_state?.started_at
                  ? formatRelativeTime(snapshot.runtime_state.started_at)
                  : "Unavailable"}
              </dd>
            </div>
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Daemon heartbeat</dt>
              <dd className="mt-1 text-brand-dark">
                {snapshot.runtime_state?.last_heartbeat_at
                  ? formatRelativeTime(snapshot.runtime_state.last_heartbeat_at)
                  : "Unavailable"}
              </dd>
            </div>
          </dl>
          {cloudBundleCopy ? (
            <div className="mt-4 rounded-xl border border-slate-100 bg-slate-50/80 p-3">
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Signed Cloud bundle ack</p>
              <p className="mt-1 text-sm font-medium text-brand-dark">{cloudBundleCopy.label}</p>
              <p className="mt-1 text-sm text-slate-600">{cloudBundleCopy.detail}</p>
              {snapshot.cloud_policy_bundle_hash ? (
                <p className="mt-2 break-all font-mono text-[11px] text-slate-500">
                  {snapshot.cloud_policy_bundle_hash}
                </p>
              ) : null}
              <p className="mt-2 text-xs text-slate-500">
                Cloud exceptions apply through signed bundle acknowledgement on this device.
              </p>
            </div>
          ) : (
            <p className="mt-4 text-sm text-slate-600">
              No signed Cloud policy bundle is synced yet. Cloud exceptions still require bundle acknowledgement before
              they apply locally.
            </p>
          )}
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <SectionLabel>Local fallback controls</SectionLabel>
        <p className="mt-2 text-sm text-slate-600">
          These controls apply when no remembered rule, Cloud policy, or Cloud exception matches.
        </p>
        <div className="mt-4 grid gap-5 md:grid-cols-2">
          <StrictConfigActionSegmented
            label="Default action"
            help="First-time actions with no prior decision."
            value={settings.default_action}
            settingKey="default_action"
            onSettingChange={handleStrictConfigChange}
            disabled={controlsDisabled}
          />
          <StrictConfigActionSegmented
            label="Changed tool hash action"
            value={settings.changed_hash_action}
            settingKey="changed_hash_action"
            onSettingChange={handleStrictConfigChange}
            disabled={controlsDisabled}
          />
          <StrictConfigActionSegmented
            label="New network domain action"
            value={settings.new_network_domain_action}
            settingKey="new_network_domain_action"
            onSettingChange={handleStrictConfigChange}
            disabled={controlsDisabled}
          />
          <StrictConfigActionSegmented
            label="Subprocess action"
            value={settings.subprocess_action}
            settingKey="subprocess_action"
            onSettingChange={handleStrictConfigChange}
            disabled={controlsDisabled}
          />
          <StrictConfigActionSegmented
            label="Destructive file write action"
            help="Backed by the destructive shell risk control."
            value={fileWriteAction}
            settingKey="destructive_shell"
            onSettingChange={handleStrictConfigChange}
            disabled={controlsDisabled}
          />
        </div>
        {saveError ? <p className="mt-3 text-sm text-red-600">{saveError}</p> : null}
        {savingKey ? <p className="mt-3 text-sm text-slate-500">Saving {savingKey.replace(/_/g, " ")}…</p> : null}
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <SectionLabel>Pending Inbox impact</SectionLabel>
        <p className="mt-2 text-sm text-brand-dark/75">
          {pendingInboxCount > 0
            ? `${pendingInboxCount} pending review item${pendingInboxCount === 1 ? "" : "s"} may be affected by stricter fallback controls.`
            : "No pending Inbox items are waiting for review right now."}
        </p>
        {onOpenInbox && pendingInboxCount > 0 ? (
          <div className="mt-3">
            <ActionButton variant="secondary" onClick={onOpenInbox}>
              Open Inbox
            </ActionButton>
          </div>
        ) : null}
      </div>
      </div>

      <aside className="space-y-4 lg:sticky lg:top-4">
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <SectionLabel>Evaluation order</SectionLabel>
          <ol className="mt-3 space-y-2 text-sm text-brand-dark/80">
            {STRICT_POLICY_EVALUATION_ORDER.map((step, index) => (
              <li key={step} className="flex gap-2">
                <span className="font-semibold text-brand-blue">{index + 1}.</span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>

        <div className="rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 shadow-sm">
          <SectionLabel>Policy simulator</SectionLabel>
          <p className="mt-2 text-sm text-slate-600">
            Preview which layer wins for a hypothetical action without changing live policy.
          </p>
          <div className="mt-4 space-y-3">
            <SimLayerSelect label="Remembered rule" value={simRemembered} onChange={handleSimRememberedChange} />
            <SimLayerSelect label="Cloud policy" value={simCloudPolicy} onChange={handleSimCloudPolicyChange} />
            <label className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark">
              <input type="checkbox" checked={simCloudException} onChange={handleSimCloudExceptionChange} />
              Active Cloud exception
            </label>
          </div>
          {simulation ? (
            <div className="mt-4 rounded-xl border border-slate-100 bg-white p-4">
              <p className="text-sm font-medium text-brand-dark">
                Outcome: {policyActionLabel(simulation.outcome)} ({simulation.winningStep})
              </p>
              <ul className="mt-2 space-y-1 text-xs text-slate-600">
                {simulation.path.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      </aside>
    </div>
  );
}
