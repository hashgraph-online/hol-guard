import { useCallback, useEffect, useMemo, useState } from "react";
import type { ChangeEvent } from "react";
import {
  HiMiniArrowPath,
  HiMiniArrowRight,
  HiMiniBeaker,
  HiMiniBolt,
  HiMiniCheckCircle,
  HiMiniClipboardDocument,
  HiMiniCloud,
  HiMiniCodeBracket,
  HiMiniDocumentText,
  HiMiniGlobeAlt,
  HiMiniNoSymbol,
  HiMiniPlay,
  HiMiniQueueList,
  HiMiniShieldCheck,
  HiMiniCommandLine,
} from "react-icons/hi2";
import { ActionButton, Badge, EmptyState, SectionLabel } from "./approval-center-primitives";
import { formatRelativeTime, policyActionLabel } from "./approval-center-utils";
import { fetchSettings, updateSettings } from "./guard-api";
import type { GuardRuntimeSnapshot, GuardSettings } from "./guard-types";
import {
  fingerprintLocalPolicySettings,
  resolveStrictFileWriteAction,
  resolveStrictScenarioOutcome,
  simulateStrictPolicyOutcome,
  STRICT_POLICY_DEFAULTS,
  STRICT_POLICY_EVALUATION_ORDER,
  type StrictScenarioId,
} from "./policy-strict-config-utils";
import {
  applyStrictConfigPatch,
  resolveStrictConfigPatch,
  StrictConfigActionSegmented,
  type StrictConfigSettingKey,
} from "./policy-strict-config-segmented";
import { formatPolicyDateTime, resolveCloudPolicyBundleCopy } from "./policy-workspace-helpers";

type PolicyStrictConfigTabProps = {
  snapshot: GuardRuntimeSnapshot;
  onOpenSettings?: () => void;
  onOpenInbox?: () => void;
  onReloadPolicy?: () => void;
  reloadingPolicy?: boolean;
};

type LoadState = "loading" | "ready" | "error";

const EVALUATION_STEPS = [
  {
    label: "Local rule",
    description: "Remembered decisions on this device.",
    icon: HiMiniQueueList,
    surfaceClass: "bg-violet-50 text-violet-700 border-violet-200",
  },
  {
    label: "Cloud policy",
    description: "Team rules from Guard Cloud.",
    icon: HiMiniCloud,
    surfaceClass: "bg-sky-50 text-sky-700 border-sky-200",
  },
  {
    label: "Cloud exception",
    description: "Signed risk acceptances.",
    icon: HiMiniCloud,
    surfaceClass: "bg-sky-50 text-sky-700 border-sky-200",
  },
  {
    label: "Strict fallback",
    description: "Local strict policy settings.",
    icon: HiMiniShieldCheck,
    surfaceClass: "bg-amber-50 text-amber-800 border-amber-200",
  },
  {
    label: "Ask or block",
    description: "Final prompt or block.",
    icon: HiMiniNoSymbol,
    surfaceClass: "bg-rose-50 text-rose-700 border-rose-200",
  },
] as const;

const WHAT_CHANGES_BULLETS = [
  "First-time actions follow your default strict action.",
  "Changed tool hashes trigger your configured review path.",
  "New network domains and subprocesses use strict fallback rules.",
  "Cloud exceptions and remembered rules still win when they match.",
] as const;

const TEST_SCENARIOS: Array<{
  id: StrictScenarioId;
  label: string;
  remembered: "allow" | "block" | "none";
  cloudPolicy: "allow" | "block" | "none";
  cloudException: boolean;
}> = [
  {
    id: "first-time",
    label: "New tool contacting unknown domain",
    remembered: "none",
    cloudPolicy: "none",
    cloudException: false,
  },
  {
    id: "remembered-allow",
    label: "Remembered allow wins",
    remembered: "allow",
    cloudPolicy: "block",
    cloudException: false,
  },
  {
    id: "cloud-exception",
    label: "Active Cloud exception",
    remembered: "block",
    cloudPolicy: "block",
    cloudException: true,
  },
];

function resolveExpectedActionTone(action: string): "success" | "destructive" | "warning" | "default" {
  if (action === "block") {
    return "destructive";
  }
  if (action === "allow") {
    return "success";
  }
  if (action === "warn" || action === "review" || action === "require-reapproval") {
    return "warning";
  }
  return "default";
}

export function PolicyStrictConfigTab({
  snapshot,
  onOpenSettings,
  onOpenInbox,
  onReloadPolicy,
  reloadingPolicy = false,
}: PolicyStrictConfigTabProps) {
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [settings, setSettings] = useState<GuardSettings | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [simRemembered, setSimRemembered] = useState<"allow" | "block" | "none">("none");
  const [simCloudPolicy, setSimCloudPolicy] = useState<"allow" | "block" | "none">("none");
  const [simCloudException, setSimCloudException] = useState(false);
  const [scenarioId, setScenarioId] = useState<StrictScenarioId>("first-time");
  const [simulationVisible, setSimulationVisible] = useState(false);

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

  const scenarioOutcome = useMemo(() => {
    if (!settings) {
      return null;
    }
    return resolveStrictScenarioOutcome(scenarioId, settings);
  }, [scenarioId, settings]);

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

  const persistSecurityLevel = useCallback(async (enabled: boolean) => {
    if (!settings) {
      return;
    }
    const nextLevel = enabled ? "strict" : "balanced";
    const previousSettings = settings;
    setSettings({ ...settings, security_level: nextLevel });
    setSaveError(null);
    try {
      const payload = await updateSettings({ security_level: nextLevel });
      setSettings(payload.settings);
    } catch (error) {
      setSettings(previousSettings);
      setSaveError(error instanceof Error ? error.message : "Unable to update strict mode.");
    }
  }, [settings]);

  const handleStrictToggle = useCallback(() => {
    void persistSecurityLevel(!isStrict);
  }, [isStrict, persistSecurityLevel]);

  const handleStrictConfigChange = useCallback(
    (key: StrictConfigSettingKey, value: string) => {
      void persistSetting(key, value);
    },
    [persistSetting],
  );

  const handleResetDefaults = useCallback(() => {
    if (!settings) {
      return;
    }
    void (async () => {
      setSaveError(null);
      try {
        const payload = await updateSettings({
          default_action: STRICT_POLICY_DEFAULTS.default_action,
          changed_hash_action: STRICT_POLICY_DEFAULTS.changed_hash_action,
          new_network_domain_action: STRICT_POLICY_DEFAULTS.new_network_domain_action,
          subprocess_action: STRICT_POLICY_DEFAULTS.subprocess_action,
          risk_actions: {
            ...settings.risk_actions,
            destructive_shell: STRICT_POLICY_DEFAULTS.destructive_shell,
          },
        });
        setSettings(payload.settings);
      } catch (error) {
        setSaveError(error instanceof Error ? error.message : "Unable to reset strict defaults.");
      }
    })();
  }, [settings]);

  const handleCopyHash = useCallback(() => {
    if (!localPolicyHash || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(localPolicyHash);
  }, [localPolicyHash]);

  const handleRunSimulation = useCallback(() => {
    setSimulationVisible(true);
  }, []);

  const handleScenarioChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    const nextId = event.target.value as StrictScenarioId;
    setScenarioId(nextId);
    setSimulationVisible(false);
    const scenario = TEST_SCENARIOS.find((item) => item.id === nextId);
    if (!scenario) {
      return;
    }
    setSimRemembered(scenario.remembered);
    setSimCloudPolicy(scenario.cloudPolicy);
    setSimCloudException(scenario.cloudException);
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
  const lastReloadAt = snapshot.runtime_state?.started_at ?? snapshot.generated_at ?? null;
  const lastReloadFormatted = formatPolicyDateTime(lastReloadAt);
  const lastAckAt = snapshot.cloud_policy_last_ack_at?.trim() ?? null;
  const daemonAckLabel = cloudBundleCopy?.tone === "green" ? "Acknowledged" : cloudBundleCopy?.label ?? "Pending";
  const expectedAction = scenarioOutcome?.outcome ?? settings?.new_network_domain_action ?? "review";
  const expectedReasoning = scenarioOutcome?.reasoning ?? "";

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px] lg:items-start">
      <div className="space-y-4">
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
                <HiMiniShieldCheck className="h-5 w-5" aria-hidden="true" />
              </span>
              <div>
                <h3 className="text-base font-semibold text-brand-dark">Strict mode</h3>
                <p className="mt-1 text-sm text-slate-600">Local enforcement tuning when no other rule matches.</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-500">{isStrict ? "Enabled" : "Disabled"}</span>
              <button
                type="button"
                role="switch"
                aria-checked={isStrict}
                aria-label="Toggle strict mode"
                disabled={controlsDisabled}
                onClick={handleStrictToggle}
                className={`relative h-7 w-12 shrink-0 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/60 ${
                  isStrict ? "bg-brand-blue" : "bg-slate-200"
                } ${controlsDisabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white shadow-sm transition-transform ${
                    isStrict ? "translate-x-5" : "translate-x-0"
                  }`}
                />
              </button>
            </div>
          </div>

          <dl className="mt-5 grid gap-4 border-t border-slate-100 pt-4 sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Strict mode</dt>
              <dd className="mt-1.5 text-sm font-medium text-brand-dark">{isStrict ? "Enabled" : "Disabled"}</dd>
            </div>
            <div>
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Policy hash</dt>
              <dd className="mt-1.5 flex items-center gap-1.5 font-mono text-sm text-brand-dark">
                {localPolicyHash}
                <button
                  type="button"
                  onClick={handleCopyHash}
                  className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark"
                  aria-label="Copy policy hash"
                >
                  <HiMiniClipboardDocument className="h-4 w-4" aria-hidden="true" />
                </button>
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Daemon ack</dt>
              <dd className="mt-1.5 flex items-center gap-1.5 text-sm text-brand-dark">
                {cloudBundleCopy?.tone === "green" ? (
                  <HiMiniCheckCircle className="h-4 w-4 text-emerald-600" aria-hidden="true" />
                ) : null}
                <span>
                  {daemonAckLabel}
                  {lastAckAt ? ` · ${formatRelativeTime(lastAckAt)}` : ""}
                </span>
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Last reload</dt>
              <dd className="mt-1.5 text-sm text-brand-dark">
                {lastReloadFormatted ?? (lastReloadAt ? formatRelativeTime(lastReloadAt) : "Unavailable")}
              </dd>
              <p className="mt-1 text-xs text-emerald-700">Auto-reload on</p>
            </div>
          </dl>

          {!isStrict && onOpenSettings ? (
            <div className="mt-4 border-t border-slate-100 pt-4">
              <ActionButton variant="secondary" onClick={onOpenSettings}>
                Enable in Settings
              </ActionButton>
            </div>
          ) : null}

          {onReloadPolicy ? (
            <div className="mt-4 flex justify-end border-t border-slate-100 pt-4">
              <ActionButton variant="secondary" onClick={onReloadPolicy} disabled={reloadingPolicy}>
                <HiMiniArrowPath className={`mr-1.5 h-4 w-4 ${reloadingPolicy ? "animate-spin" : ""}`} aria-hidden="true" />
                Reload policy
              </ActionButton>
            </div>
          ) : null}
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <SectionLabel>Local strict policy</SectionLabel>
              <p className="mt-2 text-sm text-slate-600">
                Fallback controls when no remembered rule, Cloud policy, or Cloud exception matches.
              </p>
            </div>
            <button
              type="button"
              onClick={handleResetDefaults}
              disabled={controlsDisabled}
              className="text-sm font-medium text-brand-blue hover:underline disabled:opacity-50"
            >
              Reset to defaults
            </button>
          </div>
          <div className="mt-5 divide-y divide-slate-100">
            <StrictConfigActionSegmented
              label="Default action"
              help="For any action not explicitly allowed."
              icon={HiMiniBolt}
              value={settings.default_action}
              settingKey="default_action"
              onSettingChange={handleStrictConfigChange}
              disabled={controlsDisabled}
            />
            <StrictConfigActionSegmented
              label="Changed tool hash action"
              help="When a tool or script hash is new."
              icon={HiMiniCodeBracket}
              value={settings.changed_hash_action}
              settingKey="changed_hash_action"
              onSettingChange={handleStrictConfigChange}
              disabled={controlsDisabled}
            />
            <StrictConfigActionSegmented
              label="New network domain action"
              help="When a process tries to contact a new domain."
              icon={HiMiniGlobeAlt}
              value={settings.new_network_domain_action}
              settingKey="new_network_domain_action"
              onSettingChange={handleStrictConfigChange}
              disabled={controlsDisabled}
            />
            <StrictConfigActionSegmented
              label="Subprocess action"
              help="When a process tries to launch another program."
              icon={HiMiniCommandLine}
              value={settings.subprocess_action}
              settingKey="subprocess_action"
              onSettingChange={handleStrictConfigChange}
              disabled={controlsDisabled}
            />
            <StrictConfigActionSegmented
              label="File write action"
              help="When a process writes to disk."
              icon={HiMiniDocumentText}
              value={fileWriteAction}
              settingKey="destructive_shell"
              onSettingChange={handleStrictConfigChange}
              disabled={controlsDisabled}
            />
          </div>
          <p className="mt-4 flex items-start gap-2 text-xs text-slate-500">
            <HiMiniShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
            These settings apply only when no local or Cloud rules cover the action.
          </p>
          {saveError ? <p className="mt-3 text-sm text-red-600">{saveError}</p> : null}
          {savingKey ? <p className="mt-3 text-sm text-slate-500">Saving {savingKey.replace(/_/g, " ")}…</p> : null}
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <SectionLabel>Local enforcement preview</SectionLabel>
          <p className="mt-2 text-sm text-slate-600">Evaluation order when Guard decides what to do next.</p>
          <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
            {EVALUATION_STEPS.map((step, index) => {
              const Icon = step.icon;
              return (
                <div key={step.label} className="relative">
                  <div className={`rounded-xl border p-3 ${step.surfaceClass}`}>
                    <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/70">
                      <Icon className="h-4 w-4" aria-hidden="true" />
                    </span>
                    <p className="mt-2 text-sm font-semibold text-brand-dark">{step.label}</p>
                    <p className="mt-1 text-xs leading-relaxed text-slate-600">{step.description}</p>
                  </div>
                  {index < EVALUATION_STEPS.length - 1 ? (
                    <HiMiniArrowRight
                      className="absolute top-1/2 -right-3 hidden h-4 w-4 -translate-y-1/2 text-slate-300 xl:block"
                      aria-hidden="true"
                    />
                  ) : null}
                </div>
              );
            })}
          </div>
          <p className="mt-4 text-xs text-slate-500">
            Evaluation order: {STRICT_POLICY_EVALUATION_ORDER.join(" → ")}. Team-wide exceptions are managed in Guard
            Cloud.
          </p>
        </div>
      </div>

      <aside className="space-y-4 lg:sticky lg:top-4">
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <SectionLabel>What this changes</SectionLabel>
          <ul className="mt-3 space-y-2 text-sm text-slate-600">
            {WHAT_CHANGES_BULLETS.map((item) => (
              <li key={item} className="flex gap-2">
                <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" aria-hidden="true" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <SectionLabel>Affected pending Inbox items</SectionLabel>
          <p className="mt-2 text-3xl font-semibold tabular-nums text-brand-dark">
            {pendingInboxCount}
            <span className="ml-1 text-base font-medium text-slate-500">items</span>
          </p>
          <p className="mt-1 text-sm text-slate-600">
            Pending review items may be affected by stricter fallback controls.
          </p>
          {onOpenInbox && pendingInboxCount > 0 ? (
            <div className="mt-3">
              <ActionButton variant="secondary" onClick={onOpenInbox}>
                Open Inbox
                <HiMiniArrowRight className="ml-1.5 h-4 w-4" aria-hidden="true" />
              </ActionButton>
            </div>
          ) : null}
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-sm">
          <p className="font-medium text-brand-dark">Cloud exceptions still apply</p>
          <p className="mt-2 leading-relaxed">
            Signed Cloud exceptions still require bundle acknowledgement before they apply locally.
          </p>
        </div>

        <div className="rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 shadow-sm">
          <div className="flex items-start gap-2">
            <HiMiniBeaker className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <SectionLabel>Test policy</SectionLabel>
              <p className="mt-2 text-sm text-slate-600">Simulate how Guard will respond.</p>
            </div>
          </div>
          <label className="mt-4 block space-y-1.5">
            <span className="text-sm font-medium text-brand-dark">Scenario</span>
            <select
              value={scenarioId}
              onChange={handleScenarioChange}
              className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark"
            >
              {TEST_SCENARIOS.map((scenario) => (
                <option key={scenario.id} value={scenario.id}>
                  {scenario.label}
                </option>
              ))}
            </select>
          </label>
          <div className="mt-4 space-y-2">
            <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Expected action</p>
            <Badge tone={resolveExpectedActionTone(expectedAction)}>{policyActionLabel(expectedAction)}</Badge>
            {expectedReasoning ? <p className="text-sm text-slate-600">{expectedReasoning}</p> : null}
          </div>
          <div className="mt-4">
            <ActionButton variant="secondary" onClick={handleRunSimulation}>
              <HiMiniPlay className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Run simulation
            </ActionButton>
          </div>
          {simulationVisible && simulation ? (
            <div className="mt-4 rounded-xl border border-slate-100 bg-white p-4">
              <p className="text-sm font-medium text-brand-dark">
                Policy simulator outcome: {policyActionLabel(simulation.outcome)} ({simulation.winningStep})
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
