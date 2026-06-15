import { useCallback, useEffect, useMemo, useState } from "react";
import type { ChangeEvent } from "react";
import {
  HiMiniArrowPath,
  HiMiniArrowRight,
  HiMiniBeaker,
  HiMiniCheckCircle,
  HiMiniCloud,
  HiMiniNoSymbol,
  HiMiniPlay,
  HiMiniQueueList,
  HiMiniShieldCheck,
} from "react-icons/hi2";
import { ActionButton, Badge, EmptyState, SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime, policyActionLabel } from "./approval-center-utils";
import { fetchSettings, updateSettings } from "./guard-api";
import type { GuardRuntimeSnapshot, GuardSettings } from "./guard-types";
import {
  fingerprintLocalPolicySettings,
  resolveStrictFileWriteAction,
  simulateStrictPolicyOutcome,
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
  onReloadPolicy?: () => void;
  reloadingPolicy?: boolean;
};

type LoadState = "loading" | "ready" | "error";

const EVALUATION_STEPS = [
  { label: "Local rule", icon: HiMiniQueueList, tone: "purple" },
  { label: "Cloud policy", icon: HiMiniCloud, tone: "blue" },
  { label: "Cloud exception", icon: HiMiniCloud, tone: "blue" },
  { label: "Strict fallback", icon: HiMiniShieldCheck, tone: "amber" },
  { label: "Ask or block", icon: HiMiniNoSymbol, tone: "red" },
] as const;

const WHAT_CHANGES_BULLETS = [
  "First-time actions follow your default strict action.",
  "Changed tool hashes trigger your configured review path.",
  "New network domains and subprocesses use strict fallback rules.",
  "Cloud exceptions and remembered rules still win when they match.",
] as const;

const TEST_SCENARIOS = [
  {
    id: "first-time",
    label: "New tool contacting unknown domain",
    remembered: "none" as const,
    cloudPolicy: "none" as const,
    cloudException: false,
  },
  {
    id: "remembered-allow",
    label: "Remembered allow wins",
    remembered: "allow" as const,
    cloudPolicy: "block" as const,
    cloudException: false,
  },
  {
    id: "cloud-exception",
    label: "Active Cloud exception",
    remembered: "block" as const,
    cloudPolicy: "block" as const,
    cloudException: true,
  },
] as const;

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
  const [scenarioId, setScenarioId] = useState<string>(TEST_SCENARIOS[0].id);
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

  const handleRunSimulation = useCallback(() => {
    setSimulationVisible(true);
  }, []);

  const handleScenarioChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    const nextId = event.target.value;
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
  const lastReloadAt = snapshot.runtime_state?.started_at ?? null;
  const daemonAckLabel = cloudBundleCopy?.label ?? "Pending";
  const expectedAction = simulation?.outcome ?? settings.default_action;

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
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-base font-semibold text-brand-dark">Strict mode</h3>
                  <Tag tone={isStrict ? "green" : "slate"}>{isStrict ? "Enabled" : "Disabled"}</Tag>
                </div>
                <p className="mt-1 text-sm text-slate-600">Local enforcement tuning.</p>
                <p className="mt-2 text-sm text-brand-dark/75">
                  Guard asks before risky actions that are not already allowed by policy.
                </p>
              </div>
            </div>
            {!isStrict && onOpenSettings ? (
              <ActionButton variant="secondary" onClick={onOpenSettings}>
                Enable in Settings
              </ActionButton>
            ) : null}
          </div>
          <dl className="mt-5 grid gap-4 border-t border-slate-100 pt-4 sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Strict mode</dt>
              <dd className="mt-1.5 text-sm font-medium text-brand-dark">{isStrict ? "Enabled" : "Disabled"}</dd>
            </div>
            <div>
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Policy hash</dt>
              <dd className="mt-1.5 flex items-center gap-1.5 font-mono text-sm text-brand-dark">{localPolicyHash}</dd>
            </div>
            <div>
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Daemon ack</dt>
              <dd className="mt-1.5 flex items-center gap-1.5 text-sm text-brand-dark">
                {cloudBundleCopy ? (
                  <HiMiniCheckCircle className="h-4 w-4 text-emerald-600" aria-hidden="true" />
                ) : null}
                {daemonAckLabel}
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Last reload</dt>
              <dd className="mt-1.5 text-sm text-brand-dark">
                {lastReloadAt ? formatRelativeTime(lastReloadAt) : "Unavailable"}
              </dd>
            </div>
          </dl>
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
          </div>
          <div className="mt-5 divide-y divide-slate-100">
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
              label="File write action"
              help="Backed by the destructive shell risk control."
              value={fileWriteAction}
              settingKey="destructive_shell"
              onSettingChange={handleStrictConfigChange}
              disabled={controlsDisabled}
            />
          </div>
          <p className="mt-4 text-xs text-slate-500">
            These settings apply only when no remembered rule, Cloud policy, or Cloud exception covers the action.
          </p>
          {saveError ? <p className="mt-3 text-sm text-red-600">{saveError}</p> : null}
          {savingKey ? <p className="mt-3 text-sm text-slate-500">Saving {savingKey.replace(/_/g, " ")}…</p> : null}
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <SectionLabel>Local enforcement preview</SectionLabel>
          <p className="mt-2 text-sm text-slate-600">Evaluation order when Guard decides what to do next.</p>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            {EVALUATION_STEPS.map((step, index) => {
              const Icon = step.icon;
              return (
                <div key={step.label} className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm font-medium text-brand-dark">
                    <Icon className="h-4 w-4 text-brand-blue" aria-hidden="true" />
                    {step.label}
                  </span>
                  {index < EVALUATION_STEPS.length - 1 ? (
                    <HiMiniArrowRight className="h-4 w-4 text-slate-400" aria-hidden="true" />
                  ) : null}
                </div>
              );
            })}
          </div>
          <p className="mt-4 text-xs text-slate-500">
            Evaluation order: {STRICT_POLICY_EVALUATION_ORDER.join(" → ")}. Tune fallback behavior locally; team policy
            still syncs from Guard Cloud.
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
          <p className="mt-2 text-4xl font-semibold tabular-nums text-brand-dark">{pendingInboxCount}</p>
          <p className="mt-1 text-sm text-slate-600">
            Pending review item{pendingInboxCount === 1 ? "" : "s"} may be affected by stricter fallback controls.
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
          <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Expected action</p>
              <div className="mt-1">
                <Badge tone={resolveExpectedActionTone(expectedAction)}>
                  {policyActionLabel(expectedAction)}
                </Badge>
              </div>
            </div>
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
