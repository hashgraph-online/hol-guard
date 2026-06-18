import { useCallback, useEffect, useMemo, useState } from "react";
import type { ChangeEvent } from "react";
import { EmptyState } from "./approval-center-primitives";
import { fetchSettings, updateSettings } from "./guard-api";
import type { GuardRuntimeSnapshot, GuardSettings } from "./guard-types";
import { PolicyEnforcementPreviewCard } from "./policy-strict-config-enforcement-preview";
import { PolicyLocalStrictPolicyCard } from "./policy-strict-config-local-policy-card";
import { PolicyStrictConfigRightRail } from "./policy-strict-config-right-rail";
import {
  applyStrictConfigPatch,
  resolveStrictConfigPatch,
  type StrictConfigSettingKey,
} from "./policy-strict-config-segmented";
import { PolicyStrictModeCard } from "./policy-strict-config-strict-mode-card";
import {
  fingerprintLocalPolicySettings,
  resolveStrictScenarioOutcome,
  resolveStrictScenarioSimulation,
  STRICT_POLICY_DEFAULTS,
  type StrictScenarioId,
} from "./policy-strict-config-utils";
import { formatPolicyDateTime, resolveCloudPolicyBundleCopy } from "./policy-workspace-helpers";

type PolicyStrictConfigTabProps = {
  snapshot: GuardRuntimeSnapshot;
  cloudControlsUrl?: string | null;
  onOpenSettings?: () => void;
  onOpenInbox?: () => void;
  onReloadPolicy?: () => void;
  reloadingPolicy?: boolean;
};

type LoadState = "loading" | "ready" | "error";

export function PolicyStrictConfigTab({
  snapshot,
  cloudControlsUrl = null,
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
    if (!settings || !simulationVisible) {
      return null;
    }
    return resolveStrictScenarioSimulation(settings, scenarioId);
  }, [settings, scenarioId, simulationVisible]);

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
    setScenarioId(event.target.value as StrictScenarioId);
    setSimulationVisible(false);
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

  const controlsDisabled = savingKey !== null;
  const lastReloadAt = snapshot.runtime_state?.started_at ?? snapshot.generated_at ?? null;
  const lastReloadFormatted = formatPolicyDateTime(lastReloadAt);
  const lastAckAt = snapshot.cloud_policy_last_ack_at?.trim() ?? null;
  const daemonAckSynced = cloudBundleCopy?.tone === "green";
  const daemonAckLabel = daemonAckSynced ? "Acknowledged" : cloudBundleCopy?.label ?? "Needs attention";
  const expectedAction = scenarioOutcome?.outcome ?? settings.new_network_domain_action ?? "review";
  const expectedReasoning = scenarioOutcome?.reasoning ?? "";

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_280px] xl:items-start">
      <div className="min-w-0 space-y-4">
        <PolicyStrictModeCard
          isStrict={isStrict}
          controlsDisabled={controlsDisabled}
          localPolicyHash={localPolicyHash}
          daemonAckSynced={daemonAckSynced}
          daemonAckLabel={daemonAckLabel}
          lastAckAt={lastAckAt}
          lastReloadFormatted={lastReloadFormatted}
          lastReloadAt={lastReloadAt}
          reloadingPolicy={reloadingPolicy}
          onStrictToggle={handleStrictToggle}
          onCopyHash={handleCopyHash}
          onOpenSettings={onOpenSettings}
          onReloadPolicy={onReloadPolicy}
        />
        <PolicyLocalStrictPolicyCard
          settings={settings}
          controlsDisabled={controlsDisabled}
          saveError={saveError}
          savingKey={savingKey}
          onResetDefaults={handleResetDefaults}
          onSettingChange={handleStrictConfigChange}
        />
        <PolicyEnforcementPreviewCard cloudControlsUrl={cloudControlsUrl} />
      </div>

      <PolicyStrictConfigRightRail
        pendingInboxCount={pendingInboxCount}
        cloudControlsUrl={cloudControlsUrl}
        scenarioId={scenarioId}
        expectedAction={expectedAction}
        expectedReasoning={expectedReasoning}
        simulationVisible={simulationVisible}
        simulation={simulation}
        onOpenInbox={onOpenInbox}
        onScenarioChange={handleScenarioChange}
        onRunSimulation={handleRunSimulation}
      />
    </div>
  );
}
