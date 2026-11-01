import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import type { GuardApprovalGatePublicConfig, GuardContextAssistanceConfig } from "../guard-types";
import { controlContextAssistance, fetchContextAssistance, fetchContextInstallations } from "./api";
import { ContextSettingsControls } from "./settings-controls";
import type { ContextAssistanceStatus, ContextControlAction, ContextInstallation } from "./types";
import { ContextWorkspacesPanel } from "./workspaces-panel";
import { CigarWorkspace } from "./workspace";
import { CigarVersionsPanel } from "./versions-panel";
import { CigarSetupProof } from "./one-click-setup";
import { useCigarOneClick } from "./use-one-click";
import { commitDashboardLocation } from "../dashboard-location";
import { sameCigarPreferences } from "./selection-settings";

type Props = {
  workspace?: boolean;
  data?: ReactNode;
  value?: GuardContextAssistanceConfig | null;
  savedValue?: GuardContextAssistanceConfig | null;
  gate?: GuardApprovalGatePublicConfig | null;
  locked: boolean;
  disabled: boolean;
  onChange: (value: GuardContextAssistanceConfig) => void;
  onStopped: (value: GuardContextAssistanceConfig) => void;
  onSelectionChanged?: (value: GuardContextAssistanceConfig, previous: GuardContextAssistanceConfig) => void;
  onBusyChange: (busy: boolean) => void;
};

export function ContextAssistanceSettings(props: Props) {
  const workspace = props.workspace === true;
  const [status, setStatus] = useState<ContextAssistanceStatus | null>(null);
  const [installations, setInstallations] = useState<ContextInstallation[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const request = useRef<AbortController | null>(null);
  const revision = useRef(0);
  const pending = useRef(false);
  const mounted = useRef(false);
  const savedRevision = JSON.stringify(props.savedValue);
  const versionInputs = useRef({ saved: props.savedValue, changed: props.onSelectionChanged });
  versionInputs.current = { saved: props.savedValue, changed: props.onSelectionChanged };
  const captureVersionStatus = useCallback(() => {
    if (pending.current) return (_result: ContextAssistanceStatus) => {};
    const current = ++revision.current;
    request.current?.abort();
    const previous = versionInputs.current.saved;
    return (result: ContextAssistanceStatus) => {
      // A later Stop or settings refresh invalidates this captured response.
      if (!mounted.current || current !== revision.current || pending.current) return;
      setStatus(result); setLoading(false);
      if (result.installation_options !== null) setInstallations(result.installation_options);
      if (previous && !sameCigarPreferences(previous, result.preferences)) {
        versionInputs.current.changed?.(result.preferences, previous);
      }
    };
  }, []);

  const refresh = useCallback(async () => {
    if (pending.current) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    try {
      // Opening the CIGAR workspace lists registered metadata. It never scans
      // PATH, probes Python, imports CIGAR, or activates an optional runtime.
      const result = await (workspace ? fetchContextInstallations(controller.signal) : fetchContextAssistance(controller.signal));
      if (current !== revision.current) return;
      setStatus(result);
      if (workspace) setInstallations(result.installation_options ?? []);
      setError(null);
    } catch (cause) {
      if (current !== revision.current) return;
      setStatus(null);
      if (workspace) setInstallations(null);
      setError(cause instanceof Error ? cause.message : "Context assistance status is unavailable.");
    } finally {
      if (current === revision.current) setLoading(false);
    }
  }, [workspace]);

  useEffect(() => {
    void refresh();
  }, [refresh, savedRevision]);

  useEffect(() => {
    const onFocus = () => { if (!document.hidden) void refresh(); };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onFocus);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onFocus);
    };
  }, [refresh]);

  useEffect(() => {
    if (!status?.job && !status?.effective_enabled) return;
    const timer = window.setTimeout(() => { if (!document.hidden) void refresh(); }, status.job ? 500 : 10_000);
    return () => window.clearTimeout(timer);
  }, [status, refresh]);

  const onBusyChange = props.onBusyChange;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      revision.current += 1;
      request.current?.abort();
      onBusyChange(false);
    };
  }, [onBusyChange]);

  const value = props.value ?? status?.preferences ?? null;
  const saved = props.savedValue ?? status?.preferences ?? null;
  const dirty = value && saved ? !sameCigarPreferences(value, saved) : value !== saved;
  const setup = useCigarOneClick({
    active: workspace, status, dirty, locked: props.locked, disabled: props.disabled || busy, gate: props.gate ?? null,
    publish: (state) => captureVersionStatus()(state),
    onSaved: (config, previous) => props.onSelectionChanged?.(config, previous),
  });
  useEffect(() => {
    if (!setup.busy) return;
    onBusyChange(true);
    return () => onBusyChange(false);
  }, [setup.busy, onBusyChange]);

  async function perform(action: ContextControlAction | "installations") {
    // Stop always wins over a one-click setup that is still running.
    if (action === "stop") setup.stop();
    if (pending.current || props.disabled) return;
    pending.current = true;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    props.onBusyChange(true);
    setError(null);
    // Even an unknown transport outcome must not leave a draft that can
    // accidentally opt back in at the next ordinary settings save.
    const value = props.value ?? status?.preferences;
    if (action === "stop" && value) props.onChange({ ...value, enabled: false });
    try {
      const result = action === "installations"
        ? await fetchContextInstallations(controller.signal)
        : await controlContextAssistance(action, controller.signal);
      if (current !== revision.current) return;
      setStatus(result);
      if (action === "installations") setInstallations(result.installation_options ?? []);
      if (action === "stop") props.onStopped(result.preferences);
    } catch (cause) {
      if (current !== revision.current) return;
      setStatus(null);
      setError(cause instanceof Error ? cause.message : "The context assistance operation did not return a verified result. Refresh its status.");
    } finally {
      pending.current = false;
      if (mounted.current && current === revision.current) {
        setBusy(false);
        setLoading(false);
        props.onBusyChange(false);
      }
    }
  }

  const controls = <ContextSettingsControls value={value} status={status} installations={installations}
    loading={loading} busy={busy} disabled={props.disabled} locked={props.locked}
    dirty={dirty} error={workspace ? null : error}
    onChange={props.onChange} onRefresh={() => void refresh()}
    onChooseRuntime={() => void perform("installations")} onControl={(action) => void perform(action)}
    onManageVersions={workspace ? () => {
      const url = new URL(window.location.href); url.searchParams.set("section", "versions");
      commitDashboardLocation(url.pathname + url.search + url.hash);
    } : undefined} />;
  const access = <ContextWorkspacesPanel ready={status?.effective_enabled === true} generation={status?.generation ?? null}
      dirty={dirty} documentsAllowed={status?.effective_preferences.sources.workspace_documents === true}
      agentsAllowed={status?.effective_preferences.features.agent_context === true}
      executionAllowed={status?.effective_preferences.features.execution_context === true
        && status?.capabilities?.execution_context === true}
      sharingAllowed={status?.effective_preferences.features.shared_agents === true && status?.runtime?.shared_compile_verified === true}
      gate={props.gate ?? null} />;
  return workspace ? <><CigarWorkspace status={status} installations={installations} loading={loading}
    busy={busy} disabled={props.disabled} dirty={dirty} error={error} setup={setup}
    stopAvailable={Boolean(value?.enabled || saved?.enabled || status?.job || status?.effective_enabled || error)}
    controls={controls} access={access} data={props.data}
    versions={<CigarVersionsPanel status={status} disabled={props.disabled || busy} locked={props.locked}
      dirty={dirty} gate={props.gate ?? null} captureStatus={captureVersionStatus} />}
    onRefresh={() => { void refresh(); void setup.refresh(); }}
    onStop={() => void perform("stop")} /><CigarSetupProof setup={setup} gate={props.gate ?? null} /></> : <>{controls}{access}</>;
}
