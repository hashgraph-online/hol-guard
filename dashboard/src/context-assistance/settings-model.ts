import type { GuardContextAssistanceConfig, GuardSettings } from "../guard-types";

export function withContextProfile(
  config: GuardContextAssistanceConfig,
  profile: GuardContextAssistanceConfig["resource_profile"],
): GuardContextAssistanceConfig {
  const limits = profile === "low_memory"
    ? { context_tokens: 768, reserve_tokens: 128, max_active_workspaces: 1, idle_shutdown_seconds: 120 }
    : profile === "balanced"
      ? { context_tokens: 2048, reserve_tokens: 256, max_active_workspaces: 2, idle_shutdown_seconds: 600 }
      : config.limits;
  return { ...config, resource_profile: profile, limits: { ...limits } };
}

/** A successful immediate opt-out must survive the parent's next settings save. */
export function settingsWithContextOff(settings: GuardSettings, fallback: GuardContextAssistanceConfig): GuardSettings {
  return {
    ...settings,
    context_assistance: { ...(settings.context_assistance ?? fallback), enabled: false },
    ...(settings.context_assistance_requested !== undefined
      ? { context_assistance_requested: { ...fallback, enabled: false } } : {}),
  };
}
