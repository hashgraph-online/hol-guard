/** This-device capabilities an allowed local CLI's contained runs may use. */
export const LOCAL_CLI_CAPABILITIES = ["loopback-network", "state-dir-read", "state-dir-write"] as const;
export type LocalCliCapability = (typeof LOCAL_CLI_CAPABILITIES)[number];
export type LocalCliCapabilityState = "on" | "off";
export type LocalCliCapabilityChoices = Partial<Record<LocalCliCapability, LocalCliCapabilityState>>;

export type LocalCliCapabilityFields = {
  capabilities?: Record<LocalCliCapability, LocalCliCapabilityState>;
  /** A capability a denied contained run points at while it is still off. */
  suggested_capability?: LocalCliCapability;
};

export function isLocalCliCapability(value: unknown): value is LocalCliCapability {
  return typeof value === "string" && (LOCAL_CLI_CAPABILITIES as readonly string[]).includes(value);
}

/** Capability fields of a listed item; anything malformed reads as absent. */
export function normalizeCapabilityFields(value: Record<string, unknown>): LocalCliCapabilityFields {
  const result: LocalCliCapabilityFields = {};
  const raw = value.capabilities;
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
    const states = raw as Record<string, unknown>;
    if (LOCAL_CLI_CAPABILITIES.some((name) => name in states)) {
      result.capabilities = Object.fromEntries(
        LOCAL_CLI_CAPABILITIES.map((name) => [name, states[name] === "on" ? "on" : "off"]),
      ) as Record<LocalCliCapability, LocalCliCapabilityState>;
    }
  }
  if (isLocalCliCapability(value.suggested_capability) && result.capabilities?.[value.suggested_capability] !== "on") {
    result.suggested_capability = value.suggested_capability;
  }
  return result;
}
