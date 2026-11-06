export type ProtectionPosture = "protected" | "extra_careful" | "watch";

export const PROTECTION_POSTURE_COPY: Record<
  ProtectionPosture,
  { label: string; help: string }
> = {
  protected: {
    label: "Protected",
    help: "Stops theft, wipes, and Guard bypass. Asks once about new tools or first-time secret access, then remembers.",
  },
  extra_careful: {
    label: "Extra careful",
    help: "Same as Protected, and also asks the first time this project talks to a new site or installs a new tool.",
  },
  watch: {
    label: "Watch",
    help: "Records what Guard would have stopped, but does not stop anything. Use only while debugging.",
  },
};

export const WATCH_BANNER_COPY = "Protection is off. Guard is only recording.";

export const POSTURE_OUTCOME_COLUMNS: Record<
  ProtectionPosture,
  { stops: string; asks: string; runs: string }
> = {
  protected: {
    stops: "Credential theft, Guard bypass, encoded exfil, known-bad tools",
    asks: "First secret read, new destructive command, first package script, new MCP or skill",
    runs: "Remembered actions, routine browsing, verified-benign work",
  },
  extra_careful: {
    stops: "The same automatic stops as Protected",
    asks: "Everything Protected asks, plus first new site, first new tool, and cloud advisories",
    runs: "Remembered actions and verified-benign work",
  },
  watch: {
    stops: "Nothing. Guard only records.",
    asks: "Nothing. Inbox shows what would have stopped.",
    runs: "Every action, including known-bad work",
  },
};

export function isProtectionPosture(value: string | undefined): value is ProtectionPosture {
  return value === "protected" || value === "extra_careful" || value === "watch";
}

export function deriveProtectionPosture(mode: string, securityLevel: string): ProtectionPosture {
  if (mode === "observe") return "watch";
  if (securityLevel === "strict" || securityLevel === "paranoid") return "extra_careful";
  return "protected";
}

export function resolveProtectionPostureCopy(posture: ProtectionPosture): { label: string; help: string } {
  return PROTECTION_POSTURE_COPY[posture];
}

export function postureFromLegacyLevel(level: string | undefined): ProtectionPosture {
  if (level === "strict" || level === "paranoid") return "extra_careful";
  return "protected";
}
