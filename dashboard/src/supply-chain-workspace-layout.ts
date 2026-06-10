export const SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS =
  "min-w-0 max-w-full space-y-6 overflow-x-hidden";

export type ProtectedManagersStat = {
  label: string;
  value: number;
  tone: "green" | "attention" | "blue" | "slate";
};

export function resolveProtectedManagersStat(stats: {
  stagedManagers: number;
  repairRequiredManagers: number;
  protectedManagers: number;
}): ProtectedManagersStat {
  if (stats.stagedManagers > 0) {
    return {
      label: "Ready after restart",
      value: stats.stagedManagers,
      tone: "blue",
    };
  }
  if (stats.repairRequiredManagers > 0) {
    return {
      label: "Needs path fix",
      value: stats.repairRequiredManagers,
      tone: "attention",
    };
  }
  return {
    label: "Protected tools",
    value: stats.protectedManagers,
    tone: "green",
  };
}
