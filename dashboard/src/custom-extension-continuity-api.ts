export type LocalCliContinuityStatus =
  | "applied"
  | "pending_observation"
  | "changed_identity"
  | "locally_overridden"
  | "removed"
  | "stale";

export type LocalCliContinuity = {
  status: LocalCliContinuityStatus;
  reason: string;
  cloud_revision: number | null;
  surface: "cli" | "mcp" | "package-scripts" | null;
};
