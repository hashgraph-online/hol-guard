import {
  resolveSupplyChainAuditWorkspaceDir,
  resolveSupplyChainAuditWorkspaceTarget,
} from "./supply-chain-audit-workspace";
import type { GuardManagedInstall } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const installs: GuardManagedInstall[] = [
  {
    harness: "codex",
    active: false,
    workspace: "workspace/inactive",
    manifest: {},
    updated_at: "2026-06-08T11:00:00.000Z",
  },
  {
    harness: "cursor",
    active: true,
    workspace: "workspace/active-project",
    manifest: {},
    updated_at: "2026-06-08T10:00:00.000Z",
  },
];

assert(
  resolveSupplyChainAuditWorkspaceDir(installs) === "workspace/active-project",
  "audit workspace resolver should prefer active managed installs",
);

assert(
  resolveSupplyChainAuditWorkspaceTarget({
    managedWorkspaceDir: "workspace/managed",
    statusWorkspaceDir: "workspace/status",
  }) === "workspace/managed",
  "audit workspace target should prefer managed install workspace",
);

assert(
  resolveSupplyChainAuditWorkspaceTarget({
    managedWorkspaceDir: null,
    statusWorkspaceDir: "workspace/status",
  }) === "workspace/status",
  "audit workspace target should fall back to daemon status workspace",
);

console.log("supply-chain-audit-workspace.test.ts passed");
