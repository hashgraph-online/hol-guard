import {
  listSupplyChainAuditWorkspaceChoices,
  normalizeSupplyChainAuditWorkspaceInput,
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
    selectedWorkspaceDir: " /workspace/project ",
    managedWorkspaceDir: "workspace/managed",
    statusWorkspaceDir: "workspace/status",
  }) === "/workspace/project",
  "audit workspace target should prefer the explicitly selected project",
);

assert(
  resolveSupplyChainAuditWorkspaceTarget({
    selectedWorkspaceDir: "   ",
    managedWorkspaceDir: "workspace/managed",
    statusWorkspaceDir: "workspace/status",
  }) === "workspace/managed",
  "audit workspace target should fall back to managed install workspace",
);

assert(
  resolveSupplyChainAuditWorkspaceTarget({
    managedWorkspaceDir: null,
    statusWorkspaceDir: "workspace/status",
  }) === "workspace/status",
  "audit workspace target should fall back to daemon status workspace",
);

assert(
  normalizeSupplyChainAuditWorkspaceInput(" <project-folder> ") === "",
  "audit workspace input should ignore the token placeholder",
);
assert(
  normalizeSupplyChainAuditWorkspaceInput('"/workspace/project"') === "/workspace/project",
  "audit workspace input should unwrap a quoted path",
);
assert(
  normalizeSupplyChainAuditWorkspaceInput("file://localhost/workspace/project") === "/workspace/project",
  "audit workspace input should keep a localhost file URL as a local path",
);
assert(
  normalizeSupplyChainAuditWorkspaceInput("file:///workspace/project") === "/workspace/project",
  "audit workspace input should keep a file URL path",
);
assert(
  normalizeSupplyChainAuditWorkspaceInput("file://localhost-dev/share/app") === "localhost-dev/share/app",
  "audit workspace input should not strip a host that only starts with localhost",
);
assert(
  listSupplyChainAuditWorkspaceChoices(installs)[0] === "workspace/active-project",
  "known audit folders should prefer the active install",
);

console.log("supply-chain-audit-workspace.test.ts passed");
