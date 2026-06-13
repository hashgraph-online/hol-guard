import type { GuardManagedInstall } from "./guard-types";

export function resolveSupplyChainAuditWorkspaceDir(
  managedInstalls: readonly GuardManagedInstall[],
): string | null {
  const ordered = [...managedInstalls].sort((left, right) => {
    if (left.active !== right.active) {
      return left.active ? -1 : 1;
    }
    return right.updated_at.localeCompare(left.updated_at);
  });
  for (const install of ordered) {
    const workspace = install.workspace?.trim();
    if (workspace) {
      return workspace;
    }
  }
  return null;
}

export function resolveSupplyChainAuditWorkspaceTarget(input: {
  managedWorkspaceDir?: string | null;
  statusWorkspaceDir?: string | null;
}): string | null {
  const managed = input.managedWorkspaceDir?.trim();
  if (managed) {
    return managed;
  }
  const status = input.statusWorkspaceDir?.trim();
  if (status) {
    return status;
  }
  return null;
}
