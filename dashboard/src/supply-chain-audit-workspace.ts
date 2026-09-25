import type { GuardManagedInstall } from "./guard-types";

export function normalizeSupplyChainAuditWorkspaceInput(value: string | null | undefined): string {
  let next = value?.trim() ?? "";
  if (!next || next === "<project-folder>") {
    return "";
  }
  if (
    (next.startsWith('"') && next.endsWith('"')) ||
    (next.startsWith("'") && next.endsWith("'"))
  ) {
    next = next.slice(1, -1).trim();
  }
  if (next.toLowerCase().startsWith("file://")) {
    let raw = next.slice("file://".length);
    if (/^localhost(?=\/|$)/i.test(raw)) {
      raw = raw.slice("localhost".length);
    }
    try {
      next = decodeURIComponent(raw);
    } catch {
      next = raw;
    }
  }
  return next.trim();
}

function compareManagedInstalls(left: GuardManagedInstall, right: GuardManagedInstall): number {
  if (left.active !== right.active) {
    return left.active ? -1 : 1;
  }
  return right.updated_at.localeCompare(left.updated_at);
}

export function listSupplyChainAuditWorkspaceChoices(
  managedInstalls: readonly GuardManagedInstall[],
): string[] {
  const ordered = [...managedInstalls].sort(compareManagedInstalls);
  const seen = new Set<string>();
  const choices: string[] = [];
  for (const install of ordered) {
    const workspace = normalizeSupplyChainAuditWorkspaceInput(install.workspace);
    if (!workspace || seen.has(workspace)) {
      continue;
    }
    seen.add(workspace);
    choices.push(workspace);
    if (choices.length === 6) {
      break;
    }
  }
  return choices;
}

export function resolveSupplyChainAuditWorkspaceDir(
  managedInstalls: readonly GuardManagedInstall[],
): string | null {
  const ordered = [...managedInstalls].sort(compareManagedInstalls);
  for (const install of ordered) {
    const workspace = install.workspace?.trim();
    if (workspace) {
      return workspace;
    }
  }
  return null;
}

export function resolveSupplyChainAuditWorkspaceTarget(input: {
  selectedWorkspaceDir?: string | null;
  managedWorkspaceDir?: string | null;
  statusWorkspaceDir?: string | null;
}): string | null {
  const selected = normalizeSupplyChainAuditWorkspaceInput(input.selectedWorkspaceDir);
  if (selected) {
    return selected;
  }
  const managed = normalizeSupplyChainAuditWorkspaceInput(input.managedWorkspaceDir);
  if (managed) {
    return managed;
  }
  const status = normalizeSupplyChainAuditWorkspaceInput(input.statusWorkspaceDir);
  if (status) {
    return status;
  }
  return null;
}
