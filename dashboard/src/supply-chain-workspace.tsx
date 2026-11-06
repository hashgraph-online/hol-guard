import { useMemo } from "react";
import type { GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import { resolveSupplyChainIssues } from "./supply-chain-issues";
import { resolveSupplyChainWorkspaceHero } from "./supply-chain-workspace-hero-state";
import { SupplyChainWorkspaceHero } from "./supply-chain-workspace-hero";
import { SupplyChainRecovery } from "./supply-chain-recovery";
import type { SupplyChainFixAllState } from "./supply-chain-fix-all";

export { buildSupplyChainStats } from "./supply-chain-protection-stats";

/*
 * Design contract: Supply chain tab
 * THESIS: The page answers one question, "is every package tool on this device
 *   guarded?", and lets you fix the one that is not without scrolling past
 *   explanations.
 * OWN-WORLD: A roster of the package managers on this machine, one ruled line
 *   each, like a ledger: tool, how the shell finds it, state, action.
 * STORY: Status first (all clear, or what to restore), then the roster, then
 *   the facts behind it: recent activity, audit, intel, apps and sources.
 * FIRST VIEWPORT: The status line and the top of the roster with its first
 *   rows, so a broken tool and its Fix PATH button are visible on arrival.
 * FORM: Seed 5d2c9e97, "Manager roster ledger". Ruled rows, side headings for
 *   details, no card grids, no small-caps labels, colour only for state.
 * BRAND: The status opens on Home's dark gradient with the HOL particle mark
 *   (brand-hero.tsx), so the tab reads as the same product the moment it
 *   loads. Phones keep a small flat mark instead of the stage so the roster
 *   still reaches the first viewport.
 * FINISH: Remove stays quiet until its inline Confirm; empty sections say so
 *   in one line instead of a centred placeholder.
 */

type SupplyChainWorkspaceProps = {
  snapshot: GuardRuntimeSnapshot;
  receipts?: readonly GuardReceipt[];
  fixAllState: SupplyChainFixAllState;
  onFixAll: () => void;
};

/** The status line above the roster: all clear, or what to restore. */
export function SupplyChainWorkspace({ snapshot, receipts, fixAllState, onFixAll }: SupplyChainWorkspaceProps) {
  const supplyChainIssues = useMemo(() => resolveSupplyChainIssues(snapshot), [snapshot]);
  const workspaceHero = useMemo(
    () => resolveSupplyChainWorkspaceHero(snapshot, { openIssueCount: supplyChainIssues.length, receipts }),
    [snapshot, supplyChainIssues.length, receipts],
  );

  return supplyChainIssues.length > 0 ? (
    <SupplyChainRecovery
      issues={supplyChainIssues}
      state={fixAllState}
      onFixAll={onFixAll}
      guidance={workspaceHero.stagedGuidance}
      facts={workspaceHero.facts}
      locallyProtected={workspaceHero.protectionStatus === "protected"}
    />
  ) : (
    <SupplyChainWorkspaceHero hero={workspaceHero} />
  );
}
