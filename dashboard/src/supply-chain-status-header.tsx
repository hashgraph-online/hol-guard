import { SupplyChainIssueFocus } from "./supply-chain-issue-focus";
import { SupplyChainWorkspaceHero } from "./supply-chain-workspace-hero";
import type { SupplyChainWorkspaceHeroState } from "./supply-chain-workspace-hero-state";
import type { SupplyChainIssue, SupplyChainIssueAction } from "./supply-chain-issues";

type SupplyChainStatusHeaderProps = {
  hero: SupplyChainWorkspaceHeroState;
  issues: SupplyChainIssue[];
  onIssueAction: (action: SupplyChainIssueAction) => void;
  actionPending?: boolean;
};

export function SupplyChainStatusHeader({
  hero,
  issues,
  onIssueAction,
  actionPending = false,
}: SupplyChainStatusHeaderProps) {
  if (issues.length === 0) {
    return <SupplyChainWorkspaceHero hero={hero} />;
  }

  return (
    <SupplyChainIssueFocus
      hero={hero}
      issues={issues}
      onIssueAction={onIssueAction}
      actionPending={actionPending}
    />
  );
}
