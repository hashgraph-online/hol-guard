import { useCallback } from "react";
import {
  HiMiniCheckCircle,
  HiMiniExclamationCircle,
  HiMiniXCircle,
  HiMiniQuestionMarkCircle,
  HiMiniWrenchScrewdriver,
} from "react-icons/hi2";
import { Badge, ActionButton, SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import type {
  GuardInventoryItem,
  GuardManagedInstall,
  GuardPolicyDecision,
} from "./guard-types";

export type WatchedAppStatus =
  | "not_found"
  | "found_unprotected"
  | "protected"
  | "needs_repair"
  | "unsupported";

type WatchedAppCardProps = {
  harness: string;
  install: GuardManagedInstall | undefined;
  harnessInventory: GuardInventoryItem[];
  harnessPolicies: GuardPolicyDecision[];
  hasReceipts: boolean;
  fleetUrl: string;
  onConnect: (harness: string) => void;
  onTest: (harness: string) => void;
  onRepair: (harness: string) => void;
};

function resolveAppStatus(
  install: GuardManagedInstall | undefined,
  hasInventory: boolean,
  hasReceipts: boolean
): WatchedAppStatus {
  if (install !== undefined) {
    if (install.active) return "protected";
    return "needs_repair";
  }
  if (!hasInventory && !hasReceipts) return "not_found";
  return "found_unprotected";
}

type StatusIconProps = {
  status: WatchedAppStatus;
};

function StatusIcon(props: StatusIconProps) {
  if (props.status === "protected") {
    return <HiMiniCheckCircle className="h-5 w-5 text-brand-green" aria-hidden="true" />;
  }
  if (props.status === "found_unprotected") {
    return <HiMiniExclamationCircle className="h-5 w-5 text-amber-500" aria-hidden="true" />;
  }
  if (props.status === "needs_repair") {
    return <HiMiniWrenchScrewdriver className="h-5 w-5 text-brand-purple" aria-hidden="true" />;
  }
  if (props.status === "not_found") {
    return <HiMiniXCircle className="h-5 w-5 text-slate-400" aria-hidden="true" />;
  }
  return <HiMiniQuestionMarkCircle className="h-5 w-5 text-slate-400" aria-hidden="true" />;
}

type StatusBadgeProps = {
  status: WatchedAppStatus;
};

function StatusBadge(props: StatusBadgeProps) {
  if (props.status === "protected") {
    return <Badge tone="success">Protected</Badge>;
  }
  if (props.status === "found_unprotected") {
    return <Badge tone="warning">Found, protection not installed</Badge>;
  }
  if (props.status === "needs_repair") {
    return <Badge tone="warning">Repair needed</Badge>;
  }
  if (props.status === "not_found") {
    return <Badge tone="default">Not found</Badge>;
  }
  return <Badge tone="default">Unsupported</Badge>;
}

type CardActionProps = {
  harness: string;
  status: WatchedAppStatus;
  fleetUrl: string;
  onConnect: (harness: string) => void;
  onTest: (harness: string) => void;
  onRepair: (harness: string) => void;
};

function CardAction(props: CardActionProps) {
  const handleConnect = useCallback(() => {
    props.onConnect(props.harness);
  }, [props.onConnect, props.harness]);

  const handleTest = useCallback(() => {
    props.onTest(props.harness);
  }, [props.onTest, props.harness]);

  const handleRepair = useCallback(() => {
    props.onRepair(props.harness);
  }, [props.onRepair, props.harness]);

  if (props.status === "protected") {
    return (
      <ActionButton variant="outline" onClick={handleTest}>
        Test protection
      </ActionButton>
    );
  }
  if (props.status === "found_unprotected") {
    return (
      <ActionButton onClick={handleConnect}>
        Connect
      </ActionButton>
    );
  }
  if (props.status === "needs_repair") {
    return (
      <ActionButton variant="outline" onClick={handleRepair}>
        Repair
      </ActionButton>
    );
  }
  if (props.status === "not_found") {
    return (
      <ActionButton href="https://hol.org/guard/docs/install" variant="outline">
        How to install
      </ActionButton>
    );
  }
  return null;
}

export function WatchedAppCard(props: WatchedAppCardProps) {
  const hasInventory = props.harnessInventory.length > 0;
  const status = resolveAppStatus(props.install, hasInventory, props.hasReceipts);

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-200/70 bg-white/80 shadow-sm">
      <div className="flex items-start justify-between gap-3 p-4">
        <div className="flex min-w-0 items-start gap-3">
          <StatusIcon status={status} />
          <div className="min-w-0">
            <p className="text-sm font-semibold text-brand-dark">
              {harnessDisplayName(props.harness)}
            </p>
            <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
              {props.harness}
            </p>
          </div>
        </div>
        <StatusBadge status={status} />
      </div>

      <div className="border-t border-slate-200/70 px-4 py-3">
        <SectionLabel>What Guard can see</SectionLabel>
        <p className="mt-1 text-xs text-muted-foreground">
          {props.harnessInventory.length} actions seen · {props.harnessPolicies.length} saved decisions
        </p>
      </div>

      <div className="border-t border-slate-200/70 px-4 py-3">
        <CardAction
          harness={props.harness}
          status={status}
          fleetUrl={props.fleetUrl}
          onConnect={props.onConnect}
          onTest={props.onTest}
          onRepair={props.onRepair}
        />
      </div>
    </div>
  );
}
