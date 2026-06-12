import { HiMiniArrowPath, HiMiniArrowTopRightOnSquare, HiMiniShieldCheck } from "react-icons/hi2";
import { ActionButton, Tag } from "../approval-center-primitives";
import type { GuardCloudConnectFlow } from "../guard-types";

interface EvidenceInsightsShareConnectPanelProps {
  connectError: string | null;
  connectFlow: GuardCloudConnectFlow;
  connectStarting: boolean;
  onStartConnect: () => void;
}

export function EvidenceInsightsShareConnectPanel({
  connectError,
  connectFlow,
  connectStarting,
  onStartConnect,
}: EvidenceInsightsShareConnectPanelProps) {
  const manualHref = connectFlow.authorize_url ?? connectFlow.connect_url;
  const running = connectFlow.state === "running";
  const failed = connectFlow.state === "failed";
  const primaryBusy = connectStarting || running;
  const showManualLink = connectFlow.authorize_url !== null || running || failed;
  const statusLabel = running ? "Waiting for approval" : "Connection required";
  const helperText = running
    ? "Finish sign-in in your browser to publish a public share link."
    : failed
      ? "Connect did not finish. Try again or open sign-in manually."
      : "One quick sign-in unlocks public sharing from this machine.";

  let primaryLabel = connectFlow.action_label;
  if (running) {
    primaryLabel = "Waiting for browser…";
  } else if (failed) {
    primaryLabel = "Try connect again";
  }

  return (
    <div className="space-y-4 px-5 py-5">
      <div className="flex flex-wrap items-center gap-2">
        <Tag tone="blue">{statusLabel}</Tag>
      </div>
      <p className="text-sm leading-relaxed text-slate-600">{helperText}</p>
      {connectError !== null ? (
        <p className="text-sm text-brand-attention" role="alert">
          {connectError}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <ActionButton variant="primary" onClick={onStartConnect} disabled={primaryBusy}>
          {primaryBusy ? (
            <HiMiniArrowPath className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
          ) : (
            <HiMiniShieldCheck className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
          )}
          {primaryLabel}
        </ActionButton>
        {showManualLink ? (
          <ActionButton href={manualHref} variant="outline">
            Open sign-in
            <HiMiniArrowTopRightOnSquare className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
          </ActionButton>
        ) : null}
      </div>
    </div>
  );
}
