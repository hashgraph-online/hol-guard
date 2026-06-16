import { useCallback, useState } from "react";
import { ActionButton, Surface } from "./approval-center-primitives";
import {
  QUEUE_CONNECTION_ERROR_HEADLINE,
  QUEUE_CONNECTION_ERROR_INSTRUCTION,
} from "./approval-center-utils";

export function QueueConnectionError(props: {
  message: string;
  approvalUrl: string | null;
  onRetry?: () => void;
  onRepair?: () => Promise<void>;
}) {
  const [repairing, setRepairing] = useState(false);

  const handleRepair = useCallback(async () => {
    if (props.onRepair === undefined) {
      return;
    }
    setRepairing(true);
    try {
      await props.onRepair();
    } finally {
      setRepairing(false);
    }
  }, [props.onRepair]);

  const handleOpenDaemon = useCallback(() => {
    if (props.approvalUrl !== null) {
      window.open(props.approvalUrl, "_blank", "noopener,noreferrer");
    } else {
      void handleRepair();
    }
  }, [handleRepair, props.approvalUrl]);

  return (
    <div className="space-y-4">
      <Surface tone="danger">
        <p className="text-sm font-semibold text-brand-purple">{QUEUE_CONNECTION_ERROR_HEADLINE}</p>
        <p className="mt-1 text-sm text-brand-purple/80">{props.message}</p>
        <p className="mt-2 text-sm text-brand-purple/70">{QUEUE_CONNECTION_ERROR_INSTRUCTION}</p>
        <div className="mt-4 flex flex-wrap gap-3">
          <ActionButton onClick={handleOpenDaemon}>Repair</ActionButton>
          {props.onRepair !== undefined && (
            <ActionButton onClick={handleRepair} disabled={repairing} variant="outline">
              {repairing ? "Repairing..." : "Reconnect"}
            </ActionButton>
          )}
          <code className="inline-flex min-h-10 items-center rounded-lg border border-brand-purple/30 bg-slate-50 px-3 py-2 font-mono text-sm text-brand-purple select-all">
            hol-guard start
          </code>
          {props.onRetry !== undefined && (
            <ActionButton variant="outline" onClick={props.onRetry}>
              Retry
            </ActionButton>
          )}
          {props.approvalUrl !== null && (
            <ActionButton href={props.approvalUrl} variant="outline">
              Open dashboard
            </ActionButton>
          )}
        </div>
      </Surface>
    </div>
  );
}
