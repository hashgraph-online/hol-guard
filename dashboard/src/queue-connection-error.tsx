import { useCallback, useState } from "react";
import { ActionButton, Surface } from "./approval-center-primitives";
import {
  QUEUE_CONNECTION_ERROR_HEADLINE,
  QUEUE_CONNECTION_ERROR_INSTRUCTION,
  QUEUE_SESSION_ERROR_DETAIL,
  QUEUE_SESSION_ERROR_HEADLINE,
  QUEUE_SESSION_ERROR_INSTRUCTION,
  queueErrorIsUnauthorizedSession,
} from "./queue-connection-copy";

export function QueueConnectionError(props: {
  message: string;
  approvalUrl: string | null;
  onRetry?: () => void;
  onRepair?: () => Promise<void>;
}) {
  const [repairing, setRepairing] = useState(false);
  const sessionMissing = queueErrorIsUnauthorizedSession(props.message);

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

  const headline = sessionMissing ? QUEUE_SESSION_ERROR_HEADLINE : QUEUE_CONNECTION_ERROR_HEADLINE;
  const detail = sessionMissing ? QUEUE_SESSION_ERROR_DETAIL : props.message;
  const instruction = sessionMissing ? QUEUE_SESSION_ERROR_INSTRUCTION : QUEUE_CONNECTION_ERROR_INSTRUCTION;

  return (
    <div className="space-y-4">
      <Surface tone="danger">
        <p className="text-sm font-semibold text-brand-purple" role="alert">
          {headline}
        </p>
        <p className="mt-1 text-sm text-brand-purple/80">{detail}</p>
        <p className="mt-2 text-sm text-brand-purple/70">{instruction}</p>
        <div className="mt-4 flex flex-wrap gap-3">
          {sessionMissing ? (
            props.onRetry !== undefined && (
              <ActionButton onClick={props.onRetry}>Retry</ActionButton>
            )
          ) : (
            <ActionButton onClick={handleOpenDaemon}>Repair</ActionButton>
          )}
          {sessionMissing
            ? null
            : props.onRepair !== undefined && (
                <ActionButton onClick={handleRepair} disabled={repairing} variant="outline">
                  {repairing ? "Repairing..." : "Reconnect"}
                </ActionButton>
              )}
          {sessionMissing ? null : (
            <code className="inline-flex min-h-10 items-center rounded-lg border border-brand-purple/30 bg-slate-50 px-3 py-2 font-mono text-sm text-brand-purple select-all">
              hol-guard start
            </code>
          )}
          {sessionMissing
            ? null
            : props.onRetry !== undefined && (
                <ActionButton variant="outline" onClick={props.onRetry}>
                  Retry
                </ActionButton>
              )}
          {sessionMissing
            ? null
            : props.approvalUrl !== null && (
                <ActionButton href={props.approvalUrl} variant="outline">
                  Open dashboard
                </ActionButton>
              )}
        </div>
      </Surface>
    </div>
  );
}
