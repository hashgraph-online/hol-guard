import { useCallback, useState } from "react";
import { ActionButton, Surface } from "./approval-center-primitives";
import {
  QUEUE_CONNECTION_ERROR_HEADLINE,
  QUEUE_CONNECTION_ERROR_INSTRUCTION,
  QUEUE_DESKTOP_HANDOFF_DETAIL,
  QUEUE_DESKTOP_HANDOFF_HEADLINE,
  QUEUE_DESKTOP_HANDOFF_INSTRUCTION,
  QUEUE_SESSION_COMMAND_INSTRUCTION,
  QUEUE_SESSION_ERROR_DETAIL,
  QUEUE_SESSION_ERROR_HEADLINE,
  QUEUE_SESSION_ERROR_INSTRUCTION,
  approvalsOpenCommand,
  desktopRequestUrl,
  queueErrorIsUnauthorizedSession,
} from "./queue-connection-copy";
import { requestHandedOffToDesktop } from "./desktop-request-handoff";

export function QueueConnectionError(props: {
  message: string;
  approvalUrl: string | null;
  requestId?: string | null;
  onRetry?: () => void;
  onRepair?: () => Promise<void>;
  /** Whether this tab already opened the request in HOL Guard Desktop. */
  handedOffToDesktop?: boolean;
}) {
  const [repairing, setRepairing] = useState(false);
  const sessionMissing = queueErrorIsUnauthorizedSession(props.message);
  const desktopUrl = sessionMissing ? desktopRequestUrl(props.requestId ?? null) : null;
  const openCommand = sessionMissing ? approvalsOpenCommand(props.requestId ?? null) : null;
  const handedOff =
    desktopUrl !== null && (props.handedOffToDesktop ?? requestHandedOffToDesktop(props.requestId));

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

  let headline = sessionMissing ? QUEUE_SESSION_ERROR_HEADLINE : QUEUE_CONNECTION_ERROR_HEADLINE;
  let detail = sessionMissing ? QUEUE_SESSION_ERROR_DETAIL : props.message;
  let instruction = sessionMissing ? QUEUE_SESSION_ERROR_INSTRUCTION : QUEUE_CONNECTION_ERROR_INSTRUCTION;
  if (handedOff) {
    headline = QUEUE_DESKTOP_HANDOFF_HEADLINE;
    detail = QUEUE_DESKTOP_HANDOFF_DETAIL;
    instruction = QUEUE_DESKTOP_HANDOFF_INSTRUCTION;
  }
  // The Desktop button leads when it shows, so Retry steps back beside it.
  let sessionRetryVariant: "outline" | undefined;
  if (desktopUrl !== null) {
    sessionRetryVariant = "outline";
  }

  return (
    <div className="space-y-4">
      <Surface tone={handedOff ? "default" : "danger"}>
        <p className="text-sm font-semibold text-brand-purple" role="alert">
          {headline}
        </p>
        <p className="mt-1 text-sm text-brand-purple/80">{detail}</p>
        <p className="mt-2 text-sm text-brand-purple/70">{instruction}</p>
        <div className="mt-4 flex flex-wrap gap-3">
          {desktopUrl !== null && <ActionButton href={desktopUrl}>{handedOff ? "Open in HOL Guard Desktop again" : "Open in HOL Guard Desktop"}</ActionButton>}
          {sessionMissing ? (
            props.onRetry !== undefined && (
              <ActionButton onClick={props.onRetry} variant={sessionRetryVariant}>
                Retry
              </ActionButton>
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
        {openCommand !== null && (
          <div className="mt-4 space-y-2">
            <p className="text-sm text-brand-purple/70">{QUEUE_SESSION_COMMAND_INSTRUCTION}</p>
            <code className="block overflow-x-auto rounded-lg border border-brand-purple/30 bg-slate-50 px-3 py-2 font-mono text-sm text-brand-purple select-all">
              {openCommand}
            </code>
          </div>
        )}
      </Surface>
    </div>
  );
}
