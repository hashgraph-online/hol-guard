import { useCallback, useState } from "react";
import { HiMiniCheck, HiMiniClipboardDocument } from "react-icons/hi2";
import { guardSessionRecoveryCommand, isGuardAuthenticationError } from "./guard-auth-error";
import { ActionButton, IconActionButton, Surface } from "./approval-center-primitives";
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
  const [repairError, setRepairError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const authenticationRequired = isGuardAuthenticationError(props.message);

  const handleRepair = useCallback(async () => {
    if (props.onRepair === undefined) {
      return;
    }
    setRepairing(true);
    setRepairError(null);
    try {
      await props.onRepair();
    } catch {
      setRepairError("Guard could not complete the repair. Open the local Guard app to check its status.");
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

  if (authenticationRequired) {
    const recoveryCommand = guardSessionRecoveryCommand(typeof window === "undefined" ? "" : window.location.pathname);
    return (
      <Surface>
        <h2 className="text-sm font-semibold text-brand-dark">Reconnect this browser to Guard</h2>
        <p className="mt-2 text-sm text-slate-600">
          Guard responded, but this browser's local session is missing or has expired. Your request has not been changed.
        </p>
        <p className="mt-2 text-sm text-slate-600">
          Open the dashboard from the Guard app, or run this command in your terminal. Guard Cloud sign-in is not required.
        </p>
        <div className="mt-3 flex items-start gap-2">
          <code className="min-w-0 flex-1 break-words font-mono text-sm text-brand-dark select-all">{recoveryCommand}</code>
          <IconActionButton
            label={copied ? "Copied" : "Copy recovery command"}
            icon={copied ? <HiMiniCheck /> : <HiMiniClipboardDocument />}
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(recoveryCommand);
                setCopied(true);
                setRepairError(null);
              } catch {
                setRepairError("Clipboard unavailable. Select the command to copy it.");
              }
            }}
          />
        </div>
        {repairError !== null && <p role="alert" className="mt-2 text-sm">{repairError}</p>}
        {props.onRetry !== undefined && (
          <div className="mt-4">
            <ActionButton variant="outline" onClick={props.onRetry}>Check session again</ActionButton>
          </div>
        )}
      </Surface>
    );
  }

  return (
    <div className="space-y-4">
      <Surface tone="danger">
        <p className="text-sm font-semibold text-brand-purple">{QUEUE_CONNECTION_ERROR_HEADLINE}</p>
        <p className="mt-1 text-sm text-brand-purple/80">{props.message}</p>
        {repairError !== null && <p role="alert" className="mt-2 text-sm">{repairError}</p>}
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
