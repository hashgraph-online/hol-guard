import { queueErrorIsUnauthorizedSession } from "./queue-connection-copy";

export function buildDaemonErrorCopy(): {
  title: string;
  body: string;
  primaryCta: string;
  secondaryCta: string;
} {
  return {
    title: "We can't connect to Guard.",
    body: "Retry the connection, or troubleshoot the local service without changing your protection settings.",
    primaryCta: "Retry connection",
    secondaryCta: "Troubleshoot",
  };
}

export function buildHomeRuntimeErrorCopy(message: string): {
  kind: "session" | "daemon";
  title: string;
  body: string;
  primaryCta: string;
  secondaryCta: string;
} {
  if (queueErrorIsUnauthorizedSession(message)) {
    return {
      kind: "session",
      title: "This window needs a signed session",
      body: "Guard is still running on this device. Reconnect this window so the dashboard and local protection stay in sync.",
      primaryCta: "Reconnect",
      secondaryCta: "Open review queue",
    };
  }
  return { kind: "daemon", ...buildDaemonErrorCopy() };
}
