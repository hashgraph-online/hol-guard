import { queueErrorIsUnauthorizedSession } from "./queue-connection-copy";

export function buildDaemonErrorCopy(): {
  title: string;
  body: string;
  primaryCta: string;
  secondaryCta: string;
} {
  return {
    title: "Guard is not responding",
    body: "The local Guard service is not reachable. Retry the connection, or open Settings if you need to repair protection.",
    primaryCta: "Retry",
    secondaryCta: "Go to Settings",
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
