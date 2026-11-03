import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueueConnectionError } from "./queue-connection-error";
import {
  QUEUE_CONNECTION_ERROR_HEADLINE,
  QUEUE_CONNECTION_ERROR_INSTRUCTION,
  QUEUE_SESSION_COMMAND_INSTRUCTION,
  QUEUE_SESSION_ERROR_DETAIL,
  QUEUE_SESSION_ERROR_HEADLINE,
  QUEUE_SESSION_ERROR_INSTRUCTION,
  approvalsOpenCommand,
  desktopRequestUrl,
  queueErrorIsUnauthorizedSession,
} from "./queue-connection-copy";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(
  QUEUE_CONNECTION_ERROR_HEADLINE.toLowerCase().includes("daemon"),
  "C10: Connection error headline mentions the daemon so users know what to start",
);

assert(
  QUEUE_CONNECTION_ERROR_HEADLINE.toLowerCase().includes("approval link"),
  "C10: Connection error headline explains approval links require the daemon to be running",
);

assert(
  QUEUE_CONNECTION_ERROR_INSTRUCTION.toLowerCase().includes("reload"),
  "C11: Connection error instruction tells users to reload after starting Guard",
);

assert(
  QUEUE_CONNECTION_ERROR_INSTRUCTION.toLowerCase().includes("start"),
  "C11: Connection error instruction tells users to start Guard on this machine",
);

assert(
  queueErrorIsUnauthorizedSession("unauthorized (401)") &&
    queueErrorIsUnauthorizedSession("Request failed with 401") &&
    !queueErrorIsUnauthorizedSession("HTTP 401") &&
    !queueErrorIsUnauthorizedSession("Unable to load req-401-pending") &&
    !queueErrorIsUnauthorizedSession("Guard daemon not reachable") &&
    !queueErrorIsUnauthorizedSession(""),
  "C10b: only unsigned-session fetch errors use the signed-session copy",
);

assert(
  !QUEUE_SESSION_ERROR_HEADLINE.toLowerCase().includes("daemon") &&
    !QUEUE_SESSION_ERROR_INSTRUCTION.toLowerCase().includes("start") &&
    QUEUE_SESSION_ERROR_HEADLINE.toLowerCase().includes("signed local session") &&
    QUEUE_SESSION_ERROR_DETAIL.toLowerCase().includes("still running"),
  "C10b: session error copy says Guard is running and the browser is unsigned",
);

const connectionMarkup = renderToStaticMarkup(
  createElement(QueueConnectionError, {
    message: "Failed to fetch",
    approvalUrl: null,
    onRetry: () => undefined,
    onRepair: async () => undefined,
  }),
);
assert(
  connectionMarkup.includes(QUEUE_CONNECTION_ERROR_HEADLINE) &&
    connectionMarkup.includes("hol-guard start") &&
    connectionMarkup.includes("Repair") &&
    connectionMarkup.includes("Reconnect"),
  "Connection errors still offer Repair, Reconnect, and hol-guard start",
);

const sessionMarkup = renderToStaticMarkup(
  createElement(QueueConnectionError, {
    message: "unauthorized (401)",
    approvalUrl: null,
    onRetry: () => undefined,
    onRepair: async () => undefined,
  }),
);
assert(
  sessionMarkup.includes(QUEUE_SESSION_ERROR_HEADLINE) &&
    sessionMarkup.includes(QUEUE_SESSION_ERROR_DETAIL) &&
    sessionMarkup.includes(QUEUE_SESSION_ERROR_INSTRUCTION) &&
    sessionMarkup.includes("Retry") &&
    !sessionMarkup.includes("unauthorized (401)") &&
    !sessionMarkup.includes("hol-guard start") &&
    !sessionMarkup.includes("Guard daemon not reachable") &&
    !sessionMarkup.includes("Repair") &&
    !sessionMarkup.includes("Reconnect"),
  "401 inbox errors do not tell the user Guard is down or offer Reconnect",
);

const requestId = "2c79d707370b453886adf5b2e7e622ec";
const sessionWithRequestMarkup = renderToStaticMarkup(
  createElement(QueueConnectionError, {
    message: "unauthorized (401)",
    approvalUrl: null,
    requestId,
    onRetry: () => undefined,
  }),
);
assert(
  sessionWithRequestMarkup.includes(`href="hol-guard-desktop://requests/${requestId}"`) &&
    sessionWithRequestMarkup.includes("Open in HOL Guard Desktop") &&
    sessionWithRequestMarkup.includes(`hol-guard approvals open ${requestId}`) &&
    sessionWithRequestMarkup.includes(QUEUE_SESSION_COMMAND_INSTRUCTION) &&
    sessionWithRequestMarkup.includes("Retry") &&
    !sessionWithRequestMarkup.includes("guard-token"),
  "An unsigned request link offers HOL Guard Desktop and the signed open command",
);
assert(
  !sessionMarkup.includes("hol-guard-desktop://") && !sessionMarkup.includes("approvals open"),
  "No request id: no Desktop link or open command",
);
assert(
  desktopRequestUrl("../x") === null &&
    desktopRequestUrl("2C79D707370B453886ADF5B2E7E622EC") === null &&
    approvalsOpenCommand("req; rm -rf ~") === null &&
    desktopRequestUrl(null) === null,
  "Only a queue-shaped request id becomes a link or a command",
);
const connectionWithRequestMarkup = renderToStaticMarkup(
  createElement(QueueConnectionError, { message: "Failed to fetch", approvalUrl: null, requestId }),
);
assert(
  !connectionWithRequestMarkup.includes("hol-guard-desktop://") &&
    !connectionWithRequestMarkup.includes("approvals open"),
  "A daemon that is down gets the start recovery, not the signed-session links",
);

console.log("queue-connection-error.test.ts: all tests passed");
