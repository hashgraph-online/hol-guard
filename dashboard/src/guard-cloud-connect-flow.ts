import type { GuardCloudConnectFlow, GuardCloudConnectStatusResponse } from "./guard-types";
import { fetchGuardApi, fetchGuardCloudConnectStatus } from "./guard-api";

export type GuardCloudOpenStatus = GuardCloudConnectStatusResponse & {
  dashboard_url?: string | null;
};

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function safeCloudConnectUrl(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (!url.hostname || url.username || url.password) return null;
    const host = url.hostname.toLowerCase();
    const approvedHttps = url.protocol === "https:" && (host === "hol.org" || host.endsWith(".hol.org"));
    const localHttp = url.protocol === "http:" && LOOPBACK_HOSTS.has(host);
    if (!approvedHttps && !localHttp) return null;
    return url.toString();
  } catch {
    return null;
  }
}

export class CloudRequestTimeoutError extends Error {
  constructor() {
    super("Guard Cloud did not respond within 5 seconds. Try again.");
    this.name = "CloudRequestTimeoutError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function connectFlowFromPayload(value: unknown): GuardCloudConnectFlow | null {
  if (!isRecord(value)) return null;
  const connectUrl = typeof value.connect_url === "string" ? safeCloudConnectUrl(value.connect_url) : null;
  if (!connectUrl) return null;
  return {
    state: value.state === "starting" || value.state === "running" || value.state === "failed" ? value.state : "idle",
    title: typeof value.title === "string" ? value.title : "",
    detail: typeof value.detail === "string" ? value.detail : "",
    action_label: typeof value.action_label === "string" ? value.action_label : "",
    connect_url: connectUrl,
    authorize_url: typeof value.authorize_url === "string" ? safeCloudConnectUrl(value.authorize_url) : null,
    browser_opened: typeof value.browser_opened === "boolean" ? value.browser_opened : null,
    request_id: typeof value.request_id === "string" ? value.request_id : null,
    poll_after_ms: typeof value.poll_after_ms === "number" ? value.poll_after_ms : null,
  };
}

export function parseGuardCloudConnectHttp(
  status: number,
  payload: unknown,
): GuardCloudOpenStatus {
  const record = isRecord(payload) ? payload : {};
  const dashboardUrl = typeof record.dashboard_url === "string" ? safeCloudConnectUrl(record.dashboard_url) : null;
  if (status === 409 && record.error === "guard_cloud_connect_not_required") {
    return {
      connect_required: false,
      connect_flow: null,
      dashboard_url: dashboardUrl,
    };
  }
  if (status < 200 || status >= 300) {
    const message = typeof record.message === "string" && record.message.trim()
      ? record.message
      : typeof record.error === "string" && record.error.trim()
        ? `${record.error} (${status})`
        : `Request failed with ${status}`;
    throw new Error(message);
  }
  return {
    connect_required: record.connect_required === true,
    connect_flow: connectFlowFromPayload(record.connect_flow),
    dashboard_url: dashboardUrl,
  };
}

async function readCloudConnect(
  method: "GET" | "POST",
  signal: AbortSignal,
): Promise<GuardCloudOpenStatus> {
  const response = await fetchGuardApi("/v1/cloud/connect", {
    method,
    signal,
    ...(method === "POST"
      ? {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        }
      : {}),
  });
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  return parseGuardCloudConnectHttp(response.status, payload);
}

export async function withCloudRequestTimeout<T>(
  request: (signal: AbortSignal) => Promise<T>,
  parentSignal?: AbortSignal,
): Promise<T> {
  if (parentSignal?.aborted) {
    throw new DOMException("Cloud connection request stopped", "AbortError");
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  parentSignal?.addEventListener("abort", abort, { once: true });
  let timedOut = false;
  const timeout = globalThis.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, 5000);
  try {
    return await request(controller.signal);
  } catch (error: unknown) {
    if (timedOut && !parentSignal?.aborted && error instanceof DOMException && error.name === "AbortError") {
      throw new CloudRequestTimeoutError();
    }
    throw error;
  } finally {
    globalThis.clearTimeout(timeout);
    parentSignal?.removeEventListener("abort", abort);
  }
}

type ReadCloudConnect = (
  method: "GET" | "POST",
  signal: AbortSignal,
) => Promise<GuardCloudOpenStatus>;

export async function startOrRecoverCloudConnect(
  signal: AbortSignal,
  readConnect: ReadCloudConnect = readCloudConnect,
): Promise<GuardCloudOpenStatus> {
  try {
    return await withCloudRequestTimeout((nextSignal) => readConnect("POST", nextSignal), signal);
  } catch (error: unknown) {
    if (!(error instanceof CloudRequestTimeoutError)) throw error;
    try {
      return await withCloudRequestTimeout((nextSignal) => readConnect("GET", nextSignal), signal);
    } catch {
      return await withCloudRequestTimeout((nextSignal) => readConnect("POST", nextSignal), signal);
    }
  }
}

function waitForPoll(delayMs: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.reject(new DOMException("Cloud connection polling stopped", "AbortError"));
  }
  return new Promise<void>((resolve, reject) => {
    const finish = () => {
      signal.removeEventListener("abort", abort);
      resolve();
    };
    const timeout = globalThis.setTimeout(finish, delayMs);
    const abort = () => {
      globalThis.clearTimeout(timeout);
      reject(new DOMException("Cloud connection polling stopped", "AbortError"));
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}

export async function waitForAuthorizeUrl(
  initialStatus: GuardCloudOpenStatus,
  signal: AbortSignal,
  poll: ReadCloudConnect = readCloudConnect,
): Promise<GuardCloudOpenStatus> {
  if (signal.aborted) {
    throw new DOMException("Cloud connection polling stopped", "AbortError");
  }
  let status = initialStatus;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const flow = status.connect_flow;
    if (
      !status.connect_required
      || flow?.authorize_url
      || !flow
      || !["starting", "running"].includes(flow.state)
    ) {
      return status;
    }
    const pollDelayMs = Math.max(100, Math.min(5000, flow.poll_after_ms ?? 1000));
    await waitForPoll(pollDelayMs, signal);
    const polled = await withCloudRequestTimeout((nextSignal) => poll("GET", nextSignal), signal);
    status = {
      ...polled,
      dashboard_url: safeCloudConnectUrl(polled.dashboard_url) ?? safeCloudConnectUrl(status.dashboard_url),
    };
  }
  return status;
}

type CloudConnectionPollOptions = {
  signal: AbortSignal;
  fetchStatus?: (signal: AbortSignal) => Promise<GuardCloudConnectStatusResponse>;
  wait?: (delayMs: number, signal: AbortSignal) => Promise<void>;
  maxAttempts?: number;
};

export async function waitForCloudConnection(
  initialStatus: GuardCloudConnectStatusResponse,
  {
    signal,
    fetchStatus = fetchGuardCloudConnectStatus,
    wait = waitForPoll,
    maxAttempts = 300,
  }: CloudConnectionPollOptions,
): Promise<GuardCloudConnectStatusResponse> {
  if (signal.aborted) {
    throw new DOMException("Cloud connection polling stopped", "AbortError");
  }
  let status = initialStatus;
  for (let attempt = 0; attempt < maxAttempts && status.connect_required; attempt += 1) {
    if (status.connect_flow?.state === "failed") return status;
    const pollDelayMs = Math.max(250, Math.min(5000, status.connect_flow?.poll_after_ms ?? 1000));
    await wait(pollDelayMs, signal);
    status = await withCloudRequestTimeout(fetchStatus, signal);
  }
  return status;
}
