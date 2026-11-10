/**
 * Yanez Pulse in the approval center.
 *
 * When the approval gate uses Pulse, the daemon answers a gated request with
 * `approval_gate_pulse_required`. This layer then retries it once asking the
 * daemon to create the Pulse request for that exact action (`approval_gate_pulse`).
 * It shows the match code, checks every 10 seconds until the YID app answers
 * (a check that cannot reach Pulse is tried again until the window closes), and resubmits the
 * same request with `approval_pulse_request_id`. The CLI uses the same daemon
 * and resident path, so both surfaces approve the same action the same way.
 *
 * Rejection, expiry and an unreachable Pulse all end the request with an
 * error; nothing here can grant anything by itself.
 */

export const PULSE_APPROVAL_EVENT = "hol-guard:pulse-approval";
export const PULSE_POLL_PATH = "/v1/approval-gate/pulse/poll";
// The 15-minute decision window plus the 60 s consent grace the resident adds.
const PULSE_DEADLINE_MS = 960_000;
const PULSE_POLL_INTERVAL_MS = 10_000;
// One check is one bounded resident call (at most 8 s); a check that has not
// answered by then is treated like an unreachable Pulse and tried again.
const PULSE_POLL_TIMEOUT_MS = 20_000;

export type PulseWaitTiming = {
  deadlineMs?: number;
  intervalMs?: number;
  /** Longest one check may take before it counts as unreachable. */
  pollTimeoutMs?: number;
  /**
   * Called once the daemon has created the Pulse request, before the wait
   * starts. A caller with its own short deadline stops counting it here: the
   * wait has its own 16-minute window and fails closed.
   */
  onPending?: () => void;
  /**
   * Called once the YID app has approved, just before the request is sent
   * again. A caller that paused its deadline in `onPending` restarts it here,
   * so the resubmission is bounded like the first request.
   */
  onApproved?: () => void;
};

export type PulseApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "error" | "cancelled";

export type PulseApprovalDetail = {
  requestId: string;
  matchCode: string | null;
  decideBy: string | null;
  status: PulseApprovalStatus;
};

type Send = (input: RequestInfo, init?: RequestInit) => Promise<Response>;

function announce(detail: PulseApprovalDetail): void {
  if (typeof window === "undefined" || typeof window.dispatchEvent !== "function") return;
  window.dispatchEvent(new CustomEvent<PulseApprovalDetail>(PULSE_APPROVAL_EVENT, { detail }));
}

function jsonObjectBody(init?: RequestInit): Record<string, unknown> | null {
  if ((init?.method ?? "GET").toUpperCase() !== "POST" || typeof init?.body !== "string") return null;
  try {
    const parsed: unknown = JSON.parse(init.body);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

async function peekJson(response: Response): Promise<Record<string, unknown> | null> {
  try {
    const parsed: unknown = await response.clone().json();
    return parsed !== null && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function failure(code: string, message: string, status = 403): Response {
  return new Response(JSON.stringify({ error: code, message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const OUTCOME_ERRORS: Record<Exclude<PulseApprovalStatus, "pending" | "approved">, [string, string]> = {
  rejected: ["approval_gate_pulse_rejected", "The action was rejected in the YID app."],
  expired: ["approval_gate_pulse_expired", "The Pulse request expired before it was approved."],
  error: ["approval_gate_pulse_unavailable", "Yanez Pulse is unreachable. The action stays blocked."],
  cancelled: ["approval_gate_pulse_cancelled", "The Pulse approval was cancelled."],
};

function pause(ms: number, signal?: AbortSignal | null): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve();
      return;
    }
    const done = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
  });
}

/**
 * One check of the request: an answer, "retry" when Pulse could not be reached
 * or the check did not answer within `timeoutMs`, or a final error.
 */
async function checkOnce(
  send: Send,
  requestId: string,
  signal: AbortSignal | null | undefined,
  timeoutMs: number,
): Promise<PulseApprovalStatus | "retry"> {
  const check = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stop = () => check.abort();
  // Ends the check on the timeout, or at once when the caller cancels, even if
  // the request itself never settles.
  const cutOff = new Promise<"retry" | "cancelled">((resolve) => {
    timer = setTimeout(() => {
      check.abort();
      resolve("retry");
    }, timeoutMs);
    stop = () => {
      check.abort();
      resolve("cancelled");
    };
  });
  signal?.addEventListener("abort", stop, { once: true });
  try {
    return await Promise.race([checkResponse(send, requestId, check.signal, signal), cutOff]);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", stop);
  }
}

async function checkResponse(
  send: Send,
  requestId: string,
  checkSignal: AbortSignal,
  signal: AbortSignal | null | undefined,
): Promise<PulseApprovalStatus | "retry"> {
  try {
    const response = await send(PULSE_POLL_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ request_id: requestId }),
      signal: checkSignal,
    });
    const payload = await peekJson(response);
    if (response.ok) {
      const reported = payload?.status;
      return reported === "pending" || reported === "approved" || reported === "rejected" || reported === "expired"
        ? reported
        : "error";
    }
    if (response.status === 503) return "retry";
    return payload?.error === "approval_gate_pulse_expired" ? "expired" : "error";
  } catch {
    return signal?.aborted ? "cancelled" : "retry";
  }
}

/**
 * Check the request every 10 seconds until the YID app answers or the window
 * closes. A check that cannot reach Pulse is tried again; if Pulse is still
 * unreachable when the window closes, the outcome is "error", not "expired".
 */
export async function waitForPulseApproval(
  send: Send,
  detail: Omit<PulseApprovalDetail, "status">,
  signal?: AbortSignal | null,
  timing: PulseWaitTiming = {},
): Promise<Exclude<PulseApprovalStatus, "pending">> {
  const { deadlineMs = PULSE_DEADLINE_MS, intervalMs = PULSE_POLL_INTERVAL_MS, pollTimeoutMs = PULSE_POLL_TIMEOUT_MS } =
    timing;
  announce({ ...detail, status: "pending" });
  const deadline = Date.now() + deadlineMs;
  let unreachable = false;
  for (let remaining = deadlineMs; remaining > 0; remaining = deadline - Date.now()) {
    await pause(Math.min(intervalMs, remaining), signal);
    // A check never runs past the window, so a stalled one cannot hold the wait open.
    const checkMs = Math.max(1, Math.min(pollTimeoutMs, deadline - Date.now()));
    const status = signal?.aborted ? "cancelled" : await checkOnce(send, detail.requestId, signal, checkMs);
    unreachable = status === "retry";
    if (status !== "pending" && status !== "retry") {
      announce({ ...detail, status });
      return status;
    }
  }
  const status = unreachable ? "error" : "expired";
  announce({ ...detail, status });
  return status;
}

/**
 * Run one request through the Pulse flow when the gate asks for it. Requests
 * the gate does not hold, and every non-JSON request, pass through untouched.
 */
export async function sendWithPulseApproval(
  send: Send,
  input: RequestInfo,
  init?: RequestInit,
  timing?: PulseWaitTiming,
): Promise<Response> {
  let response = await send(input, init);
  let body = jsonObjectBody(init);
  if (body === null || typeof input !== "string" || input.startsWith(PULSE_POLL_PATH)) return response;
  if (response.status === 403 && body.approval_gate_pulse !== true && body.approval_pulse_request_id === undefined) {
    const refused = await peekJson(response);
    if (refused?.error !== "approval_gate_pulse_required") return response;
    body = { ...body, approval_gate_pulse: true };
    response = await send(input, { ...init, body: JSON.stringify(body) });
  }
  if (response.status !== 202) return response;
  const pending = await peekJson(response);
  const requestId = pending?.pulse_request_id;
  if (pending?.error !== "approval_gate_pulse_pending" || typeof requestId !== "string" || requestId === "") {
    return response;
  }
  timing?.onPending?.();
  const outcome = await waitForPulseApproval(
    send,
    {
      requestId,
      matchCode: typeof pending.pulse_match_code === "string" ? pending.pulse_match_code : null,
      decideBy: typeof pending.pulse_decide_by === "string" ? pending.pulse_decide_by : null,
    },
    init?.signal,
    timing,
  );
  if (outcome !== "approved") {
    const [code, message] = OUTCOME_ERRORS[outcome];
    return failure(code, message, outcome === "error" ? 503 : 403);
  }
  // The YID approval is the proof now; the resident refuses a password or code beside it.
  const { approval_gate_pulse: _defer, approval_password: _password, approval_totp_code: _code, ...rest } = body;
  timing?.onApproved?.();
  return send(input, { ...init, body: JSON.stringify({ ...rest, approval_pulse_request_id: requestId }) });
}

/**
 * The face scan Pulse setup asks for. Guard verifies every later Pulse
 * approval against it: "medium" is a standard face scan, "high" a strict one.
 * The resident refuses anything else, so "low" is never offered.
 */
export type PulseMinTier = "medium" | "high";

export const PULSE_FACE_SCAN_OPTIONS: ReadonlyArray<{ value: PulseMinTier; label: string }> = [
  { value: "medium", label: "Standard face scan (recommended)" },
  { value: "high", label: "Strict face scan" },
];

/** The body that starts Pulse setup: the agent key and the chosen face scan. */
export function pulseEnrollmentBody(agentKey: string, minTier: PulseMinTier): Record<string, string> {
  return { pulse_agent_key: agentKey, min_tier: minTier };
}

/**
 * Plain words for a setup refusal about the face scan, or null to show the
 * daemon's own message. The UI never names assurance tiers.
 */
export function pulseSetupRefusalMessage(code: unknown, minTier: PulseMinTier): string | null {
  if (code === "approval_gate_pulse_no_signing_key") {
    return minTier === "high"
      ? "None of your devices in the YID app supports a strict face scan. Choose Standard face scan, or add a device that supports it in the YID app, then try again."
      : "Your Yanez identity has no device that can approve yet. Finish setting up the YID app on your phone, then try again.";
  }
  if (code === "approval_gate_pulse_invalid_tier") {
    return "Choose Standard or Strict face scan, then try again.";
  }
  return null;
}

/**
 * The approvals the toast shows, one per Pulse request. An event replaces only
 * its own request's entry, so a finished approval never hides the match code
 * of another one that is still waiting.
 */
export function nextPulseToasts(
  current: readonly PulseApprovalDetail[],
  detail: PulseApprovalDetail,
): PulseApprovalDetail[] {
  return current.some((entry) => entry.requestId === detail.requestId)
    ? current.map((entry) => (entry.requestId === detail.requestId ? detail : entry))
    : [...current, detail];
}

/** Drop a finished request's toast; a request that is waiting again stays. */
export function dropFinishedPulseToast(
  current: readonly PulseApprovalDetail[],
  requestId: string,
): PulseApprovalDetail[] {
  return current.filter((entry) => entry.requestId !== requestId || entry.status === "pending");
}
