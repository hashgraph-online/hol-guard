import {
  PULSE_FACE_SCAN_OPTIONS,
  PULSE_POLL_PATH,
  dropFinishedPulseToast,
  nextPulseToasts,
  pulseEnrollmentBody,
  pulseSetupRefusalMessage,
  sendWithPulseApproval,
  waitForPulseApproval,
  type PulseApprovalDetail,
} from "./pulse-approval";
import { approvalProofCooldownOptionShown, approvalProofModalTitle } from "./approval-center-review-cards";
import { withLocalProtectionDeadline } from "./guard-api";
import { PULSE_SITE_URL, pulseSetupCanClose, runPulseEnrollment, type PulseEnrollmentSteps } from "./pulse-setup-modal";
import { bulkPulsePrompt } from "./queue-bulk-approval-credentials";
import { buildApprovalProofCredentials, isApprovalProofSubmitDisabled } from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

type Call = { input: string; body: Record<string, unknown> };

function json(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json" } });
}

/** A daemon whose gate uses Pulse. `polls` is the status sequence the YID app reports. */
function pulseDaemon(polls: string[]) {
  const calls: Call[] = [];
  const send = async (input: RequestInfo, init?: RequestInit): Promise<Response> => {
    const body = typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : {};
    calls.push({ input: String(input), body });
    if (input === PULSE_POLL_PATH) {
      return json(200, { status: polls.shift() ?? "expired" });
    }
    if (body.approval_pulse_request_id === "azr_1") return json(200, { ok: true });
    if (body.approval_gate_pulse === true) {
      return json(202, {
        error: "approval_gate_pulse_pending",
        message: "Approve this action in the YID app.",
        pulse_request_id: "azr_1",
        pulse_match_code: "ABC123",
        pulse_decide_by: "2026-10-02T00:03:00+00:00",
      });
    }
    return json(403, { error: "approval_gate_pulse_required", message: "Approve in the YID app." });
  };
  return { calls, send };
}

const decision = { method: "POST", body: JSON.stringify({ action: "allow", scope: "workspace" }) };
// No pause between checks, so the tests do not wait 10 seconds per check.
const fast = { intervalMs: 0 };

async function approvedRequestIsResubmittedWithTheSameBody(): Promise<void> {
  const daemon = pulseDaemon(["pending", "approved"]);
  const response = await sendWithPulseApproval(daemon.send, "/v1/requests/r1/decision", decision, fast);
  assert(response.status === 200, "PULSE-1: approved request succeeds");
  const posts = daemon.calls.filter((c) => c.input === "/v1/requests/r1/decision");
  assert(posts.length === 3, "PULSE-1: original, defer, resubmit");
  const last = posts[2].body;
  assert(last.action === "allow" && last.scope === "workspace", "PULSE-1: resubmission keeps the exact action");
  assert(last.approval_pulse_request_id === "azr_1", "PULSE-1: resubmission carries the Pulse request id");
  assert(last.approval_gate_pulse === undefined, "PULSE-1: resubmission does not ask for another request");
}

async function resubmissionDropsThePasswordAndCode(): Promise<void> {
  const daemon = pulseDaemon(["approved"]);
  const withSecrets = {
    method: "POST",
    body: JSON.stringify({ request_ids: ["r1", "r2"], approval_password: "secret", approval_totp_code: "123456" }),
  };
  await sendWithPulseApproval(daemon.send, "/v1/requests/r1/decision", withSecrets, fast);
  const last = daemon.calls.filter((c) => c.input === "/v1/requests/r1/decision").at(-1)!.body;
  assert(
    last.approval_password === undefined && last.approval_totp_code === undefined,
    "PULSE-8: the resident refuses a password or code beside Pulse, so the resubmission drops them",
  );
  assert(Array.isArray(last.request_ids) && last.request_ids.length === 2, "PULSE-8: the rest of the body is kept");
}

async function rejectionAndExpiryFailClosed(): Promise<void> {
  for (const [status, code] of [["rejected", "approval_gate_pulse_rejected"], ["expired", "approval_gate_pulse_expired"]]) {
    const daemon = pulseDaemon([status]);
    const response = await sendWithPulseApproval(daemon.send, "/v1/requests/r1/decision", decision, fast);
    const payload = (await response.json()) as { error?: string };
    assert(response.status === 403, `PULSE-2: ${status} is refused`);
    assert(payload.error === code, `PULSE-2: ${status} reports ${code}`);
    assert(
      !daemon.calls.some((c) => c.body.approval_pulse_request_id !== undefined),
      `PULSE-2: ${status} never resubmits`,
    );
  }
}

async function anOutageFailsClosed(): Promise<void> {
  const daemon = pulseDaemon([]);
  const send = async (input: RequestInfo, init?: RequestInit) => {
    if (input === PULSE_POLL_PATH) throw new Error("connection refused");
    return daemon.send(input, init);
  };
  const response = await sendWithPulseApproval(send, "/v1/requests/r1/decision", decision, {
    deadlineMs: 50,
    intervalMs: 5,
  });
  assert(response.status === 503, "PULSE-3: Pulse still unreachable when the window closes fails closed");
}

async function aSlowCheckIsTriedAgain(): Promise<void> {
  for (const failure of ["throw", "503"]) {
    const daemon = pulseDaemon(["pending", "approved"]);
    let failed = false;
    const send = async (input: RequestInfo, init?: RequestInit) => {
      if (input === PULSE_POLL_PATH && !failed) {
        failed = true;
        if (failure === "throw") throw new Error("timed out");
        return json(503, { error: "approval_gate_pulse_unavailable", message: "unreachable" });
      }
      return daemon.send(input, init);
    };
    const response = await sendWithPulseApproval(send, "/v1/requests/r1/decision", decision, fast);
    assert(response.status === 200, `PULSE-6: one ${failure} check does not end the wait`);
  }
}

async function aLostRequestStopsTheWait(): Promise<void> {
  let checks = 0;
  const send = async () => {
    checks += 1;
    return json(403, { error: "approval_gate_pulse_expired", message: "gone" });
  };
  const outcome = await waitForPulseApproval(send, { requestId: "azr_1", matchCode: null, decideBy: null }, null, fast);
  assert(outcome === "expired" && checks === 1, "PULSE-7: a request Guard no longer holds ends the wait at once");
}

async function ungatedRequestsPassThrough(): Promise<void> {
  let count = 0;
  const send = async () => {
    count += 1;
    return json(403, { error: "approval_gate_invalid_password", message: "wrong" });
  };
  const response = await sendWithPulseApproval(send, "/v1/requests/r1/decision", decision);
  assert(response.status === 403 && count === 1, "PULSE-4: other refusals are returned untouched");
  const get = await sendWithPulseApproval(async () => json(200, { ok: true }), "/v1/settings");
  assert(get.status === 200, "PULSE-4: GET requests pass through");
}

async function pollingStopsOnTheDeadline(): Promise<void> {
  const daemon = pulseDaemon(["pending", "pending", "pending"]);
  const outcome = await waitForPulseApproval(daemon.send, { requestId: "azr_1", matchCode: null, decideBy: null }, null, {
    deadlineMs: 0,
  });
  assert(outcome === "expired", "PULSE-5: a deadline with no answer is expiry");
}

function proofFieldsAskForNothingLocal(): void {
  const gate: GuardApprovalGatePublicConfig = {
    enabled: true,
    configured: true,
    cooldown_seconds: 0,
    cooldown_active: false,
    cooldown_expires_at: null,
    locked_until: null,
    fail_closed: false,
    strict_all_decisions: false,
    totp_enabled: false,
    pulse_enabled: true,
  };
  const empty = { approvalPassword: "", approvalTotpCode: "" };
  assert(!isApprovalProofSubmitDisabled(gate, empty, false), "PULSE-6: Pulse needs no typed proof");
  assert(Object.keys(buildApprovalProofCredentials(gate, { approvalPassword: "pw", approvalTotpCode: "" })).length === 0,
    "PULSE-6: no password leaves the page in Pulse mode");
  assert(isApprovalProofSubmitDisabled({ ...gate, locked_until: "2999-01-01T00:00:00Z" }, empty, false),
    "PULSE-6: a locked gate stays locked");
}

function setupSendsTheChosenFaceScan(): void {
  const values = PULSE_FACE_SCAN_OPTIONS.map((option) => option.value);
  assert(values.join(",") === "medium,high", "PULSE-7: only standard and strict are offered, standard first");
  assert(PULSE_FACE_SCAN_OPTIONS.every((option) => !/tier|medium|high|low|assurance/i.test(option.label)),
    "PULSE-7: the labels never name an assurance tier");
  const strict = pulseEnrollmentBody("yak_x", "high");
  assert(strict.min_tier === "high" && strict.pulse_agent_key === "yak_x", "PULSE-7: setup sends the chosen face scan");
  assert(pulseEnrollmentBody("yak_x", "medium").min_tier === "medium", "PULSE-7: standard is sent as medium");
}

function setupRefusalsUsePlainWords(): void {
  const strict = pulseSetupRefusalMessage("approval_gate_pulse_no_signing_key", "high");
  assert(strict !== null && strict.includes("strict face scan"), "PULSE-8: a phone without the strict scan is explained");
  const standard = pulseSetupRefusalMessage("approval_gate_pulse_no_signing_key", "medium");
  assert(standard !== null && !standard.includes("strict"), "PULSE-8: standard setup does not mention strict");
  for (const message of [strict, standard, pulseSetupRefusalMessage("approval_gate_pulse_invalid_tier", "medium")]) {
    assert(message !== null && !/tier|assurance|medium|high/i.test(message), "PULSE-8: refusals never name a tier");
  }
  assert(pulseSetupRefusalMessage("approval_gate_required", "medium") === null, "PULSE-8: other refusals keep their message");
}


// Review of #7490.

async function aStalledCheckCannotHoldTheWaitOpen(): Promise<void> {
  const never = () => new Promise<Response>(() => undefined);
  const started = Date.now();
  const outcome = await waitForPulseApproval(
    never,
    { requestId: "azr_1", matchCode: "ABC123", decideBy: null },
    null,
    { deadlineMs: 120, intervalMs: 0, pollTimeoutMs: 30 },
  );
  assert(outcome === "error", "PULSE-9: a check that never answers ends as unreachable, not pending");
  assert(Date.now() - started < 1000, "PULSE-9: the wait ends at its window");
  const controller = new AbortController();
  const waiting = waitForPulseApproval(
    never,
    { requestId: "azr_1", matchCode: null, decideBy: null },
    controller.signal,
    { deadlineMs: 60_000, intervalMs: 0, pollTimeoutMs: 60_000 },
  );
  setTimeout(() => controller.abort(), 20);
  assert((await waiting) === "cancelled", "PULSE-9: cancelling ends a stalled check at once");
}

async function aShortDeadlineStopsOnceThePulseRequestExists(): Promise<void> {
  const daemon = pulseDaemon(["approved"]);
  const heard: string[] = [];
  const response = await sendWithPulseApproval(daemon.send, "/v1/requests/r1/decision", decision, {
    ...fast,
    onPending: () => heard.push("pending"),
    onApproved: () => heard.push(`approved after ${daemon.calls.length} calls`),
  });
  assert(response.status === 200 && heard.length === 2 && heard[0] === "pending",
    "PULSE-10: the caller hears once when the Pulse wait starts and once when it ends");
  assert(heard[1] === `approved after ${daemon.calls.length - 1} calls`,
    "PULSE-10: the approval is announced just before the resubmission");
  const rejected = pulseDaemon(["rejected"]);
  let restarted = false;
  await sendWithPulseApproval(rejected.send, "/v1/requests/r1/decision", decision, {
    ...fast,
    onApproved: () => {
      restarted = true;
    },
  });
  assert(!restarted, "PULSE-10: nothing is resubmitted, and no deadline restarted, without an approval");
  let ungated = 0;
  await sendWithPulseApproval(async () => json(200, { ok: true }), "/v1/settings", decision, {
    onPending: () => {
      ungated += 1;
    },
  });
  assert(ungated === 0, "PULSE-10: an ungated request never stops the caller's deadline");
  const slowApproval = await withLocalProtectionDeadline(async (_signal, deadline) => {
    deadline.pause();
    await new Promise((resolve) => setTimeout(resolve, 60));
    deadline.restart();
    return "approved";
  }, 20, "too slow");
  assert(slowApproval === "approved", "PULSE-10: a paused deadline lets a slow face scan finish");
  let stalledResubmission = false;
  let aborted = false;
  try {
    await withLocalProtectionDeadline((signal, deadline) => {
      signal.addEventListener("abort", () => {
        aborted = true;
      });
      deadline.pause();
      return new Promise((resolve) => setTimeout(() => {
        deadline.restart();
        // The resubmission never answers.
        void resolve;
      }, 40));
    }, 20, "too slow");
  } catch {
    stalledResubmission = true;
  }
  assert(stalledResubmission && aborted, "PULSE-10: a stalled resubmission still hits a fresh deadline and is aborted");
  let refused = false;
  try {
    await withLocalProtectionDeadline(() => new Promise(() => undefined), 20, "too slow");
  } catch {
    refused = true;
  }
  assert(refused, "PULSE-10: without a Pulse wait the deadline still applies");
}

function eachApprovalKeepsItsOwnMatchCode(): void {
  const first: PulseApprovalDetail = { requestId: "a", matchCode: "AAA111", decideBy: null, status: "pending" };
  const second: PulseApprovalDetail = { requestId: "b", matchCode: "BBB222", decideBy: null, status: "pending" };
  let toasts = nextPulseToasts(nextPulseToasts([], first), second);
  toasts = nextPulseToasts(toasts, { ...first, status: "approved" });
  const waiting = toasts.find((entry) => entry.requestId === "b");
  assert(toasts.length === 2 && waiting?.status === "pending" && waiting.matchCode === "BBB222",
    "PULSE-11: a finished approval does not hide another one's match code");
  toasts = dropFinishedPulseToast(toasts, "a");
  assert(toasts.length === 1 && toasts[0].requestId === "b", "PULSE-11: only the finished entry is removed");
  assert(dropFinishedPulseToast(toasts, "b").length === 1, "PULSE-11: a waiting entry is never removed");
}

function setupCannotCloseWhileFinishing(): void {
  assert(pulseSetupCanClose("confirm") && pulseSetupCanClose("connect") && pulseSetupCanClose("approve"),
    "PULSE-12: setup can close before Guard finishes it");
  assert(!pulseSetupCanClose("verifying"), "PULSE-12: setup cannot close while Guard turns Pulse on");
  assert(!pulseSetupCanClose("recovery"), "PULSE-12: setup cannot close while the recovery code is shown");
}

async function closingSetupWhileItStartsNeverTurnsPulseOn(): Promise<void> {
  const enrollment = {
    status: "pending" as const, request_id: "azr_setup", match_code: "K7Q2XM", yid_hint: "yid_…", decide_by: "",
  };
  function setup(overrides: Partial<PulseEnrollmentSteps> = {}) {
    const calls: string[] = [];
    let open = true;
    const steps: PulseEnrollmentSteps = {
      begin: async () => {
        calls.push("begin");
        return enrollment;
      },
      isOpen: () => open,
      started: () => calls.push("started"),
      wait: async () => {
        calls.push("wait");
        return "approved";
      },
      verifying: () => calls.push("verifying"),
      confirm: async () => {
        calls.push("confirm");
        return "PRC-ONCE";
      },
      ...overrides,
    };
    return { calls, steps, close: () => { open = false; } };
  }

  const normal = setup();
  assert((await runPulseEnrollment(normal.steps)) === "PRC-ONCE", "PULSE-15: a completed setup returns its recovery code");
  assert(normal.calls.join(",") === "begin,started,wait,verifying,confirm", "PULSE-15: setup runs in order");

  // The window closes while Guard is still starting the enrollment.
  const closedWhileStarting = setup();
  closedWhileStarting.steps.begin = async () => {
    closedWhileStarting.calls.push("begin");
    closedWhileStarting.close();
    return enrollment;
  };
  assert((await runPulseEnrollment(closedWhileStarting.steps)) === null, "PULSE-15: a closed setup reports nothing");
  assert(closedWhileStarting.calls.join(",") === "begin",
    "PULSE-15: closed while starting, setup neither waits for the YID app nor turns Pulse on");

  // The window closes during the wait (which then ends as cancelled).
  const closedWhileWaiting = setup();
  closedWhileWaiting.steps.wait = async () => {
    closedWhileWaiting.calls.push("wait");
    closedWhileWaiting.close();
    return "cancelled";
  };
  let refused = false;
  try {
    await runPulseEnrollment(closedWhileWaiting.steps);
  } catch {
    refused = true;
  }
  assert(refused && !closedWhileWaiting.calls.includes("confirm"), "PULSE-15: a cancelled wait never turns Pulse on");

  // Even an approval that arrives after the window closed is not used.
  const closedThenApproved = setup();
  closedThenApproved.steps.wait = async () => {
    closedThenApproved.calls.push("wait");
    closedThenApproved.close();
    return "approved";
  };
  assert((await runPulseEnrollment(closedThenApproved.steps)) === null && !closedThenApproved.calls.includes("confirm"),
    "PULSE-15: an approval after the window closed does not turn Pulse on");

  assert(!pulseSetupCanClose("connect", true), "PULSE-15: setup cannot close while starting the enrollment");
  assert(pulseSetupCanClose("connect", false), "PULSE-15: setup can close on step 2 when nothing is in flight");
}

function theSetupLinkTellsYanezItCameFromGuard(): void {
  const link = new URL(PULSE_SITE_URL);
  assert(link.origin === "https://pulse.yanez.ai", "PULSE-16: setup links to the YID app page");
  assert(link.searchParams.get("referrer") === "holguard" && [...link.searchParams.keys()].length === 1,
    "PULSE-16: the link carries only the HOL Guard referrer");
}

function theBulkPromptCountsWhatThePhoneShows(): void {
  assert(bulkPulsePrompt(1) === "Approve this request in your YID app.", "PULSE-13: one request");
  assert(bulkPulsePrompt(3) === "Approve these 3 requests in your YID app.",
    "PULSE-13: the count is the number of requests sent to the phone");
}

function pulseModeNeverAsksForAPasswordOrCode(): void {
  assert(approvalProofModalTitle(false, false, false, true) === "Approve in the YID app",
    "PULSE-14: the approval window names the YID app in Pulse mode");
  assert(approvalProofModalTitle(false, false, false) === "Authenticator code required",
    "PULSE-14: the authenticator title is unchanged");
  const gate: GuardApprovalGatePublicConfig = {
    enabled: true,
    configured: true,
    cooldown_seconds: 300,
    cooldown_active: false,
    cooldown_expires_at: null,
    locked_until: null,
    fail_closed: false,
    strict_all_decisions: false,
    totp_enabled: false,
    pulse_enabled: true,
  };
  assert(!approvalProofCooldownOptionShown(gate), "PULSE-14: no password-cooldown checkbox in Pulse mode");
  assert(approvalProofCooldownOptionShown({ ...gate, pulse_enabled: false }),
    "PULSE-14: the password gate keeps its checkbox");
}

await approvedRequestIsResubmittedWithTheSameBody();
await resubmissionDropsThePasswordAndCode();
await rejectionAndExpiryFailClosed();
await anOutageFailsClosed();
await aSlowCheckIsTriedAgain();
await aLostRequestStopsTheWait();
await ungatedRequestsPassThrough();
await pollingStopsOnTheDeadline();
proofFieldsAskForNothingLocal();
setupSendsTheChosenFaceScan();
setupRefusalsUsePlainWords();
await aStalledCheckCannotHoldTheWaitOpen();
await aShortDeadlineStopsOnceThePulseRequestExists();
eachApprovalKeepsItsOwnMatchCode();
setupCannotCloseWhileFinishing();
theBulkPromptCountsWhatThePhoneShows();
pulseModeNeverAsksForAPasswordOrCode();
await closingSetupWhileItStartsNeverTurnsPulseOn();
theSetupLinkTellsYanezItCameFromGuard();
console.log("pulse-approval tests passed");
