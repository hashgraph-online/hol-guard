import {
  PULSE_FACE_SCAN_OPTIONS,
  PULSE_POLL_PATH,
  pulseEnrollmentBody,
  pulseSetupRefusalMessage,
  sendWithPulseApproval,
  waitForPulseApproval,
} from "./pulse-approval";
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
console.log("pulse-approval tests passed");
