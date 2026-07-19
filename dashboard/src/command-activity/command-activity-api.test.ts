import {
  CommandActivityApiError,
  clearCommandActivityEvidence,
  createCommandActivityClient,
  fetchCommandActivityAnalytics,
  fetchCommandActivityPage,
  parseCommandActivitySseFrame,
  recordCommandActivityFeedback,
  streamCommandActivityInvalidations,
  type CommandActivityTransport,
} from "./command-activity-api";
import { DEFAULT_COMMAND_ACTIVITY_FILTERS } from "./command-activity-state";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

const location = new URL(
  "http://127.0.0.1:4173/evidence#guard_token=dashboard-session&guard_daemon=http%3A%2F%2F127.0.0.1%3A64123",
);
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: { location, localStorage: new MemoryStorage(), sessionStorage: new MemoryStorage() },
});

const requests: { url: string; init: RequestInit | undefined }[] = [];
let responder: (url: string, init: RequestInit | undefined) => Response;
const transport: CommandActivityTransport = async (input, init) => {
  const path = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  const url = new URL(path, "http://127.0.0.1:64123").toString();
  const headers = new Headers(init?.headers);
  headers.set("X-Guard-Dashboard-Session", "dashboard-session");
  const authenticated = { ...init, headers };
  requests.push({ url, init: authenticated });
  return responder(url, authenticated);
};

function activityPage(): object {
  return {
    schema_version: "guard.command-activity-api.v1",
    items: [
      {
        activity_id: "activity:01",
        occurred_at: "2026-07-19T12:00:00+00:00",
        harness: "codex",
        hook_phase: "pre",
        execution_status: "allowed_unconfirmed",
        proof_level: "pre_hook",
        policy_action: "allow",
        decision_reason_code: "no_match",
        controlling_rule_id: null,
        parse_confidence: "exact",
        uncertainty_class: null,
        match_count: 0,
        prompted: false,
        approval_reuse_status: "not-applicable",
        receipt_link_status: "not_applicable",
        receipt_id: null,
        evaluation_latency_bucket: "le_1_ms",
        persistence_latency_bucket: "le_1_ms",
        feedback_label: null,
        schema_version: "1.0.0",
        matches: [],
      },
    ],
    next_cursor: null,
  };
}

responder = () => Response.json(activityPage());
const client = createCommandActivityClient(transport);
const page = await client.fetchPage(DEFAULT_COMMAND_ACTIVITY_FILTERS);
assert(page.items.length === 1, "activity client returns a normalized page");
const pageRequest = requests.at(-1);
assert(pageRequest !== undefined, "activity client issues a request");
assert(pageRequest.url.startsWith("http://127.0.0.1:64123/v1/command-activity?"), "activity client targets loopback daemon");
assert(!pageRequest.url.includes("dashboard-session"), "dashboard session never enters the request URL");
assert(
  new Headers(pageRequest.init?.headers).get("X-Guard-Dashboard-Session") === "dashboard-session",
  "activity client uses the existing dashboard-session header",
);

responder = (_url, init) => {
  const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
  assert(body?.activity_id === "activity:01", "feedback sends only the selected activity ID");
  assert(Object.keys(body).sort().join(",") === "activity_id,label", "feedback never accepts free-form notes");
  return Response.json({
    schema_version: "guard.command-activity-api.v1",
    activity_id: "activity:01",
    label: "should_not_have_interrupted",
    created_at: "2026-07-19T12:00:00+00:00",
    updated_at: "2026-07-19T12:00:00+00:00",
    changed: true,
  });
};
const feedbackInput = Object.assign(
  { activity_id: "activity:01", label: "should_not_have_interrupted" as const },
  { notes: "must-not-cross-transport" },
);
const feedback = await recordCommandActivityFeedback(feedbackInput, undefined, transport);
assert(feedback.changed, "feedback results normalize");

const deletionCounts = {
  activities: 1,
  matches: 0,
  effects: 0,
  correlations: 0,
  rollup_days: 0,
  rollup_cells: 0,
  rollup_memberships: 0,
  rollup_pending: 0,
  feedback: 0,
  invalidations: 0,
};
responder = (_url, init) => {
  const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
  assert(body?.confirm === "clear-command-activity", "deletion always supplies the exact confirmation phrase");
  assert(body?.approval_gate_use_cooldown === false, "deletion preserves explicit approval proof choices");
  assert(
    Object.keys(body).sort().join(",") === "approval_gate_use_cooldown,confirm",
    "deletion strips unexpected runtime properties",
  );
  return Response.json({ schema_version: "guard.command-activity-diagnostics.v1", deleted: deletionCounts });
};
const deletionProof = Object.assign(
  { approval_gate_use_cooldown: false },
  { notes: "must-not-cross-transport" },
);
const deletion = await clearCommandActivityEvidence(deletionProof, undefined, transport);
assert(deletion.deleted.activities === 1, "deletion results normalize");

responder = () => Response.json({ error: "approval_gate_totp_required" }, { status: 403 });
let deletionError: unknown;
try {
  await clearCommandActivityEvidence({}, undefined, transport);
} catch (error) {
  deletionError = error;
}
assert(
  deletionError instanceof CommandActivityApiError && deletionError.code === "approval_gate_totp_required",
  "deletion errors preserve daemon approval-gate codes",
);

const secretSentinel = "SECRET_RESPONSE_SENTINEL";
responder = () => Response.json({ error: "invalid_cursor", raw_command: secretSentinel }, { status: 400 });
let requestError: unknown;
try {
  await fetchCommandActivityPage(DEFAULT_COMMAND_ACTIVITY_FILTERS, "bad-cursor", undefined, transport);
} catch (error) {
  requestError = error;
}
assert(requestError instanceof CommandActivityApiError, "HTTP failures preserve a typed API error");
assert(requestError.code === "invalid_cursor" && requestError.status === 400, "typed errors preserve status and code");
assert(!requestError.message.includes(secretSentinel), "typed errors never serialize response bodies");

responder = () => Response.json({ error: "invalid_occurred_from" }, { status: 400 });
try {
  await fetchCommandActivityPage(DEFAULT_COMMAND_ACTIVITY_FILTERS, null, undefined, transport);
} catch (error) {
  requestError = error;
}
assert(
  requestError instanceof CommandActivityApiError && requestError.code === "invalid_occurred_from",
  "list errors preserve daemon date-filter codes",
);

responder = () => Response.json({ error: "top_limit_out_of_range" }, { status: 400 });
try {
  await fetchCommandActivityAnalytics(
    { days: 7, top_limit: 10, dimension: null, dimension_value: null },
    undefined,
    transport,
  );
} catch (error) {
  requestError = error;
}
assert(
  requestError instanceof CommandActivityApiError && requestError.code === "top_limit_out_of_range",
  "analytics errors preserve daemon limit codes",
);

responder = () => Response.json({ error: secretSentinel }, { status: 400 });
try {
  await fetchCommandActivityPage(DEFAULT_COMMAND_ACTIVITY_FILTERS, null, undefined, transport);
} catch (error) {
  requestError = error;
}
assert(requestError instanceof CommandActivityApiError && requestError.code === null, "unknown error codes are discarded");
assert(!requestError.message.includes(secretSentinel), "unknown error strings never enter typed error messages");

responder = () => new Response(new Uint8Array(2_097_153), { status: 200 });
let oversizedResponseError: unknown;
try {
  await fetchCommandActivityPage(DEFAULT_COMMAND_ACTIVITY_FILTERS, null, undefined, transport);
} catch (error) {
  oversizedResponseError = error;
}
assert(
  oversizedResponseError instanceof Error && oversizedResponseError.message === "Invalid command activity JSON payload",
  "success responses are byte-bounded before JSON normalization",
);

const invalidationFrame = 'id: 9\ndata: {"event":"command_activity_invalidated","activity_id":"activity:01"}';
const parsedInvalidation = parseCommandActivitySseFrame(invalidationFrame);
assert(parsedInvalidation?.event === "command_activity_invalidated", "SSE parser accepts ID-only invalidations");
const resetFrame = 'id: 10\nevent: command_activity_reset\ndata: {"event":"command_activity_reset","reset_required":true}';
assert(parseCommandActivitySseFrame(resetFrame)?.event === "command_activity_reset", "SSE parser accepts reset events");
assert(parseCommandActivitySseFrame(`id: 11\ndata: {"event":"command_activity_invalidated","raw_command":"${secretSentinel}"}`) === null, "SSE parser rejects forbidden fields");

const streamPayload = `${invalidationFrame}\n\n${resetFrame}\n\n`;
responder = (_url, init) => {
  assert(new Headers(init?.headers).get("Last-Event-ID") === "8", "stream resumes with a numeric event header");
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(streamPayload.slice(0, 31)));
        controller.enqueue(new TextEncoder().encode(streamPayload.slice(31)));
        controller.close();
      },
    }),
    { status: 200, headers: { "Content-Type": "text/event-stream" } },
  );
};
const streamed = [];
const controller = new AbortController();
for await (const event of streamCommandActivityInvalidations(8, controller.signal, transport)) streamed.push(event);
assert(streamed.length === 2, "authenticated fetch streaming handles chunk boundaries");
const streamRequest = requests.at(-1);
assert(streamRequest !== undefined, "stream client issues a request");
assert(streamRequest.url.endsWith("/v1/command-activity/events?cursor=8"), "stream URL contains only numeric cursor state");
assert(!streamRequest.url.includes("dashboard-session"), "stream credentials never enter the URL");

const compactFrames = Array.from(
  { length: 1_200 },
  (_, index) => `id: ${index + 20}\ndata: {"event":"command_activity_invalidated","activity_id":"activity:01"}`,
).join("\n\n");
assert(compactFrames.length > 65_536, "stream fixture exceeds the per-frame bound in aggregate");
responder = () =>
  new Response(
    new ReadableStream<Uint8Array>({
      start(streamController) {
        streamController.enqueue(new TextEncoder().encode(`${compactFrames}\n\n`));
        streamController.close();
      },
    }),
    { status: 200, headers: { "Content-Type": "text/event-stream" } },
  );
let compactEventCount = 0;
for await (const _event of streamCommandActivityInvalidations(0, new AbortController().signal, transport)) {
  compactEventCount += 1;
}
assert(compactEventCount === 1_200, "one large transport chunk may contain many bounded SSE frames");
