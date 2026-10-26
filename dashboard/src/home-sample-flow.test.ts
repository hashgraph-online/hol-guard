import {
  decisionOutcome,
  INITIAL_SESSION_STATE,
  rowStatus,
  SAMPLE_SESSION,
  sampleAppName,
  sessionCounts,
  sessionPhase,
  sessionReducer,
  sessionStatusLine,
  type SessionEvent,
  type SessionState,
} from "./home-sample-flow";
import { HOW_GUARD_WORKS_OUTCOMES, resolveHowGuardWorksDefaultOpen } from "./home-how-guard-works";
import { buildSetupAppsCopy, resolveSetupApps } from "./home-setup-card";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const JARGON_WORDS = ["MCP", "harness", "runtime", "artifact"];
function containsJargon(text: string): boolean {
  return JARGON_WORDS.some((word) => text.toLowerCase().includes(word.toLowerCase()));
}

function run(state: SessionState, events: SessionEvent[]): SessionState {
  return events.reduce((current, event) => sessionReducer(current, event), state);
}

function tickUntilSettled(state: SessionState): SessionState {
  let current = state;
  for (let guard = 0; guard < 100; guard += 1) {
    const phase = sessionPhase(current);
    if (phase === "waiting" || phase === "finished") return current;
    current = sessionReducer(current, { type: "tick" });
  }
  throw new Error("session never settled");
}

const askIndex = SAMPLE_SESSION.findIndex((row) => row.verdict === "ask");
const stopIndex = SAMPLE_SESSION.findIndex((row) => row.verdict === "stopped");

// --- the script shows all three outcomes, with the harmful action before the question
assert(SAMPLE_SESSION.filter((row) => row.verdict === "ask").length === 1, "the sample asks exactly once");
assert(stopIndex >= 0 && stopIndex < askIndex, "something harmful is stopped before Guard asks");
assert(SAMPLE_SESSION.filter((row) => row.verdict === "ran").length > SAMPLE_SESSION.length / 2, "most actions run without asking");
assert(askIndex < SAMPLE_SESSION.length - 1, "work carries on after the question");

// --- playback: each tick reveals a row being checked, the next tick resolves it
assert(sessionPhase(INITIAL_SESSION_STATE) === "ready", "starts ready");
const first = sessionReducer(INITIAL_SESSION_STATE, { type: "tick" });
assert(first.shown === 1 && first.checking && rowStatus(first, 0) === "checking", "first tick shows a row being checked");
assert(sessionCounts(first).checked === 0, "a row being checked is not counted yet");
const firstDone = sessionReducer(first, { type: "tick" });
assert(!firstDone.checking && rowStatus(firstDone, 0) === "ran", "second tick resolves the row");

// --- the session pauses on the question and ignores ticks until the person answers
const waiting = tickUntilSettled(INITIAL_SESSION_STATE);
assert(sessionPhase(waiting) === "waiting" && waiting.shown === askIndex + 1, "pauses on the question");
assert(sessionReducer(waiting, { type: "tick" }) === waiting, "ticks do nothing while waiting");
assert(rowStatus(waiting, askIndex) === "waiting" && rowStatus(waiting, stopIndex) === "stopped", "row statuses follow the script");
assert(sessionStatusLine(waiting).includes("waiting for you"), "status line says Guard is waiting");
const waitingCounts = sessionCounts(waiting);
assert(waitingCounts.stopped === 1 && waitingCounts.asked === 1 && waitingCounts.ran === askIndex - 1, "counts match what is on screen");

// --- every review offers Allow once, Always allow and Block, and each one lets the session finish
for (const decision of ["once", "always", "block"] as const) {
  const decided = sessionReducer(waiting, { type: "decide", decision });
  assert(rowStatus(decided, askIndex) === decision, `${decision} is shown on the row`);
  const finished = tickUntilSettled(decided);
  assert(sessionPhase(finished) === "finished" && finished.shown === SAMPLE_SESSION.length, `${decision} lets the session finish`);
  assert(sessionStatusLine(finished).includes("asked once"), "the finished line says you were asked once");
  assert(!containsJargon(decisionOutcome(decision)), `${decision} outcome avoids jargon`);
}
assert(decisionOutcome("always").includes("changes"), "Always allow explains Guard checks again if the package changes");
assert(sessionReducer(INITIAL_SESSION_STATE, { type: "decide", decision: "once" }) === INITIAL_SESSION_STATE, "deciding before the question does nothing");

// --- replay starts the session over and counts as a new run
const finished = tickUntilSettled(sessionReducer(waiting, { type: "decide", decision: "once" }));
const replayed = sessionReducer(finished, { type: "replay" });
assert(replayed.shown === 0 && replayed.decision === null && sessionPhase(replayed) === "playing", "replay clears the session");
assert(sessionReducer(replayed, { type: "tick" }).runs === finished.runs + 1, "replay counts as a new run so rows re-animate");

// --- reduced motion jumps to the question, then to the end
const skipped = sessionReducer(INITIAL_SESSION_STATE, { type: "skip" });
assert(sessionPhase(skipped) === "waiting" && skipped.shown === askIndex + 1, "skip stops at the question");
const skippedDone = run(skipped, [{ type: "decide", decision: "block" }, { type: "skip" }]);
assert(sessionPhase(skippedDone) === "finished", "skip after answering shows the rest");

// --- copy
for (const row of SAMPLE_SESSION) {
  assert(!containsJargon(`${row.label} ${row.reason ?? ""}`), `row copy avoids jargon: ${row.id}`);
}
for (const outcome of HOW_GUARD_WORKS_OUTCOMES) {
  assert(!containsJargon(`${outcome.title} ${outcome.body}`), `outcome copy avoids jargon: ${outcome.key}`);
}
assert(sampleAppName([]) === "Claude Code", "defaults to a familiar app name");
assert(sampleAppName(["codex"]) === "Codex", "names the sample after a connected app");

// --- how-it-works defaults
// --- how-it-works defaults
assert(resolveHowGuardWorksDefaultOpen(0) && resolveHowGuardWorksDefaultOpen(19) && !resolveHowGuardWorksDefaultOpen(20), "walkthrough opens for new installs only");

// --- first-run setup card lists what Guard actually knows about
const setupApps = resolveSetupApps(
  [
    { harness: "cursor", active: false, workspace: null, manifest: {}, updated_at: "2026-10-17T00:00:00Z" },
    { harness: "codex", active: true, workspace: null, manifest: {}, updated_at: "2026-10-17T00:00:00Z" },
  ],
  ["claude-code", "cursor", "*"]
);
assert(setupApps.length === 2, `active installs and non-displayable names are skipped — got ${setupApps.length}`);
assert(setupApps[0].name === "Claude Code" && setupApps[0].state === "found", "observed apps are marked found");
assert(setupApps[1].name === "Cursor" && setupApps[1].state === "partial", "inactive managed installs are marked partial");
assert(!containsJargon(buildSetupAppsCopy(setupApps)) && !containsJargon(buildSetupAppsCopy([])), "setup copy avoids jargon");
assert(buildSetupAppsCopy([]).includes("Protect"), "empty state points people to Protect to connect an app");

console.log("home-sample-flow tests passed");
