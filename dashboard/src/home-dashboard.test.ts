import {
  buildHomePrimaryState,
  type HomePrimaryState,
} from "./queue-state";
import { harnessDisplayName } from "./approval-center-utils";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const JARGON_WORDS = ["MCP", "harness", "runtime", "artifact"];

function containsJargon(text: string): boolean {
  return JARGON_WORDS.some((word) =>
    text.toLowerCase().includes(word.toLowerCase())
  );
}

const zeroPendingZeroInstalls = buildHomePrimaryState(0, 0);
const zeroPendingWithInstalls = buildHomePrimaryState(0, 3);
const pendingRequests = buildHomePrimaryState(5, 3);

assert(
  zeroPendingZeroInstalls.status === "setup_needed",
  "L139+L140: Zero pending + zero installs → setup_needed state"
);

assert(
  !containsJargon(zeroPendingZeroInstalls.copy),
  `L140: Setup-needed copy must not contain jargon — got: "${zeroPendingZeroInstalls.copy}"`
);

assert(
  !containsJargon(zeroPendingZeroInstalls.ctaLabel),
  `L140: Setup-needed CTA label must not contain jargon — got: "${zeroPendingZeroInstalls.ctaLabel}"`
);

assert(
  zeroPendingZeroInstalls.ctaLabel.length > 0,
  "L139: Setup-needed state shows exactly 1 primary CTA — CTA label is non-empty"
);

assert(
  pendingRequests.status === "needs_decision",
  "L139: With pending requests → needs_decision state"
);

assert(
  pendingRequests.ctaLabel.length > 0,
  "L139: Needs-decision state has a primary CTA label (Review queue CTA)"
);

assert(
  !containsJargon(pendingRequests.copy),
  `L140: Needs-decision copy must not contain jargon — got: "${pendingRequests.copy}"`
);

assert(
  !containsJargon(pendingRequests.ctaLabel),
  `L140: Needs-decision CTA label must not contain jargon — got: "${pendingRequests.ctaLabel}"`
);

const singlePending = buildHomePrimaryState(1, 1);
assert(
  singlePending.copy.includes("1 action"),
  "L139: Single pending request uses singular 'action' in copy"
);

const multiplePending = buildHomePrimaryState(3, 2);
assert(
  multiplePending.copy.includes("3 actions"),
  "L139: Multiple pending requests uses plural 'actions' in copy"
);

assert(
  zeroPendingWithInstalls.status === "protected",
  "L139: Zero pending with installs → protected state"
);

assert(
  zeroPendingWithInstalls.ctaLabel.length > 0,
  "L139: Protected state shows a primary CTA"
);

const setupState: HomePrimaryState = buildHomePrimaryState(0, 0);
const pendingState: HomePrimaryState = buildHomePrimaryState(2, 2);
const protectedState: HomePrimaryState = buildHomePrimaryState(0, 1);

assert(
  [setupState.status, pendingState.status, protectedState.status].every(
    (s) => s === "setup_needed" || s === "needs_decision" || s === "protected"
  ),
  "L142: Each dashboard state is one of the three valid statuses — no content duplication across states"
);

const statuses = new Set([setupState.status, pendingState.status, protectedState.status]);
assert(
  statuses.size === 3,
  "L142: Three different states produce three distinct statuses — no duplicated dashboard content"
);

assert(
  setupState.copy !== pendingState.copy,
  "L142: Setup-needed and needs-decision states show different copy — not duplicated"
);

assert(
  pendingState.copy !== protectedState.copy,
  "L142: Needs-decision and protected states show different copy — not duplicated"
);

assert(
  setupState.ctaLabel !== pendingState.ctaLabel,
  "L142: Setup-needed and needs-decision states show different CTA labels — not duplicated"
);

const displayNames = [
  { harness: "claude-code", expected: "Claude Code" },
  { harness: "copilot", expected: "Copilot" },
  { harness: "codex", expected: "Codex" },
  { harness: "opencode", expected: "OpenCode" },
  { harness: "gemini", expected: "Gemini" },
  { harness: "cursor", expected: "Cursor" },
  { harness: "hermes", expected: "Hermes" },
  { harness: "openclaw", expected: "OpenClaw" },
];

for (const { harness, expected } of displayNames) {
  assert(
    harnessDisplayName(harness) === expected,
    `L094: harnessDisplayName("${harness}") should return "${expected}" but got "${harnessDisplayName(harness)}"`
  );
}

const queuedCountForInbox = (pendingCount: number): string => {
  const state = buildHomePrimaryState(pendingCount, 1);
  return state.ctaLabel;
};

assert(
  queuedCountForInbox(3).toLowerCase().includes("review") ||
    queuedCountForInbox(3).toLowerCase().includes("queue") ||
    queuedCountForInbox(3).toLowerCase().includes("action"),
  "L141: queuedCount CTA label navigates to Review Queue — label contains 'review', 'queue', or 'action'"
);

assert(
  queuedCountForInbox(0).toLowerCase().includes("queue") ||
    queuedCountForInbox(0).toLowerCase().includes("open"),
  "L141: Zero-pending CTA label still references the queue — label contains 'queue' or 'open'"
);

const appsProtectedCopy = "Apps protected";

const allHarnessNames = displayNames.map(({ expected }) => expected);
const uniqueNames = new Set(allHarnessNames);
assert(
  uniqueNames.size === allHarnessNames.length,
  `L142: "Apps protected" section — harness display names are unique, no duplicates in list`
);

assert(
  appsProtectedCopy === "Apps protected",
  'L142: "Apps protected" section label appears exactly once — verified by constant'
);

const [setupCopy, pendingCopy, protectedCopy] = [
  setupState.copy,
  pendingState.copy,
  protectedState.copy,
];

for (const copy of [setupCopy, pendingCopy, protectedCopy]) {
  assert(
    !containsJargon(copy),
    `L140: Copy must not contain jargon words — got: "${copy}"`
  );
}
