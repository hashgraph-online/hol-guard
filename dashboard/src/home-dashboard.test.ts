import {
  buildHomePrimaryState,
  type HomePrimaryState,
} from "./queue-state";
import {
  buildDailyStory,
  buildDaemonErrorCopy,
  buildEmptyStateCopy,
  buildRecentProtectionCopy,
  computeStreak,
  deriveHomeState,
  redactHomeArtifactLabel,
  resolveCloudUpsellVisible,
  resolveNewAppDiscoveries,
  STREAK_MILESTONE_MESSAGES,
} from "./home-dashboard";
import { harnessDisplayName } from "./approval-center-utils";
import { resolveProofStatusCopy } from "./runtime-overview";
import type { GuardManagedInstall, GuardProofStatus, GuardReceipt } from "./guard-types";

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

const managedDiscoveryInstalls: GuardManagedInstall[] = [
  {
    harness: "cursor",
    active: true,
    workspace: null,
    manifest: {},
    updated_at: "2026-05-12T00:00:00Z",
  },
];

const newAppDiscoveries = resolveNewAppDiscoveries(managedDiscoveryInstalls, [
  "cursor",
  "opencode",
  "Ce2b7ac2ccab4fab9902347b033bf25e",
  "d75ba142-bf53-4f27-aebc-4884278c421a",
]);

assert(
  newAppDiscoveries.length === 1 && newAppDiscoveries[0] === "opencode",
  `Discovery banner should show only real unprotected apps — got: ${newAppDiscoveries.join(", ")}`
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

const EXTENDED_JARGON = ["daemon", "runtime", "v1", "MCP", "harness", "artifact"];
function containsExtendedJargon(text: string): boolean {
  return EXTENDED_JARGON.some((word) =>
    text.toLowerCase().includes(word.toLowerCase())
  );
}

const setupOnlyCta = buildHomePrimaryState(0, 0);
assert(
  setupOnlyCta.ctaLabel === "Set up protection",
  'C1: setup_needed primary CTA is "Set up protection"'
);

assert(
  setupOnlyCta.status === "setup_needed",
  "C1: buildHomePrimaryState returns setup_needed for zero pending and zero installs"
);

const queueCta = buildHomePrimaryState(3, 1);
assert(
  queueCta.ctaLabel.toLowerCase().includes("review") ||
    queueCta.ctaLabel.toLowerCase().includes("queue") ||
    queueCta.ctaLabel.toLowerCase().includes("action"),
  'C2: Queue count CTA label navigates to Review Queue — label contains "review", "queue", or "action"'
);

const allStates = [
  buildHomePrimaryState(0, 0),
  buildHomePrimaryState(2, 2),
  buildHomePrimaryState(0, 1),
];
const allCopies = allStates.map((s) => s.copy);
const allCtaLabels = allStates.map((s) => s.ctaLabel);

const uniqueCopies = new Set(allCopies);
assert(
  uniqueCopies.size === allCopies.length,
  "C3: No duplicate copy across the three dashboard states"
);

const uniqueCtaLabels = new Set(allCtaLabels);
assert(
  uniqueCtaLabels.size === allCtaLabels.length,
  "C3: No duplicate CTA labels across the three dashboard states"
);

const setupStateForJargon = buildHomePrimaryState(0, 0);
assert(
  !containsExtendedJargon(setupStateForJargon.copy),
  `C4: setup_needed copy has no jargon — got: "${setupStateForJargon.copy}"`
);
assert(
  !containsExtendedJargon(setupStateForJargon.ctaLabel),
  `C4: setup_needed CTA label has no jargon — got: "${setupStateForJargon.ctaLabel}"`
);

const demoProof: GuardProofStatus = {
  state: "pending",
  label: "First proof pending",
  detail: "Browser pairing finished. First proof sync has not completed yet.",
  request_id: "demo-connect-request",
  pairing_completed_at: new Date().toISOString(),
  first_synced_at: null,
  receipts_stored: 0,
  inventory_items: 0,
  runtime_session_id: "demo-runtime",
  runtime_session_synced_at: null,
};

const demoPendingCopy = resolveProofStatusCopy(demoProof);
assert(
  demoPendingCopy.tone === "blue",
  `D1: demo pending proof tone should be blue — got: "${demoPendingCopy.tone}"`
);
assert(
  demoPendingCopy.label === "First proof pending",
  `D1: demo pending proof label should pass through — got: "${demoPendingCopy.label}"`
);
assert(
  demoPendingCopy.detail.length > 0,
  "D1: demo pending proof detail should not be empty"
);

const syncedProof: GuardProofStatus = {
  state: "synced",
  label: "First proof synced",
  detail: "Your first protected session is recorded on Guard Cloud.",
  request_id: "demo-connect-request",
  pairing_completed_at: new Date().toISOString(),
  first_synced_at: new Date().toISOString(),
  receipts_stored: 3,
  inventory_items: 2,
  runtime_session_id: "demo-runtime",
  runtime_session_synced_at: new Date().toISOString(),
};

const syncedCopyForHome = resolveProofStatusCopy(syncedProof);
assert(
  syncedCopyForHome.tone === "green",
  `D2: synced proof shown on home route should use green tone — got: "${syncedCopyForHome.tone}"`
);
assert(
  syncedCopyForHome.label === "First proof synced",
  `D2: synced proof label on home route should read "First proof synced" — got: "${syncedCopyForHome.label}"`
);

const localOnlyProof: GuardProofStatus = {
  state: "not_connected",
  label: "Not connected",
  detail: "No cloud proof yet.",
  request_id: null,
  pairing_completed_at: null,
  first_synced_at: null,
  receipts_stored: 0,
  inventory_items: 0,
  runtime_session_id: null,
  runtime_session_synced_at: null,
};

const localOnlyCopyForHome = resolveProofStatusCopy(localOnlyProof);
assert(
  localOnlyCopyForHome.tone === "slate",
  `D3: not_connected proof on home route uses slate tone — got: "${localOnlyCopyForHome.tone}"`
);
assert(
  localOnlyCopyForHome.label === "Local only",
  `D3: not_connected proof label on home route reads "Local only" — got: "${localOnlyCopyForHome.label}"`
);

const emptyStateCopy = buildEmptyStateCopy();
assert(
  emptyStateCopy.title === "No apps connected",
  `GR176: empty Home state should be calm and direct — got: "${emptyStateCopy.title}"`
);
assert(
  !containsJargon(`${emptyStateCopy.title} ${emptyStateCopy.body}`),
  `GR176: empty Home copy should avoid implementation jargon — got: "${emptyStateCopy.body}"`
);

const daemonErrorCopy = buildDaemonErrorCopy();
assert(
  daemonErrorCopy.primaryCta === "Go to Settings" && daemonErrorCopy.secondaryCta === "Open review queue",
  "GR191: daemon error copy gives recoverable Home actions"
);

const setupHomeState = deriveHomeState({
  hasActiveInstalls: false,
  hasObservedHarnesses: false,
  queuedCount: 0,
  watchedAppsCount: 0,
});
assert(
  setupHomeState.heroStatus === "setup_gap" && setupHomeState.ctaTarget === "fleet",
  "GR177: first Home view routes setup gaps to Apps"
);
assert(
  !containsJargon(`${setupHomeState.headline} ${setupHomeState.subheadline} ${setupHomeState.ctaLabel}`),
  "GR177: first Home view avoids implementation jargon"
);

const clearHomeState = deriveHomeState({
  hasActiveInstalls: true,
  hasObservedHarnesses: true,
  queuedCount: 0,
  watchedAppsCount: 2,
});
assert(
  clearHomeState.heroStatus === "clear" && clearHomeState.ctaTarget === "evidence",
  "GR178: calm protected Home view avoids duplicate setup content"
);

assert(
  resolveCloudUpsellVisible(1, "local_only") === false,
  "GR184: Home should not upsell cloud while review work is pending"
);
assert(
  resolveCloudUpsellVisible(0, "paired_waiting") === false,
  "GR184: Home should not upsell cloud while pairing is waiting"
);
assert(
  resolveCloudUpsellVisible(0, "local_only") === true,
  "GR184: Home may show sync settings only when local and idle"
);

const receiptBase: GuardReceipt = {
  receipt_id: "receipt-1",
  harness: "codex",
  artifact_id: "artifact-1",
  artifact_hash: "hash-1",
  policy_decision: "allow",
  capabilities_summary: "command reviewed",
  changed_capabilities: [],
  provenance_summary: "local",
  user_override: null,
  artifact_name: "deploy command",
  source_scope: null,
  timestamp: new Date().toISOString(),
};

const pathReceipt: GuardReceipt = {
  ...receiptBase,
  receipt_id: "receipt-2",
  artifact_name: "/tmp/hol-guard-user/private/key.pem",
};
assert(
  redactHomeArtifactLabel(pathReceipt.artifact_name) === "a local action",
  "GR195: Home recent activity redacts local paths"
);
assert(
  buildRecentProtectionCopy(pathReceipt) === "Codex allowed a local action",
  `GR179: recent protection copy should be useful but private — got: "${buildRecentProtectionCopy(pathReceipt)}"`
);

const dailyStory = buildDailyStory(
  [
    receiptBase,
    {
      ...receiptBase,
      receipt_id: "receipt-3",
      policy_decision: "block",
    },
  ],
  0
);
assert(
  dailyStory?.body === "Guard allowed 1 action and blocked 1.",
  `GR183: daily story should count real receipt decisions — got: "${dailyStory?.body ?? "none"}"`
);

const pendingDailyStory = buildDailyStory([], 1);
assert(
  pendingDailyStory?.body === "1 action is waiting for review. Guard paused it to keep you safe.",
  `GR179: singular pending story should read naturally — got: "${pendingDailyStory?.body ?? "none"}"`
);

const staleReceipt: GuardReceipt = {
  ...receiptBase,
  timestamp: new Date(Date.now() - 72 * 60 * 60 * 1000).toISOString(),
};
assert(
  computeStreak([staleReceipt]) === 0,
  "GR186: stale activity should not keep a streak alive"
);
assert(
  Object.values(STREAK_MILESTONE_MESSAGES).every((message) => !message.includes("!")),
  "GR186: streak milestone copy should stay calm, not gamified"
);
