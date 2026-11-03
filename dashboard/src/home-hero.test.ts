import { buildHeroFacts, buildHeroLiveLabel, buildHeroQueuePreview, buildHomeHeroModel, describeQueueItem, HERO_BADGE_LABELS, heroMoodForStatus, heroToneForStatus, redactQueueArtifactName } from "./home-hero";
import { brandMarkKindAt, BRAND_MARK, brandMarkSvg, sampleBrandMarkParticles } from "./brand-mark-geometry";
import type { GuardApprovalRequest, GuardReceipt } from "./guard-types";
import { formatRelativeTime } from "./approval-center-utils";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const JARGON_WORDS = ["MCP", "harness", "runtime", "artifact"];
function containsJargon(text: string): boolean {
  return JARGON_WORDS.some((word) => text.toLowerCase().includes(word.toLowerCase()));
}

function makeRequest(overrides: Partial<GuardApprovalRequest>): GuardApprovalRequest {
  return {
    request_id: "req-1",
    harness: "claude-code",
    artifact_id: "art-1",
    artifact_name: "left-pad@9.9.9",
    artifact_type: "tool_action_request",
    artifact_hash: "abc",
    publisher: null,
    policy_action: "review",
    recommended_scope: "once",
    changed_fields: ["first_seen"],
    source_scope: "project",
    config_path: "/Users/someone/.claude/settings.json",
    transport: null,
    review_command: "hol-guard approvals",
    approval_url: "http://127.0.0.1:4781/requests/req-1",
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: new Date(Date.now() - 4 * 60_000).toISOString(),
    ...overrides,
  } as GuardApprovalRequest;
}

function makeReceipt(minutesAgo: number, decision: GuardReceipt["policy_decision"] = "allow"): GuardReceipt {
  return {
    receipt_id: `r-${minutesAgo}`,
    harness: "codex",
    artifact_id: "a",
    artifact_hash: "h",
    policy_decision: decision,
    capabilities_summary: "",
    changed_capabilities: [],
    provenance_summary: "",
    user_override: null,
    source_scope: null,
    timestamp: new Date(Date.now() - minutesAgo * 60_000).toISOString(),
  };
}

// --- queue preview keeps local paths off the Home screen
assert(redactQueueArtifactName("left-pad@9.9.9") === "left-pad@9.9.9", "plain package names are shown");
assert(redactQueueArtifactName("/Users/me/.env") === null, "paths are never shown on Home");
assert(redactQueueArtifactName("~/secrets") === null, "home-relative paths are never shown on Home");
assert(redactQueueArtifactName("C:\\tools\\thing") === null, "windows paths are never shown on Home");
assert(redactQueueArtifactName("x".repeat(60)) === null, "overlong names are dropped");

const packageItem = makeRequest({
  action_envelope_json: { action_type: "package_script", package_name: "left-pad" } as GuardApprovalRequest["action_envelope_json"],
});
assert(describeQueueItem(packageItem) === "wants to run a package script · left-pad@9.9.9", `package request reads in plain language — got ${describeQueueItem(packageItem)}`);

const fileItem = makeRequest({
  artifact_name: "/Users/me/project/.env",
  artifact_type: "file_read_request",
  action_envelope_json: { action_type: "file_read", target_paths: ["/Users/me/project/.env"] } as GuardApprovalRequest["action_envelope_json"],
});
assert(describeQueueItem(fileItem) === "wants to read a file", "file reads never leak the path on Home");

const serverItem = makeRequest({ artifact_type: "mcp_server", artifact_name: "weather-tools" });
const settingItem = makeRequest({ action_envelope_json: { action_type: "config_change" } as GuardApprovalRequest["action_envelope_json"] });
assert(describeQueueItem(settingItem) === "wants to change a setting", "config changes read in plain language");
assert(describeQueueItem(serverItem) === "wants to start a new tool · weather-tools", "new servers are described as tools");

for (const item of [packageItem, fileItem, serverItem, makeRequest({ artifact_type: "hook" }), makeRequest({ artifact_type: "extension" }), makeRequest({ artifact_type: "something_else" })]) {
  assert(!containsJargon(describeQueueItem(item)), `queue description avoids jargon — got "${describeQueueItem(item)}"`);
}

const preview = buildHeroQueuePreview([packageItem, fileItem, serverItem, makeRequest({ request_id: "req-4" })]);
assert(preview.length === 3, "hero preview shows at most three paused actions");
assert(preview[0].app === "Claude Code" && preview[0].requestId === "req-1", "preview rows carry the app name and request id");
assert(preview[0].when.endsWith("ago"), "preview rows show relative time");

// --- hero facts come from real counts
const setupFacts = buildHeroFacts({ status: "setup_gap", watchedAppsCount: 0, queuedCount: 0, latestReceipts: [], analytics: null, oldestQueuedAt: null });
assert(setupFacts.length === 3 && !containsJargon(setupFacts.join(" ")), "first-run facts are plain trust statements");

const now = new Date();
const todayKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
const clearFacts = buildHeroFacts({
  status: "clear",
  watchedAppsCount: 3,
  queuedCount: 0,
  latestReceipts: [makeReceipt(12), makeReceipt(80)],
  analytics: {
    total: 100, allowed: 90, blocked: 10, reviewed: 0, first_activity_at: null, last_activity_at: null, active_day_streak: 3, peak_day_total: 40,
    daily_activity: [{ date_key: todayKey, total: 43 }], trend_buckets: [], by_harness: [], top_artifacts: [], loaded_sample_limit: 100,
  },
  oldestQueuedAt: null,
});
assert(clearFacts[0] === "3 apps protected", `app count fact — got ${clearFacts[0]}`);
assert(clearFacts[1] === "43 actions checked today", `today count prefers analytics — got ${clearFacts[1]}`);
assert(clearFacts[2].startsWith("Last decision "), `last decision fact — got ${clearFacts[2]}`);

// Receipts stamped "now" always fall on today, so this holds just after local midnight too.
const fallbackFacts = buildHeroFacts({ status: "clear", watchedAppsCount: 1, queuedCount: 0, latestReceipts: [makeReceipt(0), makeReceipt(0)], analytics: null, oldestQueuedAt: null });
assert(fallbackFacts.includes("2 actions checked today"), "today count falls back to latest receipts when analytics are not loaded");
assert(fallbackFacts[0] === "1 app protected", "singular app count");

const reviewFacts = buildHeroFacts({ status: "needs_review", watchedAppsCount: 2, queuedCount: 2, latestReceipts: [], analytics: null, oldestQueuedAt: packageItem.created_at });
assert(reviewFacts.some((fact) => fact.startsWith("Paused ")), "review facts say when the oldest action was paused");
assert(!containsJargon(reviewFacts.join(" ")), "review facts avoid jargon");

for (const status of ["degraded", "partial"] as const) {
  const facts = buildHeroFacts({ status, watchedAppsCount: 2, queuedCount: 0, latestReceipts: [], analytics: null, oldestQueuedAt: null });
  assert(facts[0] === "2 apps connected" && !facts.some((fact) => fact.includes("protected")), `${status} facts do not claim the apps are protected — got ${facts[0]}`);
}

// --- live caption and mood
assert(buildHeroLiveLabel("clear", 3, 0) === "Watching 3 apps", "clear caption");
assert(buildHeroLiveLabel("clear", 1, 0) === "Watching 1 app", "clear caption singular");
assert(buildHeroLiveLabel("needs_review", 3, 1) === "1 paused", "review caption singular");
assert(buildHeroLiveLabel("needs_review", 3, 2) === "2 paused", "review caption");
assert(buildHeroLiveLabel("setup_gap", 0, 0) === "Ready", "setup caption");
assert(buildHeroLiveLabel("checking", 2, 0) === "Checking" && buildHeroLiveLabel("degraded", 2, 0) === "Needs repair" && buildHeroLiveLabel("partial", 2, 0) === "Partly protected", "protection-health captions");
assert(heroToneForStatus("degraded") === "review" && heroToneForStatus("partial") === "setup" && heroToneForStatus("checking") === "setup", "degraded shares the review tint; partial and checking share the setup tint");
assert(HERO_BADGE_LABELS.partial === "Partially protected" && HERO_BADGE_LABELS.degraded === "Degraded" && HERO_BADGE_LABELS.checking === "Checking", "chip labels match GuardHero for the protection-health states");
assert(buildHeroFacts({ status: "checking", watchedAppsCount: 2, queuedCount: 0, latestReceipts: [makeReceipt(1)], analytics: null, oldestQueuedAt: null }).length === 0, "no facts while protection is still being checked");
const model = buildHomeHeroModel({ status: "needs_review", watchedAppsCount: 2, queuedCount: 2, queuedItems: [packageItem, fileItem], latestReceipts: [], analytics: null });
const olderItem = { ...fileItem, request_id: "req-older", created_at: new Date(Date.now() - 90 * 60_000).toISOString() };
const reordered = buildHomeHeroModel({ status: "needs_review", watchedAppsCount: 2, queuedCount: 3, queuedItems: [packageItem, olderItem, fileItem], latestReceipts: [], analytics: null });
assert(reordered.facts.includes(`Paused ${formatRelativeTime(olderItem.created_at)}`), `paused age uses the earliest created_at, not the last row — got ${reordered.facts.join(" | ")}`);
assert(model.queue.length === 2 && model.liveLabel === "2 paused" && model.facts.some((fact) => fact.startsWith("Paused ")), "hero model bundles queue, caption and facts");
assert(HERO_BADGE_LABELS.clear === "Protected" && HERO_BADGE_LABELS.needs_review === "Needs your choice" && HERO_BADGE_LABELS.setup_gap === "Setup needed", "status chip labels match the existing hero");
assert(heroMoodForStatus("needs_review") === "review" && heroMoodForStatus("setup_gap") === "setup" && heroMoodForStatus("clear") === "clear", "mood maps from status");

// --- brand mark geometry is the full lattice
assert(BRAND_MARK.discs.length === 13, "mark has 13 nodes");
const barsByKind = BRAND_MARK.bars.reduce<Record<string, number>>((acc, bar) => ({ ...acc, [bar.kind]: (acc[bar.kind] ?? 0) + 1 }), {});
assert(barsByKind.ring === 6 && barsByKind.inner === 6 && barsByKind.spoke === 6, `mark has a full outer ring, inner ring and spokes — got ${JSON.stringify(barsByKind)}`);
assert(barsByKind.radial >= 3 && barsByKind.radial <= 6, "radial bars too short to draw (the lower ones in the real mark) are skipped");
assert(brandMarkKindAt(BRAND_MARK, 0, -0.009) === 3, "centre point is the core");
assert(brandMarkKindAt(BRAND_MARK, 0, 1) === 1, "top vertex is an outer node");
assert(brandMarkKindAt(BRAND_MARK, 0.433, 0.75) === 0, "outer ring edge midpoint is a bar");
assert(brandMarkKindAt(BRAND_MARK, 0.3, 0.3) === -1, "open space is outside the mark");
let seed = 1;
const particles = sampleBrandMarkParticles(BRAND_MARK, 0.05, () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; });
assert(particles.count > 300 && particles.count === particles.kinds.length && particles.home.length === particles.count * 2, "sampling fills the mark");
assert(brandMarkSvg("#3f4174").includes("<circle") && brandMarkSvg("#3f4174").includes('class="bm-node-core"'), "svg fallback carries part classes");

console.log("home-hero tests passed");
