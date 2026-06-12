import {
  SUPPORTED_APP_SLUGS,
  SUPPORTED_APPS_BRIEF,
  resolveAppInstallStatus,
  APP_STATUS_LABELS,
} from "./apps/app-catalog";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

function testSupportedAppSlugs(): void {
  const expected = ["codex", "claude-code", "opencode", "copilot", "cursor", "gemini", "hermes", "openclaw", "kimi", "grok"];
  for (const slug of expected) {
    assert(SUPPORTED_APP_SLUGS.includes(slug as typeof SUPPORTED_APP_SLUGS[number]), `SUPPORTED_APP_SLUGS missing: ${slug}`);
  }
  assert(SUPPORTED_APP_SLUGS.length === 10, `Expected 10 slugs, got ${SUPPORTED_APP_SLUGS.length}`);
}

function testSupportedAppsBriefMentionsAllApps(): void {
  const brief = SUPPORTED_APPS_BRIEF.toLowerCase();
  assert(brief.includes("codex"), "SUPPORTED_APPS_BRIEF should mention Codex");
  assert(brief.includes("copilot"), "SUPPORTED_APPS_BRIEF should mention Copilot");
  assert(brief.includes("cursor"), "SUPPORTED_APPS_BRIEF should mention Cursor");
  assert(SUPPORTED_APPS_BRIEF.length > 20, "SUPPORTED_APPS_BRIEF should be a non-trivial string");
}

function testResolveAppInstallStatusActive(): void {
  const result = resolveAppInstallStatus({ active: true }, true, true);
  assert(result === "active", `Expected 'active', got '${result}'`);
}

function testResolveAppInstallStatusNotInstalled(): void {
  const result = resolveAppInstallStatus(undefined, false, false);
  assert(result === "not_installed", `Expected 'not_installed', got '${result}'`);
}

function testResolveAppInstallStatusObserved(): void {
  const result = resolveAppInstallStatus(undefined, true, false);
  assert(result === "observed", `Expected 'observed', got '${result}'`);
}

function testResolveAppInstallStatusPartial(): void {
  const result = resolveAppInstallStatus({ active: false }, false, false);
  assert(result === "partial", `Expected 'partial', got '${result}'`);
}

function testAppStatusLabelsComplete(): void {
  const required = ["active", "partial", "observed", "not_installed"] as const;
  for (const status of required) {
    const label = APP_STATUS_LABELS[status];
    assert(typeof label === "string" && label.length > 0, `APP_STATUS_LABELS missing or empty for: ${status}`);
  }
}

testSupportedAppSlugs();
testSupportedAppsBriefMentionsAllApps();
testResolveAppInstallStatusActive();
testResolveAppInstallStatusNotInstalled();
testResolveAppInstallStatusObserved();
testResolveAppInstallStatusPartial();
testAppStatusLabelsComplete();

console.log("fleet-workspace-phase11.test.ts: all tests passed");
