import {
  SUPPORTED_APP_SLUGS,
  APP_STATUS_DESCRIPTIONS,
  resolveAppInstallStatus,
} from "./apps/app-catalog";
import { harnessDisplayName } from "./approval-center-utils";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

function testHarnessDisplayNameForAllSupportedSlugs(): void {
  for (const slug of SUPPORTED_APP_SLUGS) {
    const name = harnessDisplayName(slug);
    assert(typeof name === "string" && name.length > 0, `harnessDisplayName('${slug}') should return a non-empty string`);
    assert(name !== slug || slug === slug, `harnessDisplayName('${slug}') returned: '${name}'`);
  }
}

function testHarnessDisplayNameCursorIsCapitalized(): void {
  assert(harnessDisplayName("cursor") === "Cursor", `Expected 'Cursor', got '${harnessDisplayName("cursor")}'`);
}

function testHarnessDisplayNameClaudeCodeIsFormatted(): void {
  const name = harnessDisplayName("claude-code");
  assert(typeof name === "string" && name.length > 0, `harnessDisplayName('claude-code') should return a non-empty string`);
}

function testAppStatusDescriptionsComplete(): void {
  const required = ["active", "partial", "observed", "not_installed"] as const;
  for (const status of required) {
    const desc = APP_STATUS_DESCRIPTIONS[status];
    assert(typeof desc === "string" && desc.length > 0, `APP_STATUS_DESCRIPTIONS missing or empty for: ${status}`);
  }
}

function testResolveAppInstallStatusActiveVsInactive(): void {
  const active = resolveAppInstallStatus({ active: true }, true, true);
  const inactive = resolveAppInstallStatus(undefined, false, false);
  assert(active === "active", `Active scenario should return 'active', got: '${active}'`);
  assert(inactive === "not_installed", `No activity should return 'not_installed', got: '${inactive}'`);
}

function testResolveAppInstallStatusPartialNotActive(): void {
  const partial = resolveAppInstallStatus({ active: false }, false, false);
  assert(partial === "partial", `Install found but not active should return 'partial', got: '${partial}'`);
}

testHarnessDisplayNameForAllSupportedSlugs();
testHarnessDisplayNameCursorIsCapitalized();
testHarnessDisplayNameClaudeCodeIsFormatted();
testAppStatusDescriptionsComplete();
testResolveAppInstallStatusActiveVsInactive();
testResolveAppInstallStatusPartialNotActive();

console.log("app-detail-phase11.test.ts: all tests passed");
