import { readFileSync } from "node:fs";

import {
  filterSettingsBySearch,
  securityLevelLabel,
  RISK_CONTROL_CONSEQUENCES,
} from "./apps/app-catalog";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

function testFilterSettingsBySearchReturnsMatchingItems(): void {
  const results = filterSettingsBySearch("secret");
  assert(results.length > 0, "filterSettingsBySearch('secret') should return at least one result");
  for (const item of results) {
    assert(typeof item.label === "string" && item.label.length > 0, "Each result should have a non-empty label");
    assert(typeof item.key === "string" && item.key.length > 0, "Each result should have a non-empty key");
  }
}

function testFilterSettingsBySearchEmptyQueryReturnsEmpty(): void {
  const results = filterSettingsBySearch("");
  assert(results.length === 0, "filterSettingsBySearch('') should return empty array");
}

function testFilterSettingsBySearchWhitespaceReturnsEmpty(): void {
  const results = filterSettingsBySearch("   ");
  assert(results.length === 0, "filterSettingsBySearch('   ') should return empty array");
}

function testFilterSettingsBySearchCaseInsensitive(): void {
  const lowerResults = filterSettingsBySearch("network");
  const upperResults = filterSettingsBySearch("NETWORK");
  assert(lowerResults.length === upperResults.length, "Search should be case-insensitive");
}

function testSecurityLevelLabelRelaxed(): void {
  assert(securityLevelLabel("relaxed") === "Relaxed", `Expected 'Relaxed', got '${securityLevelLabel("relaxed")}'`);
}

function testSecurityLevelLabelBalanced(): void {
  assert(securityLevelLabel("balanced") === "Balanced", `Expected 'Balanced', got '${securityLevelLabel("balanced")}'`);
}

function testSecurityLevelLabelStrict(): void {
  assert(securityLevelLabel("strict") === "Strict", `Expected 'Strict', got '${securityLevelLabel("strict")}'`);
}

function testSecurityLevelLabelCustom(): void {
  assert(securityLevelLabel("custom") === "Custom", `Expected 'Custom', got '${securityLevelLabel("custom")}'`);
}

function testRiskControlConsequencesHasAllKeys(): void {
  const requiredKeys = [
    "local_secret_read",
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "network_egress",
    "prompt_injection",
    "mcp_dangerous_tool",
    "malicious_skill",
    "package_script",
    "persistence",
    "guard_bypass",
    "cloud_advisory",
    "encoded_exfiltration",
    "package_unknown",
    "package_lockfile_drift",
    "package_direct_source",
    "package_custom_registry",
    "package_install",
    "low_trust_artifact",
    "runtime_known_vulnerable",
  ];
  for (const key of requiredKeys) {
    const entry = RISK_CONTROL_CONSEQUENCES[key];
    assert(entry !== undefined, `RISK_CONTROL_CONSEQUENCES missing key: ${key}`);
    assert(typeof entry.example === "string" && entry.example.length > 0, `entry.example should be non-empty for: ${key}`);
    assert(typeof entry.impact === "string" && entry.impact.length > 0, `entry.impact should be non-empty for: ${key}`);
  }
}

function testResponsiveLayoutContract(): void {
  const settingsShellSource = readFileSync(
    new URL("./settings/settings-section-shell.tsx", import.meta.url),
    "utf8",
  );
  const shellNavigationCss = readFileSync(
    new URL("./shell-navigation.css", import.meta.url),
    "utf8",
  );
  const responsiveCss = readFileSync(
    new URL("./responsive-layout.css", import.meta.url),
    "utf8",
  );
  const mainSource = readFileSync(new URL("./main.tsx", import.meta.url), "utf8");

  assert(
    settingsShellSource.includes("guard-settings-shell"),
    "Settings shell should expose a container-query root",
  );
  assert(
    settingsShellSource.includes("guard-settings-side-nav")
      && settingsShellSource.includes("guard-settings-mobile-tabs"),
    "Settings shell should expose both responsive navigation surfaces",
  );
  assert(
    responsiveCss.includes("container: guard-settings / inline-size"),
    "Responsive CSS should evaluate Settings using available workspace width",
  );
  assert(
    responsiveCss.includes("minmax(min(100%, 15.5rem), 1fr)"),
    "Protection cards should preserve a readable minimum width",
  );
  assert(
    shellNavigationCss.includes("@media (min-width: 48rem)")
      && shellNavigationCss.includes("padding-left: var(--guard-shell-rail-width)")
      && shellNavigationCss.includes("@media (min-width: 80rem)"),
    "Intermediate desktop widths should use a persistent compact rail before the expanded sidebar",
  );
  assert(
    responsiveCss.includes('[aria-label="Save settings"]'),
    "Short or narrow windows should keep the save bar from covering form content",
  );
  assert(
    mainSource.includes('import "./shell-navigation.css"')
      && mainSource.includes('import "./responsive-layout.css"'),
    "The shell and workspace responsive stylesheets should be included in the dashboard bundle",
  );
}

testFilterSettingsBySearchReturnsMatchingItems();
testFilterSettingsBySearchEmptyQueryReturnsEmpty();
testFilterSettingsBySearchWhitespaceReturnsEmpty();
testFilterSettingsBySearchCaseInsensitive();
testSecurityLevelLabelRelaxed();
testSecurityLevelLabelBalanced();
testSecurityLevelLabelStrict();
testSecurityLevelLabelCustom();
testRiskControlConsequencesHasAllKeys();
testResponsiveLayoutContract();

console.log("settings-workspace-phase11.test.ts: all tests passed");
