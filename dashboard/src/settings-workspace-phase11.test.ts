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
  ];
  for (const key of requiredKeys) {
    const entry = RISK_CONTROL_CONSEQUENCES[key];
    assert(entry !== undefined, `RISK_CONTROL_CONSEQUENCES missing key: ${key}`);
    assert(typeof entry.example === "string" && entry.example.length > 0, `entry.example should be non-empty for: ${key}`);
    assert(typeof entry.impact === "string" && entry.impact.length > 0, `entry.impact should be non-empty for: ${key}`);
  }
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

console.log("settings-workspace-phase11.test.ts: all tests passed");
