import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("./extension-policy-panel.tsx", import.meta.url), "utf8");
const quickApplySource = readFileSync(new URL("./protection-center/components/quick-apply-toolbar.tsx", import.meta.url), "utf8");

for (const expected of [
  "Protection settings",
  "Recommended",
  "Allow",
  "Block",
  "QuickApplyToolbar",
  'subject={{ one: "changeable setting", other: "changeable settings" }}',
  "onApply={setPermissionStates}",
  "What will change",
  "Emergency Lockdown",
  "Technical setting details",
  "Developer change identity",
  "Authenticate this exact change",
  "Apply ${count} reviewed change",
]) {
  assert.ok(source.includes(expected), `missing friendly Protection Center copy: ${expected}`);
}

// The three quick-apply labels are single-sourced in the shared toolbar module.
for (const expected of [
  "Quick apply to",
  "Recommended",
  "Allow all",
  "Deny all",
  "Changes stay in draft until you review and approve them",
]) {
  assert.ok(quickApplySource.includes(expected), `missing quick-apply copy: ${expected}`);
}

for (const forbidden of [
  "Blast radius before apply",
  "Server semantic preview",
  "Permission controls",
  "Local policy draft",
  "Global lockdown remains dominant",
  "Apply to every pattern you can change",
  "Reset to Recommended",
  "Block all changeable variants",
]) {
  assert.ok(!source.includes(forbidden), `legacy policy-editor copy remains: ${forbidden}`);
}

console.log("extension-policy-panel.copy.test.tsx: all assertions passed");
