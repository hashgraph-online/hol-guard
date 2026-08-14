import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("./extension-policy-panel.tsx", import.meta.url), "utf8");

for (const expected of [
  "Protection settings",
  "Recommended",
  "Allow",
  "Block",
  "Stricter",
  "Custom",
  "What will change",
  "Emergency Lockdown",
  "Technical setting details",
  "Developer change identity",
  "Authenticate this exact change",
  "Apply ${count} reviewed change",
]) {
  assert.ok(source.includes(expected), `missing friendly Protection Center copy: ${expected}`);
}

for (const forbidden of [
  "Blast radius before apply",
  "Server semantic preview",
  "Permission controls",
  "Local policy draft",
  "Global lockdown remains dominant",
]) {
  assert.ok(!source.includes(forbidden), `legacy policy-editor copy remains: ${forbidden}`);
}

console.log("extension-policy-panel.copy.test.tsx: all assertions passed");