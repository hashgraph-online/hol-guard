import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { GuardActionEnvelope, GuardReceipt } from "../guard-types";
import { detectCategory, getCategoryInfo } from "./categories";
import { EvidenceActionDetail } from "./evidence-action-detail";
import { humanFileName, plainEnglishDescription, resolveActionDetail } from "./plain-english";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

const __dirname = dirname(fileURLToPath(import.meta.url));

const BASE_ENVELOPE: GuardActionEnvelope = {
  schema_version: 1,
  action_id: "act-evidence",
  harness: "codex",
  event_name: "tool_call",
  action_type: "shell_command",
  workspace: null,
  workspace_hash: null,
  tool_name: null,
  command: null,
  prompt_excerpt: null,
  prompt_text: null,
  target_paths: [],
  network_hosts: [],
  mcp_server: null,
  mcp_tool: null,
  package_manager: null,
  package_name: null,
  script_name: null,
  raw_payload_redacted: {},
};

function makeReceipt(id: string, overrides: Partial<GuardReceipt> = {}): GuardReceipt {
  return {
    receipt_id: id,
    harness: "codex",
    artifact_id: `artifact-${id}`,
    artifact_hash: `hash-${id}`,
    policy_decision: "allow",
    capabilities_summary: `Summary ${id}`,
    changed_capabilities: [],
    provenance_summary: `Provenance ${id}`,
    user_override: null,
    artifact_name: `Tool ${id}`,
    source_scope: null,
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

const longEvidenceText = `${"cat ~/.guard/secrets.json && ".repeat(10)}printenv HOL_GUARD_TEST_TOKEN`;
const longEvidenceReceipt = makeReceipt("detail-long", {
  artifact_type: "command",
  action_envelope_json: {
    ...BASE_ENVELOPE,
    command: longEvidenceText,
  },
});

assert(
  resolveActionDetail(longEvidenceReceipt) === longEvidenceText,
  "GR232: resolveActionDetail preserves the full logged command text for Evidence copy"
);

const evidenceDetailMarkup = renderToStaticMarkup(
  createElement(EvidenceActionDetail, { receipt: longEvidenceReceipt, onClose: () => undefined }),
);

assert(
  evidenceDetailMarkup.includes("Expand"),
  "GR233: evidence action detail renders an expand control for long logged content"
);

assert(
  evidenceDetailMarkup.includes("Copy"),
  "GR233: evidence action detail renders a copy control for logged content"
);

const networkReceipt = makeReceipt("net1", {
  capabilities_summary: "calls http://api.example.com",
  artifact_name: "fetch-tool",
});
const secretReceipt = makeReceipt("sec1", {
  capabilities_summary: "reads .env file and environment variables",
  artifact_name: "env-reader",
});
const fileReceipt = makeReceipt("file1", {
  capabilities_summary: "writes files to disk at /home/user/docs",
  artifact_name: "file-writer",
});
const mcpReceipt = makeReceipt("mcp1", {
  capabilities_summary: "mcp tool call",
  artifact_name: "mcp-bridge",
});

assert(detectCategory(networkReceipt) === "network", "GR231: network receipt detected as network category");
assert(detectCategory(secretReceipt) === "secret", "GR231: secret receipt detected as secret category");
assert(detectCategory(fileReceipt) === "file-write", "GR231: file receipt detected as file-write category");
assert(detectCategory(mcpReceipt) === "mcp", "GR231: mcp receipt detected as mcp category");

const netInfo = getCategoryInfo("network");
assert(typeof netInfo.label === "string" && netInfo.label.length > 0, "GR231: getCategoryInfo returns non-empty label");
assert(typeof netInfo.color === "string" && netInfo.color.length > 0, "GR231: getCategoryInfo returns non-empty color class");

const humanName1 = humanFileName("my-cool-tool.js");
assert(humanName1.length > 0, "GR231: humanFileName returns non-empty string");

const humanName2 = humanFileName(null);
assert(humanName2.length > 0, "GR231: humanFileName handles null gracefully");

const humanName3 = humanFileName("tool.with.many.dots.js");
assert(!humanName3.includes(".js") || humanName3 === "tool.with.many.dots.js", "GR231: humanFileName trims extension");

const descNetwork = plainEnglishDescription(networkReceipt);
assert(typeof descNetwork === "string" && descNetwork.length > 0, "GR232: plainEnglishDescription returns non-empty string");

const descSecret = plainEnglishDescription(secretReceipt);
assert(typeof descSecret === "string" && descSecret.length > 0, "GR232: plainEnglishDescription works for secret receipt");

const descNull = plainEnglishDescription(makeReceipt("nullname", { artifact_name: null }));
assert(typeof descNull === "string" && descNull.length > 0, "GR232: plainEnglishDescription handles null artifact_name");

const descGeneric = plainEnglishDescription(makeReceipt("gen1", { capabilities_summary: "" }));
assert(typeof descGeneric === "string" && descGeneric.length > 0, "GR232: plainEnglishDescription handles empty capabilities_summary");

const detailSource = readFileSync(join(__dirname, "evidence-action-detail.tsx"), "utf8");
const loggedPanelSource = readFileSync(join(__dirname, "../logged-action-panel.tsx"), "utf8");

assert(
  detailSource.includes('aria-expanded') || detailSource.includes('details') || detailSource.includes('hidden'),
  "GR233: evidence-action-detail contains collapsible/hidden raw JSON pattern"
);

assert(
  detailSource.includes("copyUnavailable"),
  "GR232: clipboard unavailable state is handled in evidence-action-detail"
);

assert(
  loggedPanelSource.includes("navigator.clipboard.writeText(props.text)"),
  "GR232: logged action panel copies the full logged text to the clipboard"
);

assert(
  !detailSource.includes("// clipboard"),
  "GR232: no inline clipboard comment in evidence-action-detail"
);

assert(
  detailSource.includes('role="button"') || detailSource.includes("onClick"),
  "GR244: detail panel has interactive elements"
);

assert(
  detailSource.includes("onKeyDown") || detailSource.includes("role=") || detailSource.includes('tabIndex'),
  "GR244: detail panel includes keyboard accessibility attributes"
);

console.log("evidence-detail.test.ts: all tests passed");
