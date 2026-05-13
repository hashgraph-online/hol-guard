import { buildClearPayload, clearLabelForScope } from "./clear-policy-payload";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const artifactInput = {
  scope: "artifact" as const,
  harness: "codex",
  artifact_id: "npmjs:lodash",
  artifact_hash: "sha256-lodash",
  workspace: "/projects/myapp",
  publisher: "acme",
};

const workspaceInput = {
  scope: "workspace" as const,
  harness: "codex",
  artifact_id: "npmjs:lodash",
  workspace: "/projects/myapp",
  publisher: null,
};

const publisherInput = {
  scope: "publisher" as const,
  harness: "codex",
  artifact_id: null,
  workspace: null,
  publisher: "acme-corp",
};

const harnessInput = {
  scope: "harness" as const,
  harness: "codex",
  artifact_id: null,
  workspace: null,
  publisher: null,
};

const globalInput = {
  scope: "global" as const,
  harness: "codex",
  artifact_id: null,
  workspace: null,
  publisher: null,
};

const artifactPayload = buildClearPayload(artifactInput);
assert(
  artifactPayload.scope === "artifact",
  "T-CP-GR119-00: artifact scope payload must include scope"
);
assert(
  artifactPayload.artifact_id === "npmjs:lodash",
  "T-CP-GR119-01: artifact scope payload must include artifact_id"
);
assert(
  artifactPayload.artifact_hash === "sha256-lodash",
  "T-CP-GR119-02: artifact scope payload must include artifact_hash"
);
assert(
  artifactPayload.all === undefined,
  "T-CP-GR119-03: artifact scope payload must not set all"
);
assert(
  artifactPayload.workspace === undefined,
  "T-CP-GR119-04: artifact scope payload must not include workspace"
);

const workspacePayload = buildClearPayload(workspaceInput);
assert(
  workspacePayload.scope === "workspace",
  "T-CP-GR119-04a: workspace scope payload must include scope"
);
assert(
  workspacePayload.workspace === "/projects/myapp",
  "T-CP-GR119-05: workspace scope payload must include workspace path"
);
assert(
  workspacePayload.harness === undefined,
  "T-CP-GR119-06: workspace scope payload must not include harness"
);
assert(
  workspacePayload.artifact_id === undefined,
  "T-CP-GR119-07: workspace scope payload must not include artifact_id"
);

const publisherPayload = buildClearPayload(publisherInput);
assert(
  publisherPayload.scope === "publisher",
  "T-CP-GR119-07a: publisher scope payload must include scope"
);
assert(
  publisherPayload.publisher === "acme-corp",
  "T-CP-GR119-08: publisher scope payload must include publisher"
);
assert(
  publisherPayload.harness === undefined,
  "T-CP-GR119-09: publisher scope payload must not include harness"
);

const harnessPayload = buildClearPayload(harnessInput);
assert(
  harnessPayload.scope === "harness",
  "T-CP-GR119-09a: harness scope payload must include scope"
);
assert(
  harnessPayload.harness === "codex",
  "T-CP-GR119-10: harness scope payload must include harness name"
);
assert(
  harnessPayload.all === undefined,
  "T-CP-GR119-11: harness scope payload must not set all"
);
assert(
  harnessPayload.artifact_id === undefined,
  "T-CP-GR119-12: harness scope payload must not include artifact_id"
);

const globalPayload = buildClearPayload(globalInput);
assert(
  globalPayload.scope === "global",
  "T-CP-GR119-12a: global scope payload must include scope"
);
assert(
  globalPayload.all === true,
  "T-CP-GR119-13: global scope payload must set all=true"
);
assert(
  globalPayload.harness === undefined,
  "T-CP-GR119-14: global scope payload must not include harness"
);

const nullArtifactPayload = buildClearPayload({
  scope: "artifact",
  harness: "codex",
  artifact_id: null,
  workspace: null,
  publisher: null,
});
assert(
  nullArtifactPayload.artifact_id === undefined,
  "T-CP-GR119-15: null artifact_id must produce undefined in payload"
);

assert(
  clearLabelForScope("artifact") === "Clear exact decision",
  "T-CP-GR119-16: artifact scope label must be 'Clear exact decision'"
);
assert(
  clearLabelForScope("workspace") === "Clear project decision",
  "T-CP-GR119-17: workspace scope label must be 'Clear project decision'"
);
assert(
  clearLabelForScope("harness") === "Clear app decision",
  "T-CP-GR119-18: harness scope label must be 'Clear app decision'"
);
assert(
  clearLabelForScope("global") === "Clear global decision",
  "T-CP-GR119-19: global scope label must be 'Clear global decision'"
);
assert(
  clearLabelForScope("publisher") === "Clear publisher decision",
  "T-CP-GR119-20: publisher scope label must be 'Clear publisher decision'"
);
