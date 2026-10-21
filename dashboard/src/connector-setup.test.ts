import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ConnectorSetupCard } from "./connector-setup-card";
import {
  buildConnectorSetupGroups,
  connectorGroupKey,
  connectorSetupIdentityKey,
  isConnectorSetupItem,
  triedCatalogCommands,
} from "./connector-setup-groups";
import type { GuardAction, GuardActionEnvelope, GuardApprovalGatePublicConfig, GuardApprovalRequest } from "./guard-types";
import type { LocalCliItem } from "./local-cli-api";
import { queuePageSyncTarget } from "./review-queue-page-sync";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const BASE_ENVELOPE: GuardActionEnvelope = {
  schema_version: 1,
  action_id: "act-connector-test",
  harness: "claude-code",
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

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "request-connector-test",
  harness: "claude-code",
  artifact_id: "claude-code:project:bash",
  artifact_name: "bash",
  artifact_type: "command",
  artifact_hash: "sha256-connector",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "./claude.json",
  launch_target: "git status",
  transport: "stdio",
  review_command: "hol-guard approvals approve request-connector-test",
  approval_url: "http://127.0.0.1:4781/approvals/request-connector-test",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-04-11T12:00:00Z",
  resolved_at: null,
  action_envelope_json: null,
};

// Connector setup: rows held only because a local CLI was never set up share
// `connector:<identity_hash>:<action>` and collapse into one pinned card.
const IDENTITY = "a1b2c3d4e5f6a7b8c9d0";
const connectorRow = (
  id: string,
  digest: string,
  command: string,
  extra: Partial<GuardApprovalRequest> = {},
): GuardApprovalRequest => ({
  ...BASE_REQUEST,
  request_id: id,
  policy_action: "review" as GuardAction,
  queue_group_id: `connector:${IDENTITY}:${digest}`,
  trigger_summary: "Running lanectl to check the local lane",
  workspace: "/workspace/sample-project",
  action_envelope_json: { ...BASE_ENVELOPE, command, workspace: "/workspace/sample-project" },
  ...extra,
});
const statusRow = connectorRow("conn-1", "0011223344556677", "lanectl status --port 1", {
  dedupe_count: 3,
  last_seen_at: "2026-04-11T12:05:00Z",
});
const listenRow = connectorRow("conn-2", "8899aabbccddeeff", "lanectl listen ./notes.txt");
const otherRow = connectorRow("conn-3", "0000000000000001", "echo-mcp run", {
  queue_group_id: "connector:ffffeeeeddddcccc:0000000000000001",
});
const ordinary: GuardApprovalRequest = { ...BASE_REQUEST, request_id: "ordinary-1", queue_group_id: "dup:abc" };
const lanectl = {
  cli_id: "local-cli.lanectl",
  name: "lanectl",
  display_name: "lanectl",
  identity_hash: IDENTITY,
  surface: "cli",
  source_label: "~/.local/bin",
  commands: [
    { command_id: "status", name: "status", usage: "", description: "", parent_id: null, state: "inherit" },
    { command_id: "listen", name: "listen", usage: "", description: "", parent_id: null, state: "inherit" },
    { command_id: "port", name: "port", usage: "", description: "", parent_id: "status", state: "inherit" },
  ],
} as unknown as LocalCliItem;

assert(connectorGroupKey(statusRow.queue_group_id) === `connector:${IDENTITY}`, "group key keeps the first two segments");
assert(connectorGroupKey("dup:abc") === null, "ordinary queue groups are not connector groups");
assert(connectorGroupKey("connector:") === null, "a connector group without an identity is ignored");
assert(isConnectorSetupItem(statusRow) && !isConnectorSetupItem(ordinary), "only connector rows need setup");
assert(
  !isConnectorSetupItem({ ...statusRow, status: "resolved" }),
  "resolved connector rows leave the Needs setup card",
);

const items = [ordinary, listenRow, statusRow, otherRow];
const groups = buildConnectorSetupGroups(items, [lanectl]);
assert(groups.length === 2, "one card per connector identity");
const lane = groups.find((group) => group.identityHash === IDENTITY);
assert(lane !== undefined, "the lanectl connector is grouped");
assert(lane!.items.length === 2, "distinct actions on one connector stay as separate evidence rows");
assert(lane!.callCount === 4, "merged retries count toward calls waiting on the connector");
assert(lane!.setupHref === "/extensions/local-cli/local-cli.lanectl", "a resolved connector links to its Protect page");
assert(
  lane!.triedCommands.join(",") === "listen,status",
  "tried commands come from the catalog and never include operands",
);
assert(!lane!.caution, "plain connector calls carry no caution");
const unresolved = groups.find((group) => group.identityHash !== IDENTITY);
assert(unresolved?.setupHref === "/extensions", "an unresolved connector falls back to the Protect list");
assert(unresolved?.triedCommands.length === 0, "without a catalog nothing from the command line is shown");

// The identity key drives the local tool list fetch: it changes only when a connector appears or leaves.
assert(connectorSetupIdentityKey([ordinary]) === "", "no connector rows give an empty identity key");
const twoConnectors = connectorSetupIdentityKey([otherRow, statusRow, listenRow]);
assert(twoConnectors === `${IDENTITY},ffffeeeeddddcccc`, "the identity key is the sorted connector identities");
assert(
  connectorSetupIdentityKey([listenRow, statusRow, otherRow]) === twoConnectors,
  "the identity key ignores row order and repeated actions",
);
assert(
  connectorSetupIdentityKey([statusRow, listenRow]) !== twoConnectors,
  "a connector that appears later changes the identity key so the tool list is fetched again",
);

const cautionGroups = buildConnectorSetupGroups(
  [
    statusRow,
    connectorRow("conn-4", "1111111111111111", "lanectl wipe", {
      dedupe_count: 2,
      extension_recommendation: { caution: true } as GuardApprovalRequest["extension_recommendation"],
    }),
  ],
  [lanectl],
);
assert(cautionGroups[0].caution, "a caution row marks the whole card");
assert(cautionGroups[0].cautionCount === 2, "the caution count sums merged retries of caution rows, like calls waiting");
assert(cautionGroups[0].callCount === 5, "calls waiting still count every merged retry");

// Package scripts are matched on the script name, whatever runner invoked them.
const packageScripts = {
  cli_id: "local-cli.pkg-demo",
  name: "demo-app",
  display_name: "demo-app",
  identity_hash: "pkgidentity01",
  surface: "package-scripts",
  source_label: "demo-app",
  commands: [
    { command_id: "root", name: "pnpm run", usage: "pnpm run", description: "", parent_id: null, state: "inherit" },
    { command_id: "build", name: "build", usage: "pnpm run build", description: "", parent_id: null, state: "inherit" },
    { command_id: "test", name: "test", usage: "pnpm run test", description: "", parent_id: null, state: "inherit" },
    {
      command_id: "guard.audit",
      name: "guard:audit",
      usage: "pnpm run guard:audit",
      description: "",
      parent_id: "guard",
      state: "inherit",
    },
  ],
} as unknown as LocalCliItem;
const scriptRows = (commands: string[]) =>
  commands.map((command, index) => connectorRow(`script-${index}`, `${index}`, command));
assert(
  triedCatalogCommands(scriptRows(["npm run build"]), packageScripts).join(",") === "build",
  "npm run <script> names the script, not the run verb",
);
assert(
  triedCatalogCommands(scriptRows(["pnpm run guard:audit --verbose", "yarn test", "bun run build -- --watch"]), packageScripts).join(",")
    === "build,guard:audit,test",
  "pnpm run, yarn <script> and bun run all resolve to catalog script names, including colon names",
);
assert(
  triedCatalogCommands(scriptRows(["pnpm --filter web run build", "npm --prefix ./app run-script test"]), packageScripts).join(",")
    === "build,test",
  "runner flags and their values are skipped before the script name",
);
assert(
  triedCatalogCommands(scriptRows(["CI=1 npm run build"]), packageScripts).join(",") === "build",
  "leading environment assignments are not the runner",
);
assert(
  triedCatalogCommands(scriptRows(["npm run deploy", "npm run", "npm install"]), packageScripts).length === 0,
  "scripts outside the catalog and bare runners are never shown",
);
assert(
  triedCatalogCommands(scriptRows(["lanectl run status"]), lanectl).length === 0,
  "a CLI catalog still matches only the first subcommand, not run-style operands",
);

// A setup-card evidence row opened outside the current queue page stays active; queue navigation re-syncs.
const queuePage = [ordinary, { ...ordinary, request_id: "ordinary-2" }];
const syncInput = {
  pagedRequests: queuePage,
  activeRequestId: "conn-9",
  detailRequestId: null,
  pinnedRequestId: null,
};
assert(queuePageSyncTarget(syncInput) === "ordinary-1", "an active request off the page moves to the first queue row");
assert(
  queuePageSyncTarget({ ...syncInput, pinnedRequestId: "conn-9" }) === null,
  "a request opened from a setup card is not pulled back to the queue page",
);
assert(
  queuePageSyncTarget({ ...syncInput, pinnedRequestId: "conn-other" }) === "ordinary-1",
  "a pin on a different request does not keep this one active",
);
assert(
  queuePageSyncTarget({ ...syncInput, activeRequestId: "ordinary-2" }) === null,
  "an active request on the page stays selected",
);
assert(
  queuePageSyncTarget({ ...syncInput, detailRequestId: "conn-9" }) === null,
  "a loaded detail for the active request keeps it selected",
);
assert(
  queuePageSyncTarget({ ...syncInput, activeRequestId: null }) === "ordinary-1",
  "with nothing active the first queue row is selected",
);
assert(
  queuePageSyncTarget({ ...syncInput, pagedRequests: [], pinnedRequestId: null }) === null,
  "an empty page selects nothing",
);

const gate = { configured: true, enabled: true } as unknown as GuardApprovalGatePublicConfig;
const originalWindow = (globalThis as { window?: unknown }).window;
const storage = { getItem: () => null, setItem: () => undefined, removeItem: () => undefined };
(globalThis as { window?: unknown }).window = {
  location: { origin: "http://127.0.0.1:4174", pathname: "/", search: "", hash: "" },
  sessionStorage: storage,
  localStorage: storage,
};
const card = renderToStaticMarkup(
  createElement(ConnectorSetupCard, {
    group: lane!,
    approvalGate: gate,
    activeRequestId: null,
    onOpenRequest: () => undefined,
  }),
);
assert(card.includes("Needs setup") && card.includes("lanectl"), "the card names the connector");
assert(card.includes("4 calls waiting on this"), "the card shows how many calls wait on setup");
assert(card.includes("Running lanectl to check the local lane"), "the card shows what the agent was doing");
assert(card.includes("sample-project"), "the card shows the workspace label");
assert(card.includes("lanectl status --port 1") && card.includes("lanectl listen ./notes.txt"), "every row stays listed as evidence");
assert(card.includes("<details"), "evidence rows are expandable from Review details");
assert(!card.includes("destructive or touch"), "no caution banner without a caution row");
const cautionCard = renderToStaticMarkup(
  createElement(ConnectorSetupCard, {
    group: cautionGroups[0],
    approvalGate: gate,
    activeRequestId: null,
    onOpenRequest: () => undefined,
  }),
);
assert(cautionCard.includes("destructive or touch"), "a caution row shows the caution banner on the card");
assert(cautionCard.includes("2 of these calls are destructive"), "the caution banner counts merged retries as calls");
assert(card.includes('href="/extensions/local-cli/local-cli.lanectl"'), "Set up deep-links into the Protect flow");
const ungatedCard = renderToStaticMarkup(
  createElement(ConnectorSetupCard, {
    group: lane!,
    approvalGate: null,
    activeRequestId: null,
    onOpenRequest: () => undefined,
  }),
);
assert(
  ungatedCard.includes("Set up approval password") && !ungatedCard.includes("Block on this device"),
  "without an approval gate the card links to approval setup first",
);
(globalThis as { window?: unknown }).window = originalWindow;

const cardSource = readFileSync(fileURLToPath(new URL("./connector-setup-card.tsx", import.meta.url)), "utf8");
assert(!/applyLocalCliMutation|previewLocalCliMutation|onResolve|"allowed"/.test(cardSource), "the card never writes grants itself");

console.log("connector-setup.test.ts: all tests passed");
