import assert from "node:assert/strict";
import { parseRecentMcpSetups } from "./mcp-setup-receipts";

const setup = { rollback_handle: "a".repeat(64), selection_digest: "b".repeat(64),
  setup_name: "example", kind: "remote", registry_name: "org.example/server", version: "1.0.0" };
assert.deepEqual(parseRecentMcpSetups([setup]), [setup]);
assert.deepEqual(parseRecentMcpSetups([]), []);
assert.deepEqual(parseRecentMcpSetups([{ ...setup, rollback_available: false }]), [{ ...setup, rollback_available: false }]);
assert.throws(() => parseRecentMcpSetups([{ ...setup, rollback_available: "false" }]), /verify recent setup history/);
for (const bad of [null, {}, [null], Array(33).fill(setup), [setup, setup],
  [{ ...setup, rollback_handle: "bad" }], [{ ...setup, kind: "other" }],
  [{ ...setup, setup_name: "a.b" }], [{ ...setup, setup_name: "Uppercase" }],
  [{ ...setup, setup_name: "_leading" }], [{ ...setup, setup_name: "-leading" }],
  [{ ...setup, selection_digest: "bad" }]]) {
  assert.throws(() => parseRecentMcpSetups(bad), /verify recent setup history/);
}
assert.deepEqual(parseRecentMcpSetups([{ ...setup, host_config: "private", approval_password: "private" }]), [setup]);
console.log("mcp-setup-receipts: malformed, duplicate, oversized and private history checks passed");
