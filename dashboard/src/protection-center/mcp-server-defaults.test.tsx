import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";

import { protectionModuleFixture } from "./fixtures/protection-fixtures";
import { McpServerDefaults } from "./mcp-server-defaults";

const extension = protectionModuleFixture({
  extension_id: "command.mcp-future",
  name: "Future MCP",
  trust_class: "external",
  surface: "mcp",
  mcp_launch: { kind: "unsupported" },
  mcp_tools: [{ name: "delete_file", state: "block" }],
});
const markup = renderToStaticMarkup(<McpServerDefaults extension={extension} />);
assert.match(markup, /data-testid="mcp-launch-unsupported"/, "unknown launch kinds show the update note");
assert.match(markup, /delete_file/, "tool defaults stay visible for an unknown launch kind");
assert.match(markup, />Block</, "tool default states stay visible for an unknown launch kind");
assert.doesNotMatch(markup, /Unknown package/, "no placeholder launch details render for an unknown launch kind");
