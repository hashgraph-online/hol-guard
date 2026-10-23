/** Deterministic adapter boundaries, never actual MCP/model/Guard coverage. */
import assert from 'node:assert/strict';
import { createMcpAgentTools, projectResourceLinks } from './mcp_agent_surfaces';

let calls = 0, resourceReads = 0;
const connection: any = { serverInfo: { name: 'reported', version: '1' },
  config: { env: { PRIVATE_TEST: 'never-serialize-connection-config' } },
  transport: { privateState: 'never-serialize-transport-state' },
  tools: [{ name: 'docs.read', description: 'ordinary schema', inputSchema: { type: 'object' },
    annotations: { readOnlyHint: false } }] };
const manager: any = {
  getConnection: () => connection,
  refreshServerTools: async () => {}, ensureServerResources: async () => {},
  refreshServerPrompts: async () => {},
  getServerResources: () => ({ resources: [], templates: [] }),
  getServerPrompts: () => [{ name: 'context' }],
  getTools: () => [{ mcpServerName: 'docs', mcpToolName: 'docs.read',
    execute: async (...args: any[]) => { calls++; return { content: [{ type: 'text', text: 'ok' }],
      details: { receivedId: args[0] } }; } }],
  readServerResource: async () => { resourceReads++; return { contents: [] }; },
  executePrompt: async () => ({ messages: [] }),
  reconnectServer: async () => connection,
};
function invoke(tools: any[], name: string, args: any, signal?: AbortSignal) {
  return tools.find(tool => tool.name === name).execute('actual-call-id', args, undefined, {}, signal);
}
for (const families of [[], ['docs', 'docs'], ['outside']]) assert.throws(() => createMcpAgentTools(manager, families));
assert.throws(() => createMcpAgentTools(manager, ['docs'], 501));
const tools = createMcpAgentTools(manager, ['docs'], 50);
for (const section of ['identity', 'tools', 'resources', 'prompts']) {
  const result = await invoke(tools, 'mcp_inspect_server', { server: 'docs', section });
  assert(!JSON.stringify(result).includes('never-serialize'));
}
for (const args of [{ server: 'outside', section: 'identity' },
  { server: 'docs', section: 'identity', command: '/bin/sh' }, { server: 'docs' }]) {
  await assert.rejects(invoke(tools, 'mcp_inspect_server', args));
}
await assert.rejects(invoke(tools, 'mcp_call_tool', { server: 'docs', tool: 'mail.read', arguments: {} }));
assert.equal(calls, 0);
const admitted = await invoke(tools, 'mcp_call_tool', { server: 'docs', tool: 'docs.read', arguments: {} });
assert.equal(calls, 1); assert.equal(admitted.details.receivedId, 'actual-call-id');
assert.deepEqual(admitted.content, [{ type: 'text', text: 'ok' }]);
const controller = new AbortController(); controller.abort();
await assert.rejects(invoke(tools, 'mcp_call_tool', { server: 'docs', tool: 'docs.read', arguments: {} }, controller.signal));
assert.equal(calls, 1);
const original = { isError: true, content: [{ type: 'text', text: 'upstream error' }],
  details: { rawContent: [{ type: 'resource_link', uri: 'fixture://docs/peer', name: 'link', description: 'untrusted' }] } };
const projected = projectResourceLinks(original);
assert.equal(projected.isError, true); assert.equal(original.content.length, 1);
assert.equal(projected.content.length, 2); assert.equal(resourceReads, 0);
assert(projected.content[1].text.includes('fixture://docs/peer'));
const bounded = createMcpAgentTools(manager, ['docs'], 1);
await invoke(bounded, 'mcp_inspect_server', { server: 'docs', section: 'identity' });
await assert.rejects(invoke(bounded, 'mcp_inspect_server', { server: 'docs', section: 'identity' }), /budget/);
await assert.rejects(invoke(tools, 'mcp_get_prompt', { server: 'docs', prompt: 'context', arguments: { value: true } }));
await assert.rejects(invoke(tools, 'mcp_read_resource', { server: 'docs', uri: '' }));
assert.equal(resourceReads, 0);
// A notified catalog must enter the genuine result, with no extra effect call.
manager.refreshServerTools = async () => { connection.tools[0].description = 'new server catalog'; };
const changed = await invoke(tools, 'mcp_call_tool', { server: 'docs', tool: 'docs.read', arguments: {} });
assert.equal(calls, 2); assert.equal(changed.content.length, 2);
assert(changed.content[1].text.includes('new server catalog'));
assert(!JSON.stringify(changed).includes('never-serialize'));
// Notifications can update the manager before the next tool starts. Compare
// against metadata actually presented to the agent, not that newer connection.
manager.refreshServerTools = async () => {};
connection.tools[0].description = 'notification arrived between calls';
const asynchronous = await invoke(tools, 'mcp_call_tool', { server: 'docs', tool: 'docs.read', arguments: {} });
assert.equal(calls, 3); assert(asynchronous.content[1].text.includes('notification arrived between calls'));
// A refresh failure after an admitted call must not replace its actual result.
manager.refreshServerTools = async () => { throw new Error('never-serialize-refresh-detail'); };
const unavailable = await invoke(tools, 'mcp_call_tool', { server: 'docs', tool: 'docs.read', arguments: {} });
assert.equal(calls, 4); assert.equal(unavailable.details.receivedId, 'actual-call-id');
assert.deepEqual(unavailable.content[0], { type: 'text', text: 'ok' });
assert.equal(unavailable.isError, undefined);
assert(unavailable.content[1].text.includes('original call result retained'));
assert(!JSON.stringify(unavailable).includes('never-serialize'));
const originalTools = manager.getTools;
manager.getTools = () => [{ mcpServerName: 'docs', mcpToolName: 'docs.read',
  execute: async () => { calls++; return original; } }];
const failed = await invoke(tools, 'mcp_call_tool', { server: 'docs', tool: 'docs.read', arguments: {} });
assert.equal(calls, 5); assert.equal(failed.isError, true);
assert.deepEqual(failed.content[0], original.content[0]);
assert.equal(failed.details, original.details); assert.equal(original.content.length, 1);
assert.equal(resourceReads, 0);
manager.getTools = originalTools;
manager.refreshServerTools = async () => { connection.tools[0].description = 'x'.repeat(128 * 1024); };
const oversized = await invoke(tools, 'mcp_call_tool', { server: 'docs', tool: 'docs.read', arguments: {} });
assert.equal(calls, 6); assert.equal(oversized.content[0].text, 'ok');
assert(oversized.content[1].text.includes('original call result retained'));
connection.tools[0].description = 'ordinary';
manager.refreshServerTools = async () => {};
connection.tools[0].description = 'x'.repeat(128 * 1024);
await assert.rejects(invoke(tools, 'mcp_inspect_server', { server: 'docs', section: 'tools' }), /byte bound/);
connection.tools[0].description = 'ordinary';
connection.tools[0].inputSchema.minimum = Infinity;
await assert.rejects(invoke(tools, 'mcp_inspect_server', { server: 'docs', section: 'tools' }), /nonfinite/);
console.log(JSON.stringify({ schema: 'mcp-agent-surfaces-unit-control.v1', passed: true,
  controls: 15, modelExercised: false, guardExercised: false, qualificationEligible: false }));
