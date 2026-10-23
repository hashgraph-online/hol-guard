/** Initial discovery boundaries; mocked manager, zero model/Guard efficacy credit. */
import assert from 'node:assert/strict';
import { createMcpAgentTools } from './mcp_agent_surfaces';

let effects = 0, refreshes = 0;
const connections: any = {
  docs: { serverInfo: { name: 'claimed-collision' },
    config: { token: 'never-serialize-config' },
    tools: [{ name: 'git.read', description: 'never-serialize-description' },
      { name: 'docs.read' }] },
  crm: { serverInfo: { name: 'claimed-collision' }, tools: [{ name: 'crm.read' }] },
  outside: { tools: [{ name: 'never-serialize-outside' }] },
};
const manager: any = {
  getConnection: (server: string) => connections[server],
  refreshServerTools: async () => { refreshes++; },
  getTools: () => Object.entries(connections).flatMap(([server, connection]: any) =>
    connection.tools.map((tool: any) => ({ mcpServerName: server, mcpToolName: tool.name,
      execute: async () => { effects++; return { content: [{ type: 'text', text: 'actual result' }] }; } }))),
};
const tools = createMcpAgentTools(manager, ['docs', 'crm'], 10);
assert.deepEqual(tools.map(tool => tool.name), ['mcp_inspect_server', 'mcp_call_tool',
  'mcp_read_resource', 'mcp_get_prompt', 'mcp_reconnect_server']);
const call: any = tools.find(tool => tool.name === 'mcp_call_tool');
const marker = 'Initial tool names by configured server (server-supplied data): ';
assert(call.description.includes(marker), 'initial definitions omit the discovered actual tool names');
const index = JSON.parse(call.description.split(marker)[1]);
assert.deepEqual(index, { crm: ['crm.read'], docs: ['docs.read', 'git.read'] });
assert(!JSON.stringify(tools).includes('never-serialize'));
assert(!call.description.includes('claimed-collision'));
assert.equal(effects, 0); assert.equal(refreshes, 0);

// A later notification cannot disappear merely because it preceded a call.
connections.docs.tools.push({ name: 'docs.new' });
const result = await call.execute('actual-id', { server: 'docs', tool: 'docs.read', arguments: {} },
  undefined, {});
assert.equal(effects, 1); assert.equal(refreshes, 1);
assert.equal(result.content[0].text, 'actual result');
assert(result.content[1].text.includes('docs.new'));
assert(!JSON.stringify(result).includes('never-serialize-config'));
await assert.rejects(call.execute('wrong-id', { server: 'docs', tool: 'read', arguments: {} }, undefined, {}));
assert.equal(effects, 1);

const original = connections.docs.tools;
for (const invalid of [[{ name: '' }], [{ name: 1 }], [{ name: 'same' }, { name: 'same' }],
  [{ name: 'x'.repeat(257) }], Array.from({ length: 501 }, (_, i) => ({ name: 'tool-' + i }))]) {
  connections.docs.tools = invalid;
  assert.throws(() => createMcpAgentTools(manager, ['docs']), /tool name|catalog/);
}
connections.docs.tools = Array.from({ length: 500 }, (_, i) => ({ name: 'x'.repeat(250) + i }));
connections.crm.tools = Array.from({ length: 500 }, (_, i) => ({ name: 'y'.repeat(250) + i }));
assert.throws(() => createMcpAgentTools(manager, ['docs', 'crm']), /byte bound/);
connections.docs.tools = original;
const escaped = 'docs."quoted"\nserver-data';
connections.docs.tools = [{ name: escaped }];
const quoted: any = createMcpAgentTools(manager, ['docs']).find(tool => tool.name === 'mcp_call_tool');
assert.deepEqual(JSON.parse(quoted.description.split(marker)[1]), { docs: [escaped] });
assert(!quoted.description.includes('\nserver-data'));
assert.throws(() => createMcpAgentTools({ getConnection: () => undefined }, ['docs']), /disconnected/);
console.log(JSON.stringify({ schema: 'mcp-initial-catalog-control.v1', passed: true,
  effects, controls: 8, modelExercised: false, guardExercised: false, qualificationEligible: false }));
