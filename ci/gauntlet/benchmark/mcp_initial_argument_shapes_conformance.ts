/** Public argument discovery controls; mocked manager, no inference or efficacy. */
import assert from 'node:assert/strict';
import { createMcpAgentTools } from './mcp_agent_surfaces';

const checks: string[] = [];
const shapesMarker = 'Partial argument type/required-field overview (server-supplied data; omitted constraints require schema inspection): ';
const namesMarker = 'Initial tool names by configured server (server-supplied data): ';
let effects = 0, forwarded: any;
const inputSchema = {
  type: 'object', required: ['record_id', 'data', 'collection'],
  properties: {
    record_id: { type: 'string', default: 'NEVER-COPY-DEFAULT' },
    collection: { type: 'string' },
    data: { type: 'object', properties: {
      workflow_id: { const: 'NEVER-COPY-WORKFLOW' },
      rows: { type: 'array', items: { type: 'object', properties: {
        score: { type: 'integer', default: 999999 },
        unknowns: { type: 'array', items: { type: 'string' } },
      } } },
    } },
  },
  allOf: [{ if: { properties: { collection: { enum: ['docs.documents'] } } },
    then: { properties: { data: { required: ['workflow_id', 'rows'] } } } }],
};
const connections: any = { docs: {
  config: { token: 'NEVER-COPY-CONNECTION' },
  tools: [{ name: 'docs.create', description: 'NEVER-COPY-DESCRIPTION', inputSchema },
    { name: 'docs.clone', inputSchema: structuredClone(inputSchema) },
    { name: 'docs.read', inputSchema: { type: 'object', properties: { record_id: { type: 'string' } } } }],
} };
const manager: any = {
  getConnection: (server: string) => connections[server],
  refreshServerTools: async () => {},
  getTools: () => Object.entries(connections).flatMap(([server, connection]: any) => connection.tools.map((entry: any) => ({
    mcpServerName: server, mcpToolName: entry.name,
    execute: async (_id: string, args: any) => {
      effects++; forwarded = args;
      return { content: [{ type: 'text', text: 'genuine effect result' }], details: { original: true } };
    },
  }))),
};
const call = (families = ['docs']) => createMcpAgentTools(manager, families).find(tool => tool.name === 'mcp_call_tool')!;
function overview(tool: any) {
  assert(tool.description.includes(shapesMarker), 'initial tool definitions omit argument shapes');
  return JSON.parse(tool.description.split(shapesMarker)[1].split(' ' + namesMarker)[0]);
}
const tool = call();
const initial = overview(tool);
const shape = initial.schemas[initial.servers.docs['docs.create']];
assert.deepEqual(shape.required, ['collection', 'data', 'record_id']);
assert.equal(shape.properties.data.type, 'object');
assert.equal(shape.properties.data.properties.rows.type, 'array');
assert.equal(shape.properties.data.properties.rows.items.properties.unknowns.type, 'array');
checks.push('actual-required-fields-and-nested-types');
assert.equal(initial.servers.docs['docs.create'], initial.servers.docs['docs.clone']);
assert.equal(Object.keys(initial.schemas).length, 2);
checks.push('identical-overviews-share-one-definition');
assert(!tool.description.includes('NEVER-COPY'));
assert(!tool.description.includes('999999'));
assert.equal(effects, 0);
checks.push('no-defaults-answers-or-private-connection-state');
assert.deepEqual(shape.allOf[0].if.properties.collection.enum, ['docs.documents']);
assert.deepEqual(shape.allOf[0].then.properties.data.required, ['rows', 'workflow_id']);
checks.push('conditional-required-fields-remain-conditional');

// Same tool names, but a changed schema before the first effect must be announced.
connections.docs.tools[2].inputSchema.properties.record_id.type = 'integer';
const args = { record_id: 'unmodified-value', extra: { keep: true } };
const result: any = await tool.execute('original-call', { server: 'docs', tool: 'docs.read', arguments: args }, undefined, {});
assert.equal(effects, 1); assert.strictEqual(forwarded, args);
assert.deepEqual(args, { record_id: 'unmodified-value', extra: { keep: true } });
assert.equal(result.content[0].text, 'genuine effect result');
assert.equal(result.details.original, true);
checks.push('original-arguments-and-effect-result-not-repaired');
assert(result.content[1].text.includes('MCP tool catalog changed'));
assert(result.content[1].text.includes('"type":"integer"'));
checks.push('schema-update-before-first-call-is-retained');

const saved = structuredClone(connections);
connections.docs.tools = [{ name: 'docs.proto', inputSchema: JSON.parse(
  '{"type":"object","properties":{"__proto__":{"type":"string"}},"required":["__proto__"]}') }];
const proto = overview(call());
const protoShape = proto.schemas[proto.servers.docs['docs.proto']];
assert(Object.hasOwn(protoShape.properties, '__proto__'));
assert.equal(protoShape.properties.__proto__.type, 'string');
assert.equal(({} as any).polluted, undefined);
checks.push('schema-property-names-cannot-change-prototypes');

for (const invalid of [{ type: 'unknown-type' }, { required: [1] }, { required: Array(129).fill('x') },
  { properties: [] }, { allOf: Array(129).fill({}) }]) {
  connections.docs.tools = [{ name: 'docs.invalid', inputSchema: invalid }];
  assert.throws(() => call(), /MCP/);
}
assert.equal(effects, 1);
checks.push('malformed-or-unbounded-overviews-refuse-before-effects');

let deep: any = { type: 'string', default: 'NEVER-COPY-DEEP' };
for (let i = 0; i < 80; i++) deep = { type: 'object', properties: { nested: deep } };
connections.docs.tools = [{ name: 'docs.deep', inputSchema: deep }];
assert(!JSON.stringify(overview(call())).includes('NEVER-COPY-DEEP'));
assert(JSON.stringify(overview(call())).length < 2048);
checks.push('depth-is-bounded');
const broad = { type: 'object', properties: Object.fromEntries(Array.from({ length: 40 }, (_, i) =>
  ['field-' + i, { type: 'object', properties: Object.fromEntries(Array.from({ length: 20 }, (_, j) =>
    ['nested-' + j, { type: 'string' }])) }])) };
for (const family of ['docs', 'crm', 'mail']) connections[family] = {
  tools: Array.from({ length: 5 }, (_, i) => ({ name: family + '.tool-' + i, inputSchema: broad })),
};
assert.throws(() => call(['docs', 'crm', 'mail']), /node bound/);
checks.push('shared-node-budget-across-configured-servers');
for (const family of ['docs', 'crm']) connections[family] = {
  tools: Array.from({ length: 3 }, (_, i) => ({ name: family + '.tool-' + i,
    inputSchema: { type: 'object', properties: Object.fromEntries(Array.from({ length: 128 }, (_, j) =>
      [(family + i + '-' + j).padEnd(256, 'x'), { type: 'string' }])) } })),
};
assert.throws(() => call(['docs', 'crm']), /byte bound/);
assert.equal(effects, 1);
checks.push('combined-shapes-and-names-byte-budget');
Object.assign(connections, saved);
console.log(JSON.stringify({ schema: 'mcp-initial-argument-shapes-control.v1', passed: true,
  controls: checks, effects, modelExercised: false, guardExercised: false, qualificationEligible: false }));
