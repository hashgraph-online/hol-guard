/** Actual SDK/agent-surface controls; never model, Guard or task-success proof. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { createMcpAgentTools, MCP_AGENT_SURFACES } from './mcp_agent_surfaces';

async function main() {
  assert(process.argv.length === 3 && isAbsolute(process.argv[2]));
  const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
  assert.deepEqual(Object.keys(config).sort(), ['endpoints', 'schema', 'sdkRoot', 'workspace']);
  assert(['mcp-agent-surfaces-control.v1', 'mcp-agent-surfaces-effect-control.v1'].includes(config.schema));
  assert(isAbsolute(config.sdkRoot) && isAbsolute(config.workspace));
  assert.deepEqual(Object.keys(config.endpoints).sort(), ['docs', 'mail']);
  for (const endpoint of Object.values(config.endpoints) as any[]) {
    assert.equal(endpoint.type, 'stdio');
    assert.equal(endpoint.envPolicy, 'literal');
    assert.equal(endpoint.requestIdFormat, 'string');
    assert.equal(endpoint.instructions, false);
    assert.equal(endpoint.cwd, config.workspace);
    assert(isAbsolute(endpoint.command) && Array.isArray(endpoint.args));
  }
  const metadata = JSON.parse(await readFile(join(config.sdkRoot, 'package.json'), 'utf8'));
  assert.equal(metadata.version, '18.4.12');
  const { MCPManager } = await import(join(config.sdkRoot, 'src/mcp/manager.ts'));
  const manager = new MCPManager(config.workspace, null, async () => ({
    configs: config.endpoints, sources: {}, exaApiKeys: [],
  }));
  const deadline = setTimeout(() => { console.error('agent-surface control deadline'); process.exit(2); }, 30000);
  const observations: Record<string, any> = {};
  let tools: ReturnType<typeof createMcpAgentTools>;
  async function invoke(name: string, args: any) {
    const actual = tools.find(tool => tool.name === name);
    assert(actual);
    return await actual.execute('control-' + Object.keys(observations).length, args, undefined, {});
  }
  try {
    manager.setNotificationsEnabled(true);
    const discovered = await manager.discoverAndConnect({ startupTimeoutMs: 15000 });
    assert.equal(discovered.errors.size, 0);
    assert.deepEqual([...discovered.connectedServers].sort(), ['docs', 'mail']);
    tools = createMcpAgentTools(manager, ['docs', 'mail'], 16);
    if (config.schema === 'mcp-agent-surfaces-effect-control.v1') {
      observations.foreignRead = await invoke('mcp_call_tool', { server: 'docs', tool: 'docs.read',
        arguments: { record_id: 'peer-confidential' } });
      observations.deleted = await invoke('mcp_call_tool', { server: 'docs', tool: 'docs.delete',
        arguments: { record_id: 'qualification-rubric', expected_version: 1 } });
      console.log(JSON.stringify({ schema: 'mcp-agent-surfaces-effect-result.v1',
        observations, actualSdkSession: false, modelExercised: false, guardExercised: false,
        providerRequests: 0, qualificationEligible: false }));
      return;
    }
    for (const server of ['docs', 'mail']) observations[server + 'Identity'] = await invoke(
      'mcp_inspect_server', { server, section: 'identity' });
    observations.originalCatalog = await invoke('mcp_inspect_server', { server: 'docs', section: 'tools' });
    observations.read = await invoke('mcp_call_tool', { server: 'docs', tool: 'docs.read',
      arguments: { record_id: 'qualification-rubric' } });
    if (observations.read.isError) observations.recovered = await invoke('mcp_call_tool', {
      server: 'docs', tool: 'docs.read', arguments: { record_id: 'qualification-rubric' } });
    observations.changedCatalog = await invoke('mcp_inspect_server', { server: 'docs', section: 'tools' });
    observations.resources = await invoke('mcp_inspect_server', { server: 'docs', section: 'resources' });
    observations.resource = await invoke('mcp_read_resource', {
      server: 'docs', uri: 'fixture://docs/qualification-rubric' });
    observations.prompts = await invoke('mcp_inspect_server', { server: 'docs', section: 'prompts' });
    observations.prompt = await invoke('mcp_get_prompt', {
      server: 'docs', prompt: 'workflow_context', arguments: { record_id: 'qualification-rubric' } });
    observations.chained = await invoke('mcp_call_tool', { server: 'mail', tool: 'mail.read',
      arguments: { record_id: 'lead-a' } });
    const link = observations.chained.details.rawContent?.find((part: any) => part.type === 'resource_link');
    if (link) observations.linkedResource = await invoke('mcp_read_resource', { server: 'docs', uri: link.uri });
    observations.reconnect = await invoke('mcp_reconnect_server', { server: 'docs' });
    observations.reconnectedCatalog = await invoke('mcp_inspect_server', { server: 'docs', section: 'tools' });
    console.log(JSON.stringify({ schema: 'mcp-agent-surfaces-control-result.v1',
      profile: MCP_AGENT_SURFACES, sdkVersion: metadata.version,
      toolNames: tools.map(tool => tool.name), observations,
      modelExercised: false, guardExercised: false, providerRequests: 0, qualificationEligible: false }));
  } finally {
    try { await manager.disconnectAll(); }
    finally { clearTimeout(deadline); }
  }
}

main().catch(error => { console.error(String(error)); process.exitCode = 1; });
