/** Real SDK session + MCP APIs, scripted stream only: zero inference credit. */
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { createMcpAgentTools } from './mcp_agent_surfaces';
import { pinDeclaredToolInventory } from './developer_omp_episode';

async function main() {
  assert(process.argv.length === 3 && isAbsolute(process.argv[2]));
  const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
  assert.deepEqual(Object.keys(config).sort(), ['endpoints', 'schema', 'sdkRoot', 'workspace']);
  assert.equal(config.schema, 'mcp-agent-session-control.v1');
  assert(isAbsolute(config.sdkRoot) && isAbsolute(config.workspace));
  assert.deepEqual(Object.keys(config.endpoints).sort(), ['docs', 'mail']);
  for (const endpoint of Object.values(config.endpoints) as any[]) {
    assert.equal(endpoint.type, 'stdio'); assert.equal(endpoint.envPolicy, 'literal');
    assert.equal(endpoint.requestIdFormat, 'string'); assert.equal(endpoint.instructions, false);
    assert.equal(endpoint.cwd, config.workspace);
    assert(isAbsolute(endpoint.command) && Array.isArray(endpoint.args));
  }
  assert.equal(JSON.parse(await readFile(join(config.sdkRoot, 'package.json'), 'utf8')).version, '18.4.12');
  const sdk = await import(join(config.sdkRoot, 'src/index.ts'));
  const { MCPManager } = await import(join(config.sdkRoot, 'src/mcp/manager.ts'));
  const { AssistantMessageEventStream } = await import(resolve(config.sdkRoot, '../pi-ai/src/utils/event-stream.ts'));
  const agentDir = join(config.workspace, 'synthetic-agent');
  await mkdir(agentDir);
  const auth = await sdk.AuthStorage.create(join(agentDir, 'synthetic-auth.db'));
  const manager = new MCPManager(config.workspace, null, async () => ({
    configs: config.endpoints, sources: {}, exaApiKeys: [],
  }));
  let session: any, streamCalls = 0;
  const results: any[] = [], providerContexts: any[] = [];
  const deadline = setTimeout(() => { console.error('agent session control deadline'); process.exit(2); }, 45000);
  const schedule = [
    ['mcp_inspect_server', { server: 'docs', section: 'identity' }],
    ['mcp_inspect_server', { server: 'mail', section: 'identity' }],
    ['mcp_inspect_server', { server: 'docs', section: 'tools' }],
    ['mcp_call_tool', { server: 'docs', tool: 'docs.read', arguments: { record_id: 'qualification-rubric' } }],
    ['mcp_read_resource', { server: 'docs', uri: 'fixture://docs/qualification-rubric' }],
    ['mcp_get_prompt', { server: 'docs', prompt: 'workflow_context', arguments: { record_id: 'qualification-rubric' } }],
    ['mcp_reconnect_server', { server: 'docs' }],
  ];
  try {
    manager.setNotificationsEnabled(true);
    const discovered = await manager.discoverAndConnect({ startupTimeoutMs: 15000 });
    assert.equal(discovered.errors.size, 0);
    assert.deepEqual([...discovered.connectedServers].sort(), ['docs', 'mail']);
    const settings = await sdk.Settings.init({ cwd: config.workspace, agentDir, inMemory: true });
    const registry = new sdk.ModelRegistry(auth, join(agentDir, 'synthetic-models.yml'), { settings });
    registry.registerProvider('surface-control', { baseUrl: 'http://127.0.0.1:9/v1',
      api: 'openai-completions', authHeader: false, apiKey: 'synthetic-no-provider', models: [{
        id: 'scripted-control', name: 'scripted-control', reasoning: false, input: ['text'],
        contextWindow: 100000, maxTokens: 1000,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] });
    const model = registry.find('surface-control', 'scripted-control');
    const tools = createMcpAgentTools(manager, ['docs', 'mail'], 16);
    ({ session } = await sdk.createAgentSession({ cwd: config.workspace, agentDir,
      authStorage: auth, settings, modelRegistry: registry, model, getApiKey: async () => 'synthetic-no-provider',
      sessionManager: sdk.SessionManager.inMemory(config.workspace), toolNames: [],
      enableMCP: true, mcpManager: manager, customTools: tools, disableExtensionDiscovery: true,
      enableLsp: false, enableIrc: false, skipPythonPreflight: true,
      skills: [], rules: [], contextFiles: [], promptTemplates: [], slashCommands: [],
      preloadedCustomToolPaths: [], cacheWarming: false }));
    await pinDeclaredToolInventory(session, tools.map(tool => tool.name));
    session.subscribe((event: any) => {
      if (event.type === 'message_end' && event.message?.role === 'toolResult') results.push(event.message);
    });
    session.agent.streamFn = (_model: any, context: any) => {
      assert(streamCalls <= schedule.length, 'scripted stream call bound');
      const step = schedule[streamCalls++];
      providerContexts.push(context.messages.filter((m: any) => m.role === 'toolResult'));
      const message = { role: 'assistant', api: model.api, provider: model.provider, model: model.id,
        timestamp: Date.now(), stopReason: step ? 'toolUse' : 'stop',
        content: step ? [{ type: 'toolCall', id: 'surface-step-' + streamCalls,
          name: step[0], arguments: step[1] }] : [{ type: 'text', text: 'Scripted transport control complete.' }],
        usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } };
      const stream = new AssistantMessageEventStream();
      queueMicrotask(() => { stream.push({ type: 'start', partial: message });
        stream.push({ type: 'done', reason: message.stopReason, message }); });
      return stream;
    };
    await session.prompt('Mechanical control: inspect configured MCP metadata and retrieve the synthetic qualification-rubric context. No user task or efficacy credit.');
    assert.equal(streamCalls, schedule.length + 1); assert.equal(results.length, schedule.length);
    console.log(JSON.stringify({ schema: 'mcp-agent-session-control-result.v1',
      actualSdkSession: true, toolNames: session.getActiveToolNames(), streamCalls, results,
      finalProviderToolContext: providerContexts.at(-1), scripted: true,
      modelExercised: false, guardExercised: false, providerRequests: 0, qualificationEligible: false }));
  } finally {
    try { if (session) await session.dispose(); }
    finally { try { await manager.disconnectAll(); }
      finally { auth.close(); clearTimeout(deadline); } }
  }
}

main().catch(error => { console.error(String(error)); process.exitCode = 1; });
