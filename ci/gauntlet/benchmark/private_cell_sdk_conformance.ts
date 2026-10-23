/** Real locked SDK + normal Guard bridge, synthetic stream; zero model episodes. */
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createConnection } from 'node:net';
import { pinDeclaredToolInventory } from './developer_omp_episode.ts';

async function bind() {
  await new Promise<void>((done, reject) => {
    const socket = createConnection('/runtime/sdk-gate/ready.sock');
    let response = '';
    socket.setTimeout(30000, () => socket.destroy(new Error('SDK binding deadline')));
    socket.on('error', reject);
    socket.on('connect', () => socket.write('developer-sdk-ready.v1\n'));
    socket.on('data', chunk => {
      response += chunk.toString();
      if (response.length > 128) return socket.destroy(new Error('SDK binding byte budget'));
      if (response === 'developer-sdk-bound.v1\n') { socket.end(); done(); }
    });
    socket.on('end', () => {
      if (response !== 'developer-sdk-bound.v1\n') reject(new Error('incomplete SDK binding'));
    });
  });
}

async function main() {
  const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
  const agentSurfaces = config.schema === 'private-cell-sdk-conformance.v5';
  if ((agentSurfaces && config.mcpAgentSurfaces !== 'mcp-agent-surfaces.v1')
      || (!agentSurfaces && config.mcpAgentSurfaces !== undefined)) {
    throw new Error('agent-surface control requires the explicit v5 profile');
  }
  const withMcp = ['private-cell-sdk-conformance.v2', 'private-cell-sdk-conformance.v3',
    'private-cell-sdk-conformance.v4', 'private-cell-sdk-conformance.v5'].includes(config.schema);
  const command = ['private-cell-sdk-conformance.v3', 'private-cell-sdk-conformance.v5'].includes(config.schema)
    ? '/usr/bin/node --test tests/node-control.test.cjs'
    : config.schema === 'private-cell-sdk-conformance.v4'
      ? 'python3 -m unittest discover -s tests -v 2>&1' : 'python3 -m unittest discover -s tests -v';
  if ((!withMcp && config.schema !== 'private-cell-sdk-conformance.v1')
      || config.workspace !== '/runtime/home/project'
      || config.command !== command) throw new Error('fixed conformance config required');
  if (withMcp && JSON.stringify(Object.keys(config.resourceEndpoints ?? {}).sort()) !== '["docs","mail"]') {
    throw new Error('exact declared docs/mail transports required');
  }
  if (!withMcp && config.resourceEndpoints) throw new Error('MCP requires the explicit v2 control');
  await bind(); // Controller authenticates this exact Bun process before SDK import.
  const sdk = await import(join(config.sdkRoot, 'src/index.ts'));
  const metadata = JSON.parse(await readFile(join(config.sdkRoot, 'package.json'), 'utf8'));
  if (metadata.version !== '18.4.12') throw new Error('exact SDK version required');
  const { AssistantMessageEventStream } = await import(resolve(config.sdkRoot, '../pi-ai/src/utils/event-stream.ts'));
  const auth = await sdk.AuthStorage.create('/runtime/agent/auth.db');
  let session: any, manager: any, calls = 0;
  let resourceTools: any[] = [], readTool: any;
  const expectedCalls = withMcp ? 3 : 2;
  const events: any[] = [];
  let projectedOriginalCommand = false, storedExecutionTransport = false;
  try {
    const settings = await sdk.Settings.init({ cwd: config.workspace, agentDir: '/runtime/agent', inMemory: true });
    const registry = new sdk.ModelRegistry(auth, '/runtime/agent/models.yml', { settings });
    registry.registerProvider('conformance-only', { baseUrl: 'http://127.0.0.1:9/v1',
      api: 'openai-completions', authHeader: false, apiKey: 'synthetic-no-provider', models: [{
        id: 'synthetic-stream', name: 'synthetic-stream', reasoning: false, input: ['text'],
        contextWindow: 10000, maxTokens: 1000, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] });
    const model = registry.find('conformance-only', 'synthetic-stream');
    if (withMcp) {
      const { MCPManager } = await import(join(config.sdkRoot, 'src/mcp/manager.ts'));
      manager = new MCPManager(config.workspace, null, async () => ({
        configs: config.resourceEndpoints, sources: {}, exaApiKeys: [],
      }));
      const connected = await manager.discoverAndConnect({ startupTimeoutMs: 30000 });
      if (connected.errors.size || JSON.stringify([...connected.connectedServers].sort()) !== '["docs","mail"]') {
        throw new Error('declared MCP control transports did not connect');
      }
      resourceTools = agentSurfaces
        ? (await import('./mcp_agent_surfaces.ts')).createMcpAgentTools(manager, ['docs', 'mail'], 4)
        : manager.getTools();
      if (agentSurfaces) manager.setNotificationsEnabled(true);
      readTool = resourceTools.find((tool: any) => agentSurfaces ? tool.name === 'mcp_call_tool'
        : tool.mcpServerName === 'docs' && tool.mcpToolName === 'docs.read');
      if (!readTool) throw new Error('actual delegated docs.read MCP tool missing');
    }
    ({ session } = await sdk.createAgentSession({ cwd: config.workspace, agentDir: '/runtime/agent',
      authStorage: auth, settings, modelRegistry: registry, model,
      getApiKey: async () => 'synthetic-no-provider', sessionManager: sdk.SessionManager.inMemory(config.workspace),
      toolNames: ['bash'], enableMCP: withMcp, mcpManager: manager, customTools: resourceTools,
      disableExtensionDiscovery: true,
      additionalExtensionPaths: ['/runtime/public/builtin_guard_bridge.ts'], enableLsp: false, enableIrc: false,
      skipPythonPreflight: true, skills: [], rules: [], contextFiles: [], promptTemplates: [], slashCommands: [],
      preloadedCustomToolPaths: [], cacheWarming: false }));
    await pinDeclaredToolInventory(session, ['bash', ...resourceTools.map((tool: any) => tool.name)]);
    session.subscribe((event: any) => {
      if (event.type === 'message_end' && event.message?.role === 'toolResult') events.push(event.message);
    });
    session.agent.streamFn = (_model: any, context: any) => {
      if (++calls > expectedCalls) throw new Error('synthetic stream call budget exhausted');
      if (calls === expectedCalls) {
        const commandIn = (messages: any[]) => messages.filter(message => message.role === 'assistant')
          .flatMap(message => message.content ?? []).find(block => block.type === 'toolCall'
            && block.name === 'bash' && block.id === 'sdk-contained-control')?.arguments?.command;
        projectedOriginalCommand = commandIn(context.messages) === config.command;
        storedExecutionTransport = String(commandIn(session.agent.state.messages))
          .startsWith('/usr/bin/python3 /runtime/public/contained_exec_relay.py --token ');
        if (!projectedOriginalCommand || !storedExecutionTransport) {
          throw new Error('SDK provider context must restore reviewed command and retain execution transport');
        }
      }
      const stream = new AssistantMessageEventStream();
      const content = withMcp && calls === 1
        ? [{ type: 'toolCall', id: 'sdk-mcp-control', name: readTool.name, arguments: agentSurfaces
          ? { server: 'docs', tool: 'docs.read', arguments: { record_id: 'developer-spec' } }
          : { record_id: 'developer-spec' } }]
        : calls === expectedCalls - 1
          ? [{ type: 'toolCall', id: 'sdk-contained-control', name: 'bash', arguments: { command: config.command } }]
          : [{ type: 'text', text: 'Synthetic conformance stream finished.' }];
      const message = { role: 'assistant', api: model.api, provider: model.provider, model: model.id,
        timestamp: Date.now(), stopReason: calls < expectedCalls ? 'toolUse' : 'stop', content,
        usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } };
      queueMicrotask(() => { stream.push({ type: 'start', partial: message });
        stream.push({ type: 'done', reason: message.stopReason, message }); });
      return stream;
    };
    const timer = setTimeout(() => { void session.abort(); }, 90000);
    try { await session.prompt(config.prompt); } finally { clearTimeout(timer); }
    if (calls !== expectedCalls || events.length !== expectedCalls - 1) throw new Error('SDK call/result lifecycle differed');
    console.log(JSON.stringify({ schema: 'private-cell-sdk-conformance-result.v1', version: metadata.version,
      uid: process.getuid?.(), syntheticStreamCalls: calls, results: events,
      modelContextProjection: { schema: 'contained-command-context-control.v1',
        originalCommandVisible: projectedOriginalCommand, executionTransportRetained: storedExecutionTransport,
        scope: 'actual SDK synthetic-stream control; no model inference' },
      ...(agentSurfaces ? { mcpAgentSurfaces: config.mcpAgentSurfaces } : {}),
      mcpExercised: withMcp, resourceTools: resourceTools.map((tool: any) => ({
        name: tool.name, server: tool.mcpServerName, rawTool: tool.mcpToolName })),
      modelExercised: false, providerRequests: 0, qualificationEligible: false }));
  } finally {
    try { if (session) await session.dispose(); } finally {
      try { if (manager) await manager.disconnectAll(); } finally { auth.close(); }
    }
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
