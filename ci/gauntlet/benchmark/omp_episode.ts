/** Actual OMP 18.4.12 session over declared MCP endpoints.
 * Receives public configuration only. The controller owns receipts and scoring.
 * This runner alone never qualifies a campaign or asserts Guard attribution.
 */
import { isAbsolute, join } from 'node:path';
import { mkdir, readFile } from 'node:fs/promises';
import { BUSINESS_PROTOCOL_PROFILE, runBusinessPrompt } from './business_protocol_recovery';

type Config = {
  schema: 'gauntlet-omp-episode.v1' | 'gauntlet-omp-episode.v2';
  mcpAgentSurfaces?: 'mcp-agent-surfaces.v1';
  sdkRoot: string;
  workspace: string;
  agentDir: string;
  modelId: string;
  baseUrl: string;
  prompt: string;
  deadlineSeconds: number;
  maxToolCalls: number;
  maxModelTokens?: number;
  endpoints: Record<string, {
    type: 'stdio'; command: string; args: string[]; env: Record<string, string>;
    envPolicy: 'literal'; cwd: string; timeout: number;
    requestIdFormat: 'string'; instructions: false;
  }>;
};

function emit(value: unknown) {
  process.stdout.write(JSON.stringify(value) + '\n');
}

function validate(config: Config) {
  if (!['gauntlet-omp-episode.v1', 'gauntlet-omp-episode.v2'].includes(config.schema)
      || (config.schema === 'gauntlet-omp-episode.v2'
        ? config.mcpAgentSurfaces !== 'mcp-agent-surfaces.v1' : config.mcpAgentSurfaces !== undefined)) {
    throw new Error('invalid versioned episode schema/profile');
  }
  for (const key of ['sdkRoot', 'workspace', 'agentDir'] as const) {
    if (!isAbsolute(config[key])) throw new Error(`${key} must be absolute`);
  }
  const url = new URL(config.baseUrl);
  if (!['127.0.0.1', 'localhost', 'host.lima.internal'].includes(url.hostname)
      || url.username || url.password || url.protocol !== 'http:') {
    throw new Error('pilot accepts credential-free local model endpoints only');
  }
  if (!Number.isInteger(config.deadlineSeconds) || config.deadlineSeconds < 1
      || config.deadlineSeconds > 1800 || !Number.isInteger(config.maxToolCalls)
      || config.maxToolCalls < 1 || config.maxToolCalls > 500) {
    throw new Error('invalid episode budgets');
  }
  if (config.maxModelTokens !== undefined && (!Number.isInteger(config.maxModelTokens)
      || config.maxModelTokens < 1 || config.maxModelTokens > 1000000)) {
    throw new Error('invalid total model token budget');
  }
  if (!config.prompt || !config.modelId || !Object.keys(config.endpoints).length) {
    throw new Error('episode needs a task, model and endpoints');
  }
  for (const endpoint of Object.values(config.endpoints)) {
    if (endpoint.type !== 'stdio' || !isAbsolute(endpoint.command)
        || endpoint.envPolicy !== 'literal' || endpoint.requestIdFormat !== 'string'
        || endpoint.instructions !== false || endpoint.cwd !== config.workspace) {
      throw new Error('endpoint must use explicit isolated stdio configuration');
    }
  }
}

async function main() {
  if (process.argv.length !== 3 || !isAbsolute(process.argv[2])) {
    throw new Error('usage: bun omp_episode.ts /absolute/public-episode.json');
  }
  const config: Config = JSON.parse(await readFile(process.argv[2], 'utf8'));
  validate(config);
  const metadata = JSON.parse(await readFile(join(config.sdkRoot, 'package.json'), 'utf8'));
  if (metadata.version !== '18.4.12') throw new Error('OMP version mismatch');
  await mkdir(config.agentDir, { recursive: true, mode: 0o700 });
  const sdk = await import(join(config.sdkRoot, 'src/index.ts'));
  const { MCPManager } = await import(join(config.sdkRoot, 'src/mcp/manager.ts'));
  const auth = await sdk.AuthStorage.create(join(config.agentDir, 'benchmark-auth.db'));
  const settings = await sdk.Settings.init({ cwd: config.workspace,
    agentDir: config.agentDir, inMemory: true });
  const registry = new sdk.ModelRegistry(auth, join(config.agentDir, 'models.yml'), { settings });
  registry.registerProvider('benchmark-local', {
    baseUrl: config.baseUrl, api: 'openai-completions', authHeader: false,
    // A local synthetic placeholder, never an operator credential.
    apiKey: 'benchmark-no-auth',
    models: [{ id: config.modelId, name: config.modelId, reasoning: false,
      supportsTools: true, input: ['text'], contextWindow: 32768, maxTokens: 8192,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }],
  });
  const model = registry.find('benchmark-local', config.modelId);
  if (!model) throw new Error('declared local model unavailable');
  const manager = new MCPManager(config.workspace, null, async () => ({
    configs: config.endpoints, sources: {}, exaApiKeys: [],
  }));
  let session: any;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let toolCalls = 0;
  let budgetExceeded = false;
  let modelTokens = 0;
  let modelUsageKnown = true;
  let refreshFailed = false;
  let inferenceStarted = false;
  let lastAssistant: any;
  const started = Date.now();
  try {
    const connection = await manager.discoverAndConnect({ startupTimeoutMs: 30000,
      onStatus: (status: unknown) => emit({ type: 'mcp_status', status }) });
    if (connection.errors.size) throw new Error('MCP endpoint connection failed');
    const connected = [...connection.connectedServers].sort();
    if (JSON.stringify(connected) !== JSON.stringify(Object.keys(config.endpoints).sort())) {
      throw new Error('declared MCP endpoint did not finish connecting');
    }
    const budgetTools = (actualTools: any[]) => actualTools.map((tool: any) => new Proxy(tool, {
      get(target, property, receiver) {
        if (property !== 'execute') return Reflect.get(target, property, receiver);
        return (...args: any[]) => {
          if (budgetExceeded || ++toolCalls > config.maxToolCalls) {
            budgetExceeded = true;
            throw new Error('episode tool budget exhausted before forwarding');
          }
          return target.execute.apply(target, args);
        };
      },
    }));
    const declaredTools = config.mcpAgentSurfaces
      ? (await import('./mcp_agent_surfaces')).createMcpAgentTools(manager, Object.keys(config.endpoints), config.maxToolCalls)
      : manager.getTools();
    if (config.mcpAgentSurfaces) manager.setNotificationsEnabled(true);
    const tools = budgetTools(declaredTools);
    if (!tools.length) throw new Error('no actual MCP tools discovered');
    ({ session } = await sdk.createAgentSession({
      cwd: config.workspace, agentDir: config.agentDir, authStorage: auth,
      settings, modelRegistry: registry, model, getApiKey: async () => 'benchmark-no-auth',
      sessionManager: sdk.SessionManager.inMemory(config.workspace),
      enableMCP: true, mcpManager: manager, customTools: tools,
      disableExtensionDiscovery: true, enableLsp: false, enableIrc: false,
      skipPythonPreflight: true, skills: [], rules: [], contextFiles: [],
      promptTemplates: [], slashCommands: [], preloadedCustomToolPaths: [],
      cacheWarming: false, deadline: started + config.deadlineSeconds * 1000,
    }));
    const names = tools.map((tool: any) => tool.name);
    await session.setActiveToolsByName(names);
    if (JSON.stringify([...session.getActiveToolNames()].sort()) !== JSON.stringify([...names].sort())) {
      throw new Error('business episode active tools differ from declared MCP tools');
    }
    manager.setOnToolsChanged(async (actualTools: any[]) => {
      try {
        const refreshed = config.mcpAgentSurfaces ? tools : budgetTools(actualTools);
        if (config.mcpAgentSurfaces) {
          await session.setActiveToolPresentation(names, []);
        } else {
          await session.refreshMCPTools(refreshed);
          await session.setActiveToolsByName(refreshed.map((tool: any) => tool.name));
        }
        emit({ type: 'mcp_tools_changed', tools: refreshed.map((tool: any) => ({
          name: tool.name, server: tool.mcpServerName, rawTool: tool.mcpToolName })) });
      } catch (error) {
        refreshFailed = true;
        emit({ type: 'episode_error', error: String(error), phase: 'tool-refresh',
          retryableInfrastructure: false, qualification: false });
        await session.abort();
      }
    });
    emit({ type: 'episode_start', harness: 'omp', version: metadata.version,
      modelProtocolProfile: BUSINESS_PROTOCOL_PROFILE,
      model: config.modelId, tools: tools.map((tool: any) => ({ name: tool.name,
        server: tool.mcpServerName, rawTool: tool.mcpToolName })), qualification: false });
    session.subscribe((event: any) => {
      // Retain complete messages and tool events. Streaming partial messages
      // duplicate increasingly large transcripts without adding custody proof.
      if (event.type !== 'message_update') emit({ type: 'agent_event', event });
      if (event.type === 'message_end' && event.message?.role === 'assistant') {
        lastAssistant = event.message;
        const used = event.message.usage?.totalTokens;
        if (!Number.isInteger(used) || used <= 0) modelUsageKnown = false;
        else modelTokens += used;
        if (config.maxModelTokens !== undefined
            && (!modelUsageKnown || modelTokens >= config.maxModelTokens)) {
          budgetExceeded = true;
          void session.abort();
        }
      }
    });
    timer = setTimeout(() => { budgetExceeded = true; void session.abort(); },
      Math.max(1, started + config.deadlineSeconds * 1000 - Date.now()));
    inferenceStarted = true;
    emit({ type: 'inference_start' });
    const protocol = await runBusinessPrompt({
      prompt: async text => { lastAssistant = undefined; return session.prompt(text); },
      initialPrompt: config.prompt, lastAssistant: () => lastAssistant,
      stopped: () => budgetExceeded || refreshFailed, emit,
    });
    emit({ type: 'episode_end', status: budgetExceeded ? 'budget-exhausted'
        : protocol.unresolved ? 'model-protocol-unresolved' : 'finished',
      modelProtocolRecoveries: protocol.recoveries,
      toolCalls, modelTokens, modelUsageKnown, refreshFailed,
      durationMs: Date.now() - started, qualification: false });
  } catch (error) {
    emit({ type: 'episode_error', error: String(error),
      phase: inferenceStarted ? 'inference' : 'startup',
      retryableInfrastructure: !inferenceStarted && (
        String(error) === 'Error: MCP endpoint connection failed'
        || String(error) === 'Error: declared MCP endpoint did not finish connecting'),
      qualification: false });
    process.exitCode = 1;
  } finally {
    if (timer) clearTimeout(timer);
    try {
      if (session) await session.dispose();
    } finally {
      try { await manager.disconnectAll(); } finally { auth.close(); }
    }
  }
}

main().catch(error => {
  emit({ type: 'episode_error', error: String(error), qualification: false });
  process.exitCode = 1;
});
