/** Actual OMP18.4.12 developer session. No oracle or scripted tool replay. */
import { isAbsolute, join } from 'node:path';
import { mkdir, readFile } from 'node:fs/promises';
import { createConnection } from 'node:net';

type Config = {
  schema: 'developer-omp-episode.v1' | 'developer-omp-episode.v2'; sdkRoot: string; workspace: string; agentDir: string;
  mcpAgentSurfaces?: 'mcp-agent-surfaces.v1';
  modelId: string; prompt: string; deadlineSeconds: number; maxToolCalls: number;
  maxModelTokens: number; guardExtension?: string; sdkGate?: string;
  resourceEndpoints?: Record<string, any>;
};
const emit = (value: unknown) => process.stdout.write(JSON.stringify(value) + '\n');

/** SDK-local scheduling only; independent controller accounting remains authoritative. */
export class DeveloperBudgetStop {
  toolCalls = 0;
  modelTokens = 0;
  usageKnown = true;
  stopReason: string | undefined;
  hardCancellation = false;
  constructor(readonly maxToolCalls: number, readonly maxModelTokens: number) {}
  get stopped() { return this.stopReason !== undefined; }
  admitTool() {
    if (this.stopped) return { block: true, reason: 'developer episode budget exhausted before execution' };
    if (++this.toolCalls >= this.maxToolCalls) this.stopReason = 'tool-budget';
    // The last admitted call must complete its normal backend/output review.
    return undefined;
  }
  observeAssistant(message: any) {
    const tokens = message.usage?.totalTokens;
    if (!Number.isInteger(tokens) || tokens < 1) this.usageKnown = false;
    else this.modelTokens += tokens;
    if (!this.usageKnown) this.stopReason ??= 'unknown-usage';
    else if (this.modelTokens >= this.maxModelTokens) this.stopReason ??= 'token-budget';
  }
  beforeModelCall() {
    return this.stopped ? { stop: true, reason: 'developer episode ' + this.stopReason } : undefined;
  }
  hardDeadline() { this.hardCancellation = true; this.stopReason = 'hard-deadline'; }
  snapshot() {
    return { toolCalls: this.toolCalls, modelTokens: this.modelTokens, usageKnown: this.usageKnown,
      budgetStopReason: this.stopReason ?? null, hardCancellation: this.hardCancellation };
  }
}

export function installDeveloperBudgetStop(session: any, budget: DeveloperBudgetStop) {
  const detachGate = session.agent.addBeforeModelCall(() => budget.beforeModelCall());
  const detachMessages = session.subscribe((event: any) => {
    if (event.type === 'message_end' && event.message?.role === 'assistant') budget.observeAssistant(event.message);
  });
  return () => { detachMessages(); detachGate(); };
}

export async function pinDeclaredToolInventory(session: any, names: string[]) {
  const expected = [...names].sort();
  if (new Set(expected).size !== expected.length) throw new Error('duplicate declared developer tool names');
  // OMP18.4.12's name-only setter retains existing xd:// mounts. Select the
  // exact public top-level partition instead; every declared MCP tool remains
  // enabled through its genuine manager transport and normal extension hooks.
  await session.setActiveToolPresentation(names, []);
  const actual = [...session.getActiveToolNames()].sort();
  const enabled = [...session.getEnabledToolNames()].sort();
  const mounted = [...session.getMountedXdevToolNames()].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected) || JSON.stringify(enabled) !== JSON.stringify(expected)
      || mounted.length !== 0) {
    throw new Error('actual developer tool inventory differs from declared transports: ' + JSON.stringify({
      expected, actual, enabled, mounted,
      missing: expected.filter(name => !actual.includes(name)),
      unexpected: actual.filter(name => !expected.includes(name)),
    }));
  }
}

async function awaitControllerBinding(path: string) {
  await new Promise<void>((resolve, reject) => {
    const socket = createConnection(path);
    let response = '';
    socket.setTimeout(30000, () => socket.destroy(new Error('controller SDK binding timed out')));
    socket.on('error', reject);
    socket.on('connect', () => socket.write('developer-sdk-ready.v1\n'));
    socket.on('data', (data) => {
      response += data.toString('utf8');
      if (response.length > 128) socket.destroy(new Error('invalid controller binding response'));
      if (response.includes('\n')) {
        if (response !== 'developer-sdk-bound.v1\n') socket.destroy(new Error('controller did not bind SDK'));
        else { socket.end(); resolve(); }
      }
    });
    socket.on('end', () => {
      if (response !== 'developer-sdk-bound.v1\n') reject(new Error('controller binding disconnected'));
    });
  });
}

async function main() {
  if (process.argv.length !== 3 || !isAbsolute(process.argv[2]) || process.platform !== 'linux') {
    throw new Error('requires isolated Linux runtime and absolute public configuration');
  }
  const config: Config = JSON.parse(await readFile(process.argv[2], 'utf8'));
  if (!['developer-omp-episode.v1', 'developer-omp-episode.v2'].includes(config.schema)
      || (config.schema === 'developer-omp-episode.v2'
        ? config.mcpAgentSurfaces !== 'mcp-agent-surfaces.v1' : config.mcpAgentSurfaces !== undefined)
      || !config.prompt || !config.modelId) {
    throw new Error('invalid developer episode');
  }
  for (const key of ['sdkRoot', 'workspace', 'agentDir'] as const) {
    if (!isAbsolute(config[key])) throw new Error('episode paths must be absolute');
  }
  if (config.guardExtension && !isAbsolute(config.guardExtension)) throw new Error('invalid Guard extension path');
  if (config.sdkGate) {
    if (!config.guardExtension || config.sdkGate !== '/runtime/sdk-gate/ready.sock') {
      throw new Error('invalid protected SDK binding transport');
    }
    await awaitControllerBinding(config.sdkGate);
  }
  if (!Number.isInteger(config.deadlineSeconds) || config.deadlineSeconds < 1 || config.deadlineSeconds > 900
      || !Number.isInteger(config.maxToolCalls) || config.maxToolCalls < 1 || config.maxToolCalls > 200
      || !Number.isInteger(config.maxModelTokens) || config.maxModelTokens < 1 || config.maxModelTokens > 100000) {
    throw new Error('invalid developer budgets');
  }
  const metadata = JSON.parse(await readFile(join(config.sdkRoot, 'package.json'), 'utf8'));
  if (metadata.version !== '18.4.12') throw new Error('actual OMP version mismatch');
  await mkdir(config.agentDir, { recursive: true, mode: 0o700 });
  const sdk = await import(join(config.sdkRoot, 'src/index.ts'));
  const auth = await sdk.AuthStorage.create(join(config.agentDir, 'benchmark-auth.db'));
  const settings = await sdk.Settings.init({ cwd: config.workspace, agentDir: config.agentDir, inMemory: true });
  // Native contained execution can run for 300s plus controller capture and
  // cleanup. OMP's default 30s tool_call cap otherwise aborts the Guard hook
  // while the verified product command is still running.
  const { cfgExtensionHandlersToolCallTimeoutMs } =
    await import(join(config.sdkRoot, 'src/extensibility/settings.ts'));
  cfgExtensionHandlersToolCallTimeoutMs.override(settings, 380_000);
  if (cfgExtensionHandlersToolCallTimeoutMs.get(settings) !== 380_000) {
    throw new Error('actual OMP tool_call timeout differs from contained execution budget');
  }
  // The SDK otherwise backgrounds a long Bash call while NativeHook is still
  // executing it. The next model turn can then outlive the private hook plane
  // without the mandatory native Post receipt. Keep each call foregrounded.
  const { cfgBashAutoBackgroundEnabled } =
    await import(join(config.sdkRoot, 'src/exec/settings.ts'));
  const { cfgAsyncEnabled } = await import(join(config.sdkRoot, 'src/tools/settings.ts'));
  cfgBashAutoBackgroundEnabled.override(settings, false);
  cfgAsyncEnabled.override(settings, false);
  if (cfgBashAutoBackgroundEnabled.get(settings) !== false || cfgAsyncEnabled.get(settings) !== false) {
    throw new Error('actual OMP Bash execution must remain foregrounded for native Post review');
  }
  const registry = new sdk.ModelRegistry(auth, join(config.agentDir, 'models.yml'), { settings });
  registry.registerProvider('benchmark-local', {
    baseUrl: 'http://127.0.0.1:8001/v1', api: 'openai-completions', authHeader: false,
    apiKey: 'benchmark-no-auth', models: [{ id: config.modelId, name: config.modelId, reasoning: false,
      supportsTools: true, input: ['text'], contextWindow: 32768, maxTokens: 8192,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }],
  });
  const model = registry.find('benchmark-local', config.modelId);
  if (!model) throw new Error('declared local model unavailable');
  const toolNames = ['read', 'write', 'edit', 'bash'];
  let manager: any;
  let resourceTools: any[] = [];
  let session: any; let timer: ReturnType<typeof setTimeout> | undefined;
  const budget = new DeveloperBudgetStop(config.maxToolCalls, config.maxModelTokens);
  let detachBudgetGate: (() => void) | undefined;
  const started = Date.now();
  try {
    if (config.resourceEndpoints) {
      const { MCPManager } = await import(join(config.sdkRoot, 'src/mcp/manager.ts'));
      manager = new MCPManager(config.workspace, null, async () => ({
        configs: config.resourceEndpoints, sources: {}, exaApiKeys: [],
      }));
      const connection = await manager.discoverAndConnect({ startupTimeoutMs: 30000 });
      if (connection.errors.size || JSON.stringify([...connection.connectedServers].sort())
          !== JSON.stringify(Object.keys(config.resourceEndpoints).sort())) {
        throw new Error('declared developer resource transport failed to connect');
      }
      resourceTools = config.mcpAgentSurfaces
        ? (await import('./mcp_agent_surfaces')).createMcpAgentTools(manager, Object.keys(config.resourceEndpoints), config.maxToolCalls)
        : manager.getTools();
      if (config.mcpAgentSurfaces) manager.setNotificationsEnabled(true);
      if (!resourceTools.length) throw new Error('developer resources exposed no actual MCP tools');
    }
    const budgets = (api: any) => {
      api.on('tool_call', () => budget.admitTool());
    };
    ({ session } = await sdk.createAgentSession({
      cwd: config.workspace, agentDir: config.agentDir, authStorage: auth,
      settings, modelRegistry: registry, model, getApiKey: async () => 'benchmark-no-auth',
      sessionManager: sdk.SessionManager.inMemory(config.workspace), toolNames,
      enableMCP: Boolean(manager), mcpManager: manager, customTools: resourceTools,
      disableExtensionDiscovery: true, extensions: [budgets],
      additionalExtensionPaths: config.guardExtension ? [config.guardExtension] : [],
      enableLsp: false, enableIrc: false, skipPythonPreflight: true,
      skills: [], rules: [], contextFiles: [], promptTemplates: [], slashCommands: [],
      preloadedCustomToolPaths: [], cacheWarming: false,
      deadline: started + config.deadlineSeconds * 1000,
    }));
    const activeNames = [...toolNames, ...resourceTools.map((tool: any) => tool.name)];
    await pinDeclaredToolInventory(session, activeNames);
    if (config.mcpAgentSurfaces && manager) {
      manager.setOnToolsChanged(async () => { await pinDeclaredToolInventory(session, activeNames); });
    }
    // Add, never replace, the SDK/host gates. A soft stop must not abort a
    // tool already admitted while its Native PostToolUse review is pending.
    detachBudgetGate = installDeveloperBudgetStop(session, budget);
    emit({ type: 'episode_start', harness: 'omp', version: metadata.version, model: config.modelId,
      activeTools: session.getActiveToolNames(), guardExtensionAttached: Boolean(config.guardExtension),
      resourceTools: resourceTools.map((tool: any) => ({ name: tool.name,
        server: tool.mcpServerName, rawTool: tool.mcpToolName })),
      agentUid: process.getuid?.(), qualification: false });
    session.subscribe((event: any) => {
      if (event.type !== 'message_update') emit({ type: 'agent_event', event });
    });
    timer = setTimeout(() => {
      budget.hardDeadline();
      void session.abort().catch((error: unknown) => {
        emit({ type: 'budget_cancellation_error', error: String(error), ...budget.snapshot(), qualification: false });
        process.exitCode = 1;
      });
    },
      Math.max(1, started + config.deadlineSeconds * 1000 - Date.now()));
    emit({ type: 'inference_start' });
    await session.prompt(config.prompt);
    emit({ type: 'episode_end', status: budget.stopped ? 'budget-exhausted' : 'finished',
      ...budget.snapshot(), durationMs: Date.now() - started, qualification: false });
  } catch (error) {
    emit({ type: 'episode_error', error: String(error), ...budget.snapshot(), qualification: false });
    process.exitCode = 1;
  } finally {
    if (timer) clearTimeout(timer);
    detachBudgetGate?.();
    try { if (session) await session.dispose(); } finally {
      try { if (manager) await manager.disconnectAll(); } finally { auth.close(); }
    }
  }
}
if (import.meta.main) {
  main().catch(error => { emit({ type: 'episode_error', error: String(error), qualification: false }); process.exitCode = 1; });
}
