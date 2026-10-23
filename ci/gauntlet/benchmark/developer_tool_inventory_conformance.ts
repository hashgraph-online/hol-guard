/** Actual locked SDK registration/presentation only: no prompt, model, or tool execution. */
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { tmpdir } from 'node:os';
import { pinDeclaredToolInventory } from './developer_omp_episode.ts';

async function main() {
  const sdkRoot = process.argv[2];
  if (!sdkRoot || !isAbsolute(sdkRoot)) throw new Error('exact absolute installed SDK root required');
  const metadata = JSON.parse(await readFile(join(sdkRoot, 'package.json'), 'utf8'));
  if (metadata.version !== '18.4.12') throw new Error('locked SDK version differs');
  const root = await mkdtemp(join(tmpdir(), 'developer-sdk-inventory-'));
  // These assets contain no candidate code or product configuration.
  const workspace = join(root, 'workspace');
  const agentDir = join(root, 'agent');
  await mkdir(workspace); await mkdir(agentDir);
  const sdk = await import(join(sdkRoot, 'src/index.ts'));
  const { MCPManager } = await import(join(sdkRoot, 'src/mcp/manager.ts'));
  const { MCPTool } = await import(join(sdkRoot, 'src/mcp/tool-bridge.ts'));
  const auth = await sdk.AuthStorage.create(join(agentDir, 'fixture-auth.db'));
  const settings = await sdk.Settings.init({ cwd: workspace, agentDir, inMemory: true });
  const registry = new sdk.ModelRegistry(auth, join(agentDir, 'models.yml'), { settings });
  registry.registerProvider('inventory-fixture', { baseUrl: 'http://127.0.0.1:9/v1', api: 'openai-completions',
    authHeader: false, apiKey: 'fixture-no-auth', models: [{ id: 'registration-only', name: 'registration-only',
      reasoning: false, input: ['text'], contextWindow: 10000, maxTokens: 1000,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] });
  const model = registry.find('inventory-fixture', 'registration-only');
  const manager = new MCPManager(workspace, null, async () => ({ configs: {}, sources: {}, exaApiKeys: [] }));
  // A genuine SDK MCPTool declaration; no connection operation can be executed.
  const resourceTools = MCPTool.fromTools({ name: 'inventory-fixture' }, [{ name: 'docs.read',
    description: 'Registration fixture only', inputSchema: { type: 'object', properties: {} } }]);
  resourceTools[0].execute = () => { throw new Error('registration fixture must never execute a tool'); };
  let session: any;
  let providerCalls = 0;
  let toolCalls = 0;
  try {
    ({ session } = await sdk.createAgentSession({ cwd: workspace, agentDir, authStorage: auth,
      settings, modelRegistry: registry, model, getApiKey: async () => { providerCalls++; throw new Error('no model'); },
      sessionManager: sdk.SessionManager.inMemory(workspace), toolNames: ['read', 'write', 'edit', 'bash'],
      enableMCP: true, mcpManager: manager, customTools: resourceTools, disableExtensionDiscovery: true,
      extensions: [(api: any) => api.on('tool_call', () => { toolCalls++; throw new Error('no tool execution'); })],
      additionalExtensionPaths: [], enableLsp: false, enableIrc: false, skipPythonPreflight: true,
      skills: [], rules: [], contextFiles: [], promptTemplates: [], slashCommands: [],
      preloadedCustomToolPaths: [], cacheWarming: false }));
    const expected = ['read', 'write', 'edit', 'bash', resourceTools[0].name];
    await session.setActiveToolsByName(expected);
    const before = { active: session.getActiveToolNames(), enabled: session.getEnabledToolNames(),
      mounted: session.getMountedXdevToolNames() };
    if (!before.enabled.includes(resourceTools[0].name) || !before.mounted.includes(resourceTools[0].name)
        || before.active.includes(resourceTools[0].name)) throw new Error('locked SDK did not reproduce xd:// partition');
    await pinDeclaredToolInventory(session, expected);
    const after = { active: session.getActiveToolNames(), enabled: session.getEnabledToolNames(),
      mounted: session.getMountedXdevToolNames() };
    let missingRejected = false;
    let missingDiagnostic: any;
    try { await pinDeclaredToolInventory(session, [...expected, 'mcp__missing_unregistered']); }
    catch (error) {
      missingDiagnostic = JSON.parse(String(error).split('transports: ')[1]);
      missingRejected = missingDiagnostic.missing.includes('mcp__missing_unregistered');
    }
    let duplicateRejected = false;
    try { await pinDeclaredToolInventory(session, [...expected, expected[0]]); }
    catch (error) { duplicateRejected = String(error).includes('duplicate declared'); }
    if (!missingRejected || !duplicateRejected || providerCalls !== 0 || toolCalls !== 0) {
      throw new Error('inventory failure/no-execution invariant failed');
    }
    console.log(JSON.stringify({ schema: 'developer-sdk-inventory-conformance.v1', version: metadata.version,
      before, after, missingRejected, missingDiagnostic, duplicateRejected, providerCalls, toolCalls,
      actualModelEpisode: false, qualificationEligible: false,
      scope: 'actual SDK registration in controller process; no agent/product namespace conformance',
      uid: process.getuid?.() }));
  } finally {
    try { if (session) await session.dispose(); }
    finally { try { await manager.disconnectAll(); } finally { auth.close(); await rm(root, { recursive: true }); } }
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
