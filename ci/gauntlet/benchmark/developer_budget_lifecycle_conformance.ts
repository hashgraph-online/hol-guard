/** Locked SDK scheduling fixture: synthetic stream, real read, no provider or Native authority. */
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { DeveloperBudgetStop, installDeveloperBudgetStop, pinDeclaredToolInventory } from './developer_omp_episode.ts';

async function main() {
  const sdkRoot = process.argv[2];
  if (!sdkRoot || !isAbsolute(sdkRoot)) throw new Error('absolute locked SDK root required');
  const metadata = JSON.parse(await readFile(join(sdkRoot, 'package.json'), 'utf8'));
  if (metadata.version !== '18.4.12') throw new Error('locked SDK version differs');
  const sdk = await import(join(sdkRoot, 'src/index.ts'));
  const { AssistantMessageEventStream } = await import(resolve(sdkRoot, '../pi-ai/src/utils/event-stream.ts'));
  const root = await mkdtemp(join(tmpdir(), 'developer-budget-lifecycle-'));
  const cases = [];
  try {
    for (const kind of ['tool-limit', 'token-in-flight', 'hard-deadline']) {
      const workspace = join(root, kind), agentDir = join(workspace, 'agent');
      await mkdir(agentDir, { recursive: true });
      const marker = 'trusted-sdk-read-fixture-' + kind;
      await writeFile(join(workspace, 'input.txt'), marker);
      const auth = await sdk.AuthStorage.create(join(agentDir, 'fixture-auth.db'));
      const settings = await sdk.Settings.init({ cwd: workspace, agentDir, inMemory: true });
      const registry = new sdk.ModelRegistry(auth, join(agentDir, 'models.yml'), { settings });
      registry.registerProvider('lifecycle-fixture', { baseUrl: 'http://127.0.0.1:9/v1',
        api: 'openai-completions', authHeader: false, apiKey: 'fixture-no-auth', models: [{
          id: 'no-provider', name: 'no-provider', reasoning: false, input: ['text'],
          contextWindow: 10000, maxTokens: 1000,
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] });
      const model = registry.find('lifecycle-fixture', 'no-provider');
      const budget = new DeveloperBudgetStop(kind === 'tool-limit' ? 1 : 10, 10);
      const observations: string[] = [];
      let session: any, detach: (() => void) | undefined, timer: ReturnType<typeof setTimeout> | undefined;
      let syntheticStreamCalls = 0, apiKeyRequests = 0, hostGateCalls = 0;
      try {
        ({ session } = await sdk.createAgentSession({ cwd: workspace, agentDir, authStorage: auth,
          settings, modelRegistry: registry, model,
          getApiKey: async () => { apiKeyRequests++; return 'fixture-no-auth'; },
          sessionManager: sdk.SessionManager.inMemory(workspace), toolNames: ['read'], enableMCP: false,
          disableExtensionDiscovery: true, extensions: [(api: any) => {
            api.on('tool_call', () => budget.admitTool());
            api.on('tool_call', async (event: any, ctx: any) => {
              observations.push('admitted:' + event.toolCallId);
              if (kind === 'token-in-flight') budget.observeAssistant({ usage: { totalTokens: 10 } });
              if (kind === 'hard-deadline') {
                timer = setTimeout(() => { budget.hardDeadline(); void session.abort(); }, 15);
                await new Promise<void>(resolveWait => {
                  if (ctx.signal?.aborted) return resolveWait();
                  ctx.signal?.addEventListener('abort', () => resolveWait(), { once: true });
                  setTimeout(resolveWait, 80);
                });
                observations.push('pre-returned-after-cancellation');
              }
            });
            api.on('tool_result', async (event: any) => {
              observations.push('post-start:' + event.toolCallId);
              await new Promise(resolveWait => setTimeout(resolveWait, 20));
              if (!event.content.some((part: any) => part.type === 'text' && part.text.includes(marker))) {
                throw new Error('real SDK read result absent');
              }
              observations.push('post-complete:' + event.toolCallId);
            });
          }], additionalExtensionPaths: [], enableLsp: false, enableIrc: false,
          skipPythonPreflight: true, skills: [], rules: [], contextFiles: [], promptTemplates: [],
          slashCommands: [], preloadedCustomToolPaths: [], cacheWarming: false }));
        await pinDeclaredToolInventory(session, ['read']);
        // A separate host gate must remain installed; budget never replaces it.
        session.agent.setBeforeModelCall(() => { hostGateCalls++; });
        detach = installDeveloperBudgetStop(session, budget);
        session.agent.streamFn = () => {
          if (++syntheticStreamCalls > 1) throw new Error('budget permitted another inference');
          const stream = new AssistantMessageEventStream();
          const message = { role: 'assistant', api: model.api, provider: model.provider, model: model.id,
            timestamp: Date.now(), stopReason: 'toolUse', content: [
              { type: 'toolCall', id: 'first', name: 'read', arguments: { path: join(workspace, 'input.txt') } },
              { type: 'toolCall', id: 'second', name: 'read', arguments: { path: join(workspace, 'input.txt') } }],
            usage: { input: 1, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 1,
              cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } };
          queueMicrotask(() => { stream.push({ type: 'start', partial: message });
            stream.push({ type: 'done', reason: 'toolUse', message }); });
          return stream;
        };
        await session.prompt('SDK scheduling fixture only.');
        // Abort settles the SDK loop before its pending pre callback returns.
        // Drain this fixture's bounded callback too; never hide its missing Post.
        if (kind === 'hard-deadline') await new Promise(resolveWait => setTimeout(resolveWait, 100));
        const soft = kind !== 'hard-deadline';
        if (syntheticStreamCalls !== 1 || !budget.stopped || hostGateCalls < 1
            || !observations.includes('admitted:first') || observations.includes('admitted:second')
            || (soft && !observations.includes('post-complete:first'))
            || (!soft && !budget.hardCancellation)) throw new Error('SDK lifecycle invariant failed: '
              + JSON.stringify({ kind, observations, syntheticStreamCalls, apiKeyRequests, hostGateCalls,
                ...budget.snapshot(), messages: session.agent.state.messages }));
        cases.push({ kind, observations, syntheticStreamCalls, apiKeyRequests, hostGateCalls, ...budget.snapshot() });
      } finally {
        if (timer) clearTimeout(timer);
        detach?.();
        try { if (session) await session.dispose(); } finally { auth.close(); }
      }
    }
    console.log(JSON.stringify({ schema: 'developer-budget-lifecycle-conformance.v1', version: metadata.version,
      cases, uid: process.getuid?.(), actualModelEpisode: false, qualificationEligible: false,
      nativePolicyConformance: false, scope: 'synthetic unit stream; real SDK read/callback ordering only' }));
  } finally { await rm(root, { recursive: true }); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
