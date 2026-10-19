/** Actual locked SDK discovery only: no model registry, prompt or inference. */
import { isAbsolute, join } from 'node:path';
import { readFile } from 'node:fs/promises';

async function main() {
  if (process.argv.length !== 3 || !isAbsolute(process.argv[2])) {
    throw new Error('absolute startup-control configuration required');
  }
  const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
  const profiles: Record<string, string[]> = {
    'business-sdk-startup-control.v1': ['crm', 'docs', 'mail', 'tables'],
    'business-sdk-startup-control.v2': ['calendar', 'chat', 'crm', 'docs', 'mail', 'tables', 'tickets'],
  };
  const families = profiles[config.schema];
  if (!families || !isAbsolute(config.sdkRoot) || config.workspace !== '/runtime/home/project'
      || JSON.stringify(Object.keys(config.endpoints).sort())
         !== JSON.stringify(families)) {
    throw new Error('exact declared-family discovery control required');
  }
  for (const endpoint of Object.values(config.endpoints) as any[]) {
    if (endpoint.type !== 'stdio' || endpoint.command !== '/usr/bin/python3'
        || endpoint.envPolicy !== 'literal' || endpoint.requestIdFormat !== 'string'
        || endpoint.cwd !== config.workspace || endpoint.instructions !== false) {
      throw new Error('ordinary explicit MCP transport required');
    }
  }
  const metadata = JSON.parse(await readFile(join(config.sdkRoot, 'package.json'), 'utf8'));
  if (metadata.version !== '18.4.12') throw new Error('locked SDK required');
  const { MCPManager } = await import(join(config.sdkRoot, 'src/mcp/manager.ts'));
  const manager = new MCPManager(config.workspace, null, async () => ({
    configs: config.endpoints, sources: {}, exaApiKeys: [],
  }));
  const statuses: unknown[] = [];
  const started = Date.now();
  try {
    const result = await manager.discoverAndConnect({ startupTimeoutMs: 30000,
      onStatus: (status: unknown) => statuses.push(status) });
    const connected = [...result.connectedServers].sort();
    if (result.errors.size || JSON.stringify(connected) !== JSON.stringify(families)) {
      throw new Error('actual SDK discovery failed: ' + JSON.stringify(statuses));
    }
    const tools = manager.getTools();
    if (!tools.length) throw new Error('actual MCP tools missing');
    console.log(JSON.stringify({ schema: 'business-sdk-startup-control-result.v1',
      sdkVersion: metadata.version, connected, statuses,
      tools: tools.map((tool: any) => ({ name: tool.name,
        server: tool.mcpServerName, rawTool: tool.mcpToolName })),
      elapsedMs: Date.now() - started, modelExercised: false,
      providerRequests: 0, qualificationEligible: false }));
  } finally {
    await manager.disconnectAll();
  }
}

main().catch(error => { console.error(String(error)); process.exitCode = 1; });
