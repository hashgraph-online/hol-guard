/** Actual locked SDK projection controls. No model, Guard or task-success credit. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

async function main() {
  assert(process.argv.length === 3 && isAbsolute(process.argv[2]));
  const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
  assert.deepEqual(Object.keys(config).sort(), ['endpoints', 'schema', 'sdkRoot', 'workspace']);
  assert.equal(config.schema, 'mcp-protocol-manager-control.v1');
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
  const notifications: unknown[] = [];
  const unsubscribe = manager.addNotificationListener((server: string, method: string) => {
    notifications.push({ server, method });
  });
  const deadline = setTimeout(() => { console.error('manager control deadline'); process.exit(2); }, 30000);
  const inventory = () => manager.getTools().map((tool: any) => ({
    name: tool.name, server: tool.mcpServerName, rawTool: tool.mcpToolName,
    description: tool.description, parameters: tool.parameters, approval: tool.approval,
  }));
  try {
    await manager.setNotificationsEnabled(true);
    const discovery = await manager.discoverAndConnect({ startupTimeoutMs: 15000 });
    assert.equal(discovery.errors.size, 0);
    assert.deepEqual([...discovery.connectedServers].sort(), ['docs', 'mail']);
    const before = inventory();
    const call = async (family: string, record: string) => {
      const tool = manager.getTools().find((t: any) => t.mcpServerName === family
        && t.mcpToolName === family + '.read');
      assert(tool, 'genuine read tool required');
      return await tool.execute('protocol-control-' + family, { record_id: record }, undefined, {});
    };
    const result = await call('docs', 'qualification-rubric');
    const recovered = result.isError ? await call('docs', 'qualification-rubric') : null;
    // Wait for the manager's actual notification-driven refresh, bounded by the hard deadline.
    const refreshDeadline = Date.now() + 2000;
    while (Date.now() < refreshDeadline && !notifications.length) await Bun.sleep(10);
    const after = inventory();
    const resource = await manager.readServerResource('docs', 'fixture://docs/qualification-rubric');
    await manager.refreshServerPrompts('docs');
    const prompts = manager.getServerPrompts('docs');
    const prompt = await manager.executePrompt('docs', 'workflow_context', { record_id: 'qualification-rubric' });
    const chained = await call('mail', 'lead-a');
    const link = chained.details.rawContent?.find((part: any) => part.type === 'resource_link');
    const linkedResource = link ? await manager.readServerResource('docs', link.uri) : null;
    const reconnected = await manager.reconnectServer('docs');
    assert(reconnected, 'genuine reconnect required');
    const afterReconnect = inventory();
    console.log(JSON.stringify({ schema: 'mcp-protocol-manager-control-result.v1',
      sdkVersion: metadata.version, connected: [...discovery.connectedServers].sort(),
      before, after, afterReconnect, notifications, result, recovered, resource,
      prompts, prompt, chained, linkedResource,
      modelExercised: false, guardExercised: false, providerRequests: 0,
      qualificationEligible: false }));
  } finally {
    unsubscribe();
    try { await manager.disconnectAll(); }
    finally { clearTimeout(deadline); }
  }
}

main().catch(error => { console.error(String(error)); process.exitCode = 1; });
