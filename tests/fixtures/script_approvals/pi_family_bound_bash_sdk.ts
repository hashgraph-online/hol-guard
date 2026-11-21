// Real pinned SDK hooks + Bash tools; no model, account or operator config.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [sdkRoot, configurationPath] = process.argv.slice(2);
const configuration = JSON.parse(readFileSync(configurationPath, "utf8"));
const sdk = join(sdkRoot, "node_modules", configuration.harness === "pi"
  ? "@earendil-works/pi-coding-agent" : "@oh-my-pi/pi-coding-agent");
const version = JSON.parse(readFileSync(join(sdk, "package.json"), "utf8")).version;
if (version !== configuration.expectedVersion) throw Error("unpinned OMP SDK");
const { handlers, bindSession, bindExec } = await import(pathToFileURL(configuration.routingModule).href);
const { execCommand } = await import(pathToFileURL(join(sdk, configuration.harness === "pi"
  ? "dist/core/exec.js" : "src/exec/exec.ts")).href);
const acknowledgements = [];
bindExec(async (command, args, options) => {
  const result = await execCommand(command, args, options?.cwd ?? configuration.workspace, options);
  acknowledgements.push({ code: result.code, stderr: result.stderr?.slice(-1000) });
  return result;
});
const sessionModule = configuration.harness === "pi"
  ? join(sdk, "dist/core/session-manager.js") : join(sdk, "src/session/session-manager.ts");
const { SessionManager } = await import(pathToFileURL(sessionModule).href);
const restarting = existsSync(configuration.sessionFile);
const sessionManager = restarting ? await SessionManager.open(configuration.sessionFile)
  : SessionManager.inMemory(configuration.workspace);
bindSession(sessionManager);
const persistSession = () => writeFileSync(configuration.sessionFile,
  [sessionManager.getHeader(), ...sessionManager.getEntries()].map((entry) => JSON.stringify(entry)).join("\n") + "\n");
async function beginIntent(runner) {
  if (!restarting || configuration.newIntent) {
    await runner.emitInput("Lane-owned SDK user intent", undefined, "interactive");
    sessionManager.appendMessage({ role: "user", content: "Lane-owned SDK user intent", timestamp: Date.now() });
  }
}
async function deliverContext(runner, result, isError = result.isError === true) {
  const message = {role:"toolResult",toolCallId:configuration.callId,toolName:"bash",
    content:result.content,details:result.details,isError,timestamp:Date.now()};
  sessionManager.appendMessage(message);
  await runner.emitContext([message]);
}
const extension = {
  path: configuration.routingModule, resolvedPath: configuration.routingModule, handlers,
  flags: new Map(), commands: new Map(), shortcuts: new Map(), tools: new Map(),
};
if (configuration.harness === "pi") {
  const load = (path: string) => import(pathToFileURL(join(sdk, "dist/core", path)).href);
  const { ExtensionRunner } = await load("extensions/runner.js");
  const { AgentSession } = await load("agent-session.js");
  const { createBashTool } = await load("tools/bash.js");
  const { SettingsManager } = await load("settings-manager.js");
  const runner = new ExtensionRunner([extension], {}, configuration.workspace, sessionManager, {});
  await beginIntent(runner);
  const owner = { agent: {}, _extensionRunner: runner, settingsManager: SettingsManager.inMemory() };
  AgentSession.prototype._installAgentToolHooks.call(owner);
  const args = structuredClone(configuration.input);
  const hook = await owner.agent.beforeToolCall({
    toolCall: { id: configuration.callId, name: "bash" }, args,
  });
  if (hook !== undefined) throw Error("Pi mutation route returned an unexpected decision");
  try {
    let result = await createBashTool(configuration.workspace).execute(configuration.callId, args);
    const hookResult = await owner.agent.afterToolCall({
      toolCall: { id: configuration.callId, name: "bash" }, args, result, isError: false,
    });
    if (hookResult) result = { ...result, ...hookResult };
    await deliverContext(runner, result);
    console.log(JSON.stringify({ version, result, acknowledgements, originalInput: configuration.input }));
  } catch (error) {
    // Match pi-agent-core's createErrorToolResult, then enter the actual
    // AgentSession result hook just as finalizeExecutedToolCall does.
    const result = { content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }], details: {} };
    const hookResult = await owner.agent.afterToolCall({
      toolCall: { id: configuration.callId, name: "bash" }, args, result, isError: true,
    });
    await deliverContext(runner, { ...result, ...hookResult }, true);
    console.log(JSON.stringify({ version, result: { ...result, ...hookResult, isError: true },
      sdkError: String(error), acknowledgements, originalInput: configuration.input }));
  }
  persistSession();
  process.exit(0);
}
const load = (path: string) => import(pathToFileURL(join(sdk, "src", path)).href);
const { Settings, withActiveSettings } = await load("config/settings.ts");
const { ExtensionRunner } = await load("extensibility/extensions/runner.ts");
const { ExtensionToolWrapper } = await load("extensibility/extensions/wrapper.ts");
const { BashTool } = await load("tools/bash.ts");
const settings = Settings.isolated();
const runner = new ExtensionRunner(
  [extension], {}, configuration.workspace, sessionManager, {}, undefined, settings,
);
await beginIntent(runner);
const tool = new BashTool({
  cwd: configuration.workspace, hasUI: false, settings, sessionManager,
  getSessionId: () => sessionManager.getSessionId(), getSessionFile: () => null,
});
const wrapped = new ExtensionToolWrapper(tool, runner);
const result = await withActiveSettings(settings, () => wrapped.execute(
  configuration.callId, configuration.input, undefined, undefined, { settings },
));
await deliverContext(runner, result);
console.log(JSON.stringify({ version, result, acknowledgements, originalInput: configuration.input }));
await runner.shutdown();
persistSession();
