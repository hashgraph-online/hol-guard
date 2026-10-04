// Watch is recording-only. This fixture scope prevents model substitutions from executing.
export const WATCH_COMMAND = `python -I -S -c 'print("ordinary-watch-fixture")'`;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function permittedWatchInput(toolName: string, input: unknown, cwd = process.env.GAUNTLET_WATCH_WORKSPACE): boolean {
  if (toolName !== "bash" || !isRecord(input)) return false;
  const args = input;
  if (args.command !== WATCH_COMMAND || Object.keys(args).some(key => !["command", "timeout", "cwd"].includes(key))) return false;
  if (args.cwd !== undefined && (typeof cwd !== "string" || args.cwd !== cwd)) return false;
  return args.timeout === undefined || (
    typeof args.timeout === "number" && Number.isFinite(args.timeout) && args.timeout > 0 && args.timeout <= 120
  );
}

type ToolCall = { toolName: string; input: unknown };
type ScopeAPI = { on(event: "tool_call", handler: (event: ToolCall) => unknown): void };

export default function watchScope(pi: ScopeAPI): void {
  pi.on("tool_call", event => {
    if (!permittedWatchInput(event.toolName, event.input)) {
      return { block: true, reason: "The Watch fixture accepts only its fixed harmless command." };
    }
  });
}
