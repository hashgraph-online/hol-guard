// Watch is recording-only. This fixture scope prevents model substitutions from executing.
import { realpathSync } from "node:fs";
export const WATCH_COMMAND = `python -I -S -c 'print("ordinary-watch-fixture")'`;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function permittedWatchInput(toolName: string, input: unknown, cwd = process.env.GAUNTLET_WATCH_WORKSPACE): boolean {
  if (toolName !== "bash" || !isRecord(input)) return false;
  const args = input;
  if (args.command !== WATCH_COMMAND || Object.keys(args).some(key => !["command", "timeout", "cwd", "env", "pty", "async"].includes(key))) return false;
  // The pinned bash schema may emit these defaults even when no override was requested.
  if (args.env !== undefined && (!isRecord(args.env) || Object.keys(args.env).length !== 0)) return false;
  if (args.pty !== undefined && args.pty !== false) return false;
  if (args.async !== undefined && args.async !== false) return false;
  if (args.cwd !== undefined && args.cwd !== cwd) {
    if (typeof args.cwd !== "string" || typeof cwd !== "string") return false;
    // Only macOS's system root spelling may differ; never accept a task-owned symlink.
    const rootSpelling = (value: string) => value.replace(/^\/private(?=\/(?:tmp|var)(?:\/|$))/, "");
    if (rootSpelling(args.cwd) !== rootSpelling(cwd)) return false;
    try {
      if (realpathSync(args.cwd) !== realpathSync(cwd)) return false;
    } catch {
      return false;
    }
  }
  // Zero disables only OMP's command timer. The runner's independent host
  // deadline still bounds this exact fixed print command and reaps its group.
  return args.timeout === undefined || (
    typeof args.timeout === "number" && Number.isFinite(args.timeout) && args.timeout >= 0 && args.timeout <= 120
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
