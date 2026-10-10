// Watch is recording-only. This fixture scope prevents model substitutions from executing.
import { realpathSync } from "node:fs";
import { win32 } from "node:path";
export const WATCH_COMMAND = `python -I -S -c 'print("ordinary-watch-fixture")'`;

/** Spell a cwd the way its platform does, so equal directories compare equal:
 * macOS reports /tmp and /var under /private, and Windows accepts either slash
 * and either drive-letter case. Symlinks are never resolved here. */
export function cwdSpelling(value: string, platform: string = process.platform): string {
  if (platform === "win32") return win32.normalize(value).replace(/^[a-z]:/, drive => drive.toUpperCase());
  return value.replace(/^\/private(?=\/(?:tmp|var)(?:\/|$))/, "");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function permittedWatchInput(toolName: string, input: unknown, cwd = process.env.GAUNTLET_WATCH_WORKSPACE): boolean {
  if (toolName !== "bash" || !isRecord(input)) return false;
  const args = input;
  if (args.command !== WATCH_COMMAND || Object.keys(args).some(key => !["command", "timeout", "cwd", "env", "pty", "async", "i", "intent"].includes(key))) return false;
  // The SDK may attach a plain-text intent label; it never reaches the shell.
  if (["i", "intent"].some(key => args[key] !== undefined && typeof args[key] !== "string")) return false;
  // The pinned bash schema may emit these defaults even when no override was requested.
  if (args.env !== undefined && (!isRecord(args.env) || Object.keys(args.env).length !== 0)) return false;
  if (args.pty !== undefined && args.pty !== false) return false;
  if (args.async !== undefined && args.async !== false) return false;
  if (args.cwd !== undefined && args.cwd !== cwd) {
    if (typeof args.cwd !== "string" || typeof cwd !== "string") return false;
    // Only the platform's own spelling may differ; never accept a task-owned symlink.
    if (cwdSpelling(args.cwd) !== cwdSpelling(cwd)) return false;
    try {
      if (realpathSync(args.cwd) !== realpathSync(cwd)) return false;
    } catch {
      return false;
    }
  }
  // OMP defaults an omitted timeout to 300 seconds; require the fixture's explicit bound.
  return typeof args.timeout === "number" && Number.isFinite(args.timeout) && args.timeout > 0 && args.timeout <= 120;
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
