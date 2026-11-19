/** What a new agent runs, what it is asked to do, and what it may not open. */

const PROGRAMS: Record<string, string> = { codex: "codex", claude: "claude-code" };
const MODEL = /^[A-Za-z0-9._:/-]{1,128}$/;
const PATH = /^[A-Za-z0-9._\-/*@+]{1,256}$/;
export const SECRET_PATHS = ["**/.env", "**/.env.*", "**/*.pem", "**/*.key"];
export const MAX_BLOCKED = 32;

export type ParsedCommand = { harness: string; model: string | null } | { error: string };

/** Reads a command such as `codex` or `claude --model sonnet`. Swarm starts the
 * CLI itself with Guard's safe options, so only the program and a model are
 * taken; anything else is refused instead of silently dropped. */
export function parseCommand(command: string, installed: string[]): ParsedCommand {
  const words = command.trim().split(/\s+/).filter(Boolean);
  if (!words.length) return { error: "Type the command to run, such as codex or claude." };
  const program = words[0].split("/").pop() ?? "";
  const harness = PROGRAMS[program];
  if (!harness) return { error: "Swarm can run codex or claude. Start the command with one of them." };
  if (!installed.includes(harness)) return { error: `${program} is not installed where Guard can find it. Install it, then restart Guard.` };
  let model: string | null = null;
  for (let i = 1; i < words.length; i++) {
    const word = words[i];
    let value: string | undefined;
    if (word === "--model" || word === "-m") value = words[++i];
    else if (word.startsWith("--model=")) value = word.slice("--model=".length);
    else return { error: `Only --model can be added to the command. Swarm sets everything else and never turns off the CLI's safety checks (${word} was not used).` };
    if (!value || value.startsWith("-") || !MODEL.test(value)) return { error: "Give --model a model name, such as --model sonnet." };
    model = value;
  }
  return { harness, model };
}

/** Folder and file names inside the project, one per line or comma-separated. */
export function blockedPaths(text: string, secrets: boolean): { paths: string[]; bad: string[] } {
  const paths: string[] = [];
  const bad: string[] = [];
  for (const raw of text.split(/[\n,]/)) {
    if (!raw.trim()) continue;
    const path = raw.trim().replace(/^(\.\/)+/, "");
    const parts = path.replace(/\/+$/, "").split("/");
    if (!PATH.test(path) || /^[-~]/.test(path) || parts.some((p) => p === "" || p === "." || p === "..")) bad.push(raw.trim());
    else if (!paths.includes(path)) paths.push(path);
  }
  if (secrets) for (const path of SECRET_PATHS) if (!paths.includes(path)) paths.push(path);
  return { paths, bad };
}

export type WorkDefinition = { goal: string; scope: string; done: string; avoid: string };

/** The first prompt the agent gets: its goal first, then its limits. */
export function workText(work: WorkDefinition, blocked: string[]): string {
  const lines = [`Goal: ${work.goal.trim()}`];
  if (work.scope.trim()) lines.push(`Files in scope: ${work.scope.trim()}`);
  if (work.done.trim()) lines.push(`Done when: ${work.done.trim()}`);
  if (work.avoid.trim()) lines.push(`Not allowed: ${work.avoid.trim()}`);
  if (blocked.length) lines.push(`You cannot open these paths, so do not try: ${blocked.join(", ")}`);
  return lines.join("\n");
}

/** The goal line of a task Swarm wrote, or the task's first line. */
export function goalOf(task: string | null): string | null {
  if (!task) return null;
  const first = task.split("\n", 1)[0].trim();
  return first.startsWith("Goal: ") ? first.slice("Goal: ".length) : first;
}
