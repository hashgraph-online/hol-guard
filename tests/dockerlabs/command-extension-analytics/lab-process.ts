import { resolve } from "node:path";

export interface CommandResult {
  exitCode: number;
  stderr: string;
  stdout: string;
}

export type CommandRunner = (
  command: readonly string[],
  options?: { cwd?: string; env?: Record<string, string | undefined> },
) => Promise<CommandResult>;

export const LAB_DIR = resolve(import.meta.dir);
export const REPO_ROOT = resolve(LAB_DIR, "../../..");
export const COMPOSE_FILE = resolve(LAB_DIR, "docker-compose.yml");

export async function runCommand(
  command: readonly string[],
  options: { cwd?: string; env?: Record<string, string | undefined> } = {},
): Promise<CommandResult> {
  const process = Bun.spawn([...command], {
    cwd: options.cwd,
    env: { ...Bun.env, ...options.env },
    stderr: "pipe",
    stdout: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    process.exited,
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

export function requireSuccess(result: CommandResult, label: string): string {
  if (result.exitCode !== 0) {
    throw new Error(`${label} failed (${result.exitCode})\n${result.stderr || result.stdout}`);
  }
  return result.stdout.trim();
}

export function composeCommand(project: string, ...args: string[]): string[] {
  return ["docker", "compose", "-f", COMPOSE_FILE, "-p", project, ...args];
}

export function safeProjectName(raw: string): string {
  const normalized = raw.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!normalized || normalized.length > 48) throw new Error("invalid Dockerlabs project name");
  return normalized;
}

export async function listProjectResources(
  project: string,
  runner: CommandRunner = runCommand,
): Promise<{ containers: string[]; networks: string[]; volumes: string[] }> {
  const filter = `label=com.docker.compose.project=${project}`;
  const [containers, volumes, networks] = await Promise.all([
    runner(["docker", "ps", "-aq", "--filter", filter]),
    runner(["docker", "volume", "ls", "-q", "--filter", filter]),
    runner(["docker", "network", "ls", "-q", "--filter", filter]),
  ]);
  return {
    containers: lines(requireSuccess(containers, "container inventory")),
    volumes: lines(requireSuccess(volumes, "volume inventory")),
    networks: lines(requireSuccess(networks, "network inventory")),
  };
}

function lines(value: string): string[] {
  return value.split("\n").map((item) => item.trim()).filter(Boolean);
}
