import { LAB_DIR, composeCommand, type CommandRunner } from "./lab-process";

const SESSION_PATH = "/guard-home/.installed-dashboard-session";
const READ_ONCE = `
import os
import stat
path = ${JSON.stringify(SESSION_PATH)}
descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RuntimeError("invalid session handoff")
    session = os.read(descriptor, 8192).decode("ascii").strip()
    if not session:
        raise RuntimeError("empty session handoff")
finally:
    os.close(descriptor)
os.unlink(path)
print(session)
`;

export async function readDashboardSession(
  project: string,
  environment: Record<string, string>,
  runner: CommandRunner,
): Promise<string> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const result = await runner(composeCommand(project, "exec", "-T", "guard", "python", "-c", READ_ONCE), {
      cwd: LAB_DIR,
      env: environment,
    });
    if (result.exitCode === 0 && result.stdout.trim()) return result.stdout.trim();
    await Bun.sleep(100);
  }
  throw new Error("dashboard session handoff unavailable");
}
