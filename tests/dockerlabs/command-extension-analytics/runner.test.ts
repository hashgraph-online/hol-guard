import { describe, expect, test } from "bun:test";

import { composeCommand, safeProjectName, type CommandResult } from "./lab-process";
import { readyFromLogs } from "./runner";
import { teardownLab } from "./teardown";

function result(stdout = "", exitCode = 0): CommandResult {
  return { exitCode, stderr: "", stdout };
}

describe("command extension analytics Dockerlabs orchestration", () => {
  test("normalizes bounded compose project names", () => {
    expect(safeProjectName("Guard Command Analytics 42")).toBe("guard-command-analytics-42");
    expect(() => safeProjectName("../")).toThrow("invalid Dockerlabs project name");
    expect(() => safeProjectName("x".repeat(49))).toThrow("invalid Dockerlabs project name");
  });

  test("uses a pinned compose file and explicit project", () => {
    const command = composeCommand("guard-command-analytics", "up", "-d", "--wait");
    expect(command.slice(0, 2)).toEqual(["docker", "compose"]);
    expect(command.some((item) => item.endsWith("docker-compose.yml"))).toBe(true);
    expect(command).toContain("guard-command-analytics");
    expect(command.slice(-2)).toEqual(["-d", "--wait"]);
  });

  test("preserves exact wheel bindings when compose reparses the lab", async () => {
    const environment = {
      GUARD_TEST_PROJECT: "guard-command-analytics",
      HOL_GUARD_LAB_EXPECTED_VERSION: "2.0.1117",
      HOL_GUARD_LAB_PORT: "4781",
      HOL_GUARD_LAB_WHEEL: "dist/hol_guard-2.0.1117-py3-none-any.whl",
    };
    const ready = await readyFromLogs("guard-command-analytics", environment, async (command, options) => {
      expect(command).toContain("logs");
      expect(options?.env).toEqual(environment);
      return result('guard | HOL_GUARD_LAB_READY {"dashboard_session":"session"}\n');
    });
    expect(ready.dashboard_session).toBe("session");
  });

  test("teardown removes volumes and orphans then proves zero resources", async () => {
    const commands: string[][] = [];
    const evidence = await teardownLab("guard-command-analytics", async (command, options) => {
      commands.push([...command]);
      if (command.includes("down")) expect(options?.env?.HOL_GUARD_LAB_PORT).toBe("4781");
      return result();
    });
    expect(commands[0]?.slice(-2)).toEqual(["-v", "--remove-orphans"]);
    expect(commands.some((command) => command.includes("volume"))).toBe(true);
    expect(commands.some((command) => command.includes("network"))).toBe(true);
    expect(evidence).toMatchObject({
      command: "bun run guard:test:teardown",
      containers: 0,
      networks: 0,
      orphans: 0,
      status: "clean",
      volumes: 0,
    });
  });

  test("teardown fails when a labeled resource survives", async () => {
    await expect(teardownLab("guard-command-analytics", async (command) => {
      if (command.includes("volume")) return result("volume-id\n");
      return result();
    })).rejects.toThrow("Dockerlabs cleanup incomplete");
  });

  test("installed fixture is wheel-only and exercises the required evidence paths", async () => {
    const directory = import.meta.dir;
    const [dockerfile, dockerignore, compose, server, runner] = await Promise.all([
      Bun.file(`${directory}/Dockerfile`).text(),
      Bun.file(`${directory}/Dockerfile.dockerignore`).text(),
      Bun.file(`${directory}/docker-compose.yml`).text(),
      Bun.file(`${directory}/installed_server.py`).text(),
      Bun.file(`${directory}/runner.ts`).text(),
    ]);
    expect(dockerfile).toContain("pip install --no-cache-dir /opt/wheels/*.whl");
    expect(dockerfile).not.toContain("COPY src");
    expect(dockerignore).toContain("!dist/*.whl");
    expect(dockerignore).toContain("installed_server.py");
    expect(compose).not.toContain("../../src");
    for (const harness of ["codex", "claude-code", "cursor"]) expect(server).toContain(`harness=\"${harness}\"`);
    for (const reason of ["CONTAINMENT", "CAPABILITY"]) expect(server).toContain(`ActivityDecisionReason.${reason}`);
    expect(server).toContain("site-packages");
    expect(runner).toContain("finally");
    expect(runner).toContain("teardownLab(project");
  });
});
