import { describe, expect, test } from "bun:test";

import { composeCommand, safeProjectName, type CommandResult } from "./lab-process";
import { runInstalledPlaywright } from "./installed-playwright";
import { fetchLabGet } from "./relay-fetch";
import { readyFromLogs } from "./runner";
import { readDashboardSession } from "./session-handoff";
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

  test("retries an idempotent relay GET after a transient reset", async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      if (calls === 1) throw new TypeError("connection reset");
      return new Response("ready", { status: 200 });
    };
    try {
      const response = await fetchLabGet("http://127.0.0.1:4781/healthz");
      expect(response.status).toBe(200);
      expect(calls).toBe(2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("keeps Guard internal and publishes only the fixed-target relay", async () => {
    const compose = await Bun.file(`${import.meta.dir}/docker-compose.yml`).text();
    const guardBlock = compose.slice(compose.indexOf("  guard:"), compose.indexOf("  relay:"));
    const relayStart = compose.indexOf("  relay:");
    const relayBlock = compose.slice(relayStart, compose.indexOf("\nvolumes:", relayStart));
    expect(guardBlock).toContain("- guard-analytics");
    expect(guardBlock).not.toContain("ports:");
    expect(relayBlock).toContain('["python", "/opt/guard-lab/tcp_relay.py"]');
    expect(relayBlock).toContain('"127.0.0.1:${HOL_GUARD_LAB_PORT:?set by runner}:4781"');
    expect(relayBlock).toContain("- guard-analytics\n      - host-access");
    expect(relayBlock).toContain("condition: service_healthy");
    expect(compose).toContain("guard-analytics:\n    internal: true");
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
      return result('guard | HOL_GUARD_LAB_READY {"activity_count":7}\n');
    });
    expect(ready.activity_count).toBe(7);
  });

  test("consumes the owner-only dashboard session handoff", async () => {
    const session = await readDashboardSession("guard-command-analytics", {}, async (command) => {
      expect(command).toContain("exec");
      expect(command.at(-1)).toContain("/guard-home/.installed-dashboard-session");
      expect(command.at(-1)).toContain("metadata.st_uid != os.getuid()");
      expect(command.at(-1)).toContain("stat.S_IMODE(metadata.st_mode) != 0o600");
      expect(command.at(-1)).toContain("os.unlink(path)");
      return result("session\n");
    });
    expect(session).toBe("session");
  });

  test("scans proof artifacts when installed Playwright fails", async () => {
    let proofScanned = false;
    let invocation = 0;
    await expect(runInstalledPlaywright("http://127.0.0.1:4781", "session", 7, "proof", async () => {
      invocation += 1;
      return invocation === 1 ? result() : result("", 1);
    }, async () => {
      proofScanned = true;
    })).rejects.toThrow("installed dashboard Playwright failed");
    expect(proofScanned).toBe(true);
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
    const [dockerfile, dockerignore, compose, server, containmentProbe, runner, relay, relayFetch, playwright,
      databasePrivacy]
      = await Promise.all([
      Bun.file(`${directory}/Dockerfile`).text(),
      Bun.file(`${directory}/Dockerfile.dockerignore`).text(),
      Bun.file(`${directory}/docker-compose.yml`).text(),
      Bun.file(`${directory}/installed_server.py`).text(),
      Bun.file(`${directory}/installed_containment_probe.py`).text(),
      Bun.file(`${directory}/runner.ts`).text(),
      Bun.file(`${directory}/tcp_relay.py`).text(),
      Bun.file(`${directory}/relay-fetch.ts`).text(),
      Bun.file(`${directory}/../../../dashboard/playwright.installed.config.ts`).text(),
      Bun.file(`${directory}/database-privacy.ts`).text(),
    ]);
    expect(dockerfile).toContain("pip install --no-cache-dir /opt/wheels/*.whl");
    expect(dockerfile).not.toContain("COPY src");
    expect(dockerignore).toContain("!dist/*.whl");
    expect(dockerignore).toContain("installed_server.py");
    expect(dockerignore).toContain("github-cli-fixture.sh");
    expect(dockerignore).toContain("tcp_relay.py");
    expect(compose).not.toContain("../../src");
    expect(compose).toContain("internal: true");
    expect(compose).toContain("no-new-privileges:true");
    expect(compose).not.toContain("SYS_ADMIN");
    expect(compose).not.toContain("seccomp:unconfined");
    expect(dockerfile).not.toContain("bubblewrap");
    expect(relay).toContain("destination.shutdown(socket.SHUT_WR)");
    expect(relay).toContain("active.remove(source)");
    expect(relay).not.toContain("(), (), 30");
    for (const harness of ["codex", "claude-code", "cursor"]) {
      expect(server).toContain(`_run_installed_hook(\"${harness}\"`);
    }
    expect(server).toContain("subprocess.run(");
    expect(server).toContain('"git status --short"');
    expect(server).toContain('"git diff --stat"');
    expect(server).toContain('"git push --delete origin stale-lab-branch"');
    expect(server).toContain('"shutdown -h now # {SENTINEL}"');
    expect(server).not.toContain("execute_contained");
    expect(containmentProbe).toContain('Path("/bin/sh").resolve(strict=True)');
    expect(containmentProbe).toContain("execute_contained(request");
    expect(containmentProbe).toContain('declared_outputs=("output/format-output.txt",)');
    expect(containmentProbe).toContain("result.outputs[0].content == b\"formatted\\n\"");
    expect(containmentProbe).toContain("not destination.exists()");
    expect(containmentProbe).toContain("cat {protected_path}");
    expect(containmentProbe).toContain("printf changed 2>/dev/null > {protected_path}");
    expect(containmentProbe).toContain('"namespace-unavailable"');
    expect(containmentProbe).toContain('"site-packages"');
    expect(server).not.toContain("record_pre_hook_command_activity_best_effort");
    expect(server).not.toContain("record_command_activity(");
    expect(server).not.toContain("ActivityDecisionReason.CAPABILITY");
    expect(server).toContain("HOL_GUARD_LAB_PENDING");
    expect(server).not.toContain('"dashboard_session"');
    expect(server).toContain("os.O_NOFOLLOW");
    expect(server).toContain("request_scope_contract(");
    expect(server).toContain("codex_lab_workflow_drift_0002");
    expect(server).toContain("codex_lab_workflow_retry_0003");
    expect(server).not.toContain("apply_approval_resolution(");
    expect(server).toContain('\"activity_proof\": \"drift-rejected-restored-one-shot-reuse\"');
    expect(server).toContain("site-packages");
    expect(runner).toContain("finally");
    expect(runner).toContain("teardownLab(project");
    expect(runner).toContain('"/v1/command-activity/diagnostics"');
    expect(runner).toContain("/v1/command-activity/events?cursor=0");
    expect(runner).toContain('"X-Guard-Dashboard-Session": session');
    expect(runner).toContain("scope_contract_digest: pending.scope_contract_digest");
    expect(runner).toContain("approveWorkflowAuthorization(origin, pending, session)");
    expect(runner).toContain('"-I"');
    expect(runner).toContain("HOL_GUARD_LAB_PYTHON");
    expect(relayFetch).toContain("async function fetchLabGet");
    expect(runner).toContain("init.method === undefined");
    expect(runner).toContain("await fetch(request, options)");
    expect(runner.lastIndexOf("try {")).toBeLessThan(runner.lastIndexOf("runInstalledContainment(runner, version)"));
    expect(runner.lastIndexOf("runInstalledContainment(runner, version)")).toBeLessThan(
      runner.lastIndexOf('composeCommand(project, "up"'),
    );
    expect(playwright).toContain('trace: "off"');
    expect(databasePrivacy).toContain("command_activity(?:_[a-z0-9_]+)?");
    expect(databasePrivacy).toContain("envelope_redacted_json");
    expect(runner).toContain('["event", "activity_id"]');
    for (const category of ["prompt-free", "contained", "workflow", "review", "block"]) {
      expect(runner).toContain(`\"${category}\"`);
    }
  });
});
