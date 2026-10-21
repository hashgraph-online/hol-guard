import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";

import { composeCommand, REPO_ROOT, runCommand, safeProjectName, type CommandResult } from "./lab-process";
import { runInstalledPlaywright } from "./installed-playwright";
import { fetchLabGet, fetchLabIdempotent } from "./relay-fetch";
import { readyFromLogs, resolveWheel } from "./runner";
import { readDashboardSession } from "./session-handoff";
import { teardownLab } from "./teardown";

function result(stdout = "", exitCode = 0): CommandResult {
  return { exitCode, stderr: "", stdout };
}

describe("command extension analytics Dockerlabs orchestration", () => {
  test("requires an explicit native wheel instead of building a pure wheel", () => {
    const original = Bun.env.HOL_GUARD_WHEEL;
    try {
      delete Bun.env.HOL_GUARD_WHEEL;
      expect(() => resolveWheel()).toThrow("native-injected wheel");
      Bun.env.HOL_GUARD_WHEEL = resolve(REPO_ROOT, "dist/synthetic.whl");
      expect(resolveWheel()).toBe("dist/synthetic.whl");
    } finally {
      if (original === undefined) delete Bun.env.HOL_GUARD_WHEEL;
      else Bun.env.HOL_GUARD_WHEEL = original;
    }
  });

  test("normalizes bounded compose project names", () => {
    expect(safeProjectName("Guard Command Analytics 42")).toBe("guard-command-analytics-42");
    expect(() => safeProjectName("../")).toThrow("invalid Dockerlabs project name");
    expect(() => safeProjectName("x".repeat(49))).toThrow("invalid Dockerlabs project name");
  });

  test("terminates a stalled diagnostic command", async () => {
    const started = Date.now();
    const timedOut = await runCommand([process.execPath, "-e", "await Bun.sleep(10_000)"], { timeoutMs: 100 });
    expect(timedOut.exitCode).not.toBe(0);
    expect(Date.now() - started).toBeLessThan(3_000);
    await expect(runCommand([process.execPath, "-e", ""], { timeoutMs: 0 }))
      .rejects.toThrow("timeoutMs must be a positive integer");
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

  test("retries an explicitly idempotent relay POST after a transient reset", async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async (_input, init) => {
      calls += 1;
      expect(init?.method).toBe("POST");
      if (calls === 1) throw new TypeError("connection reset");
      return Response.json({ resolved: true });
    };
    try {
      const response = await fetchLabIdempotent("http://127.0.0.1:4781/v1/requests/id/approve", {
        method: "POST",
        body: JSON.stringify({ action: "allow", scope: "artifact" }),
      });
      expect(await response.json()).toEqual({ resolved: true });
      expect(calls).toBe(2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("publishes only the loopback relay while Guard stays on the internal network", async () => {
    const compose = await Bun.file(`${import.meta.dir}/docker-compose.yml`).text();
    const server = await Bun.file(`${import.meta.dir}/installed_server.py`).text();
    const relay = await Bun.file(`${import.meta.dir}/tcp_relay.py`).text();
    const guardBlock = compose.slice(compose.indexOf("  guard:"), compose.indexOf("  relay:"));
    const relayStart = compose.indexOf("  relay:");
    const relayBlock = compose.slice(relayStart, compose.indexOf("  host_relay:", relayStart));
    const hostRelayBlock = compose.slice(compose.indexOf("  host_relay:"), compose.indexOf("\nvolumes:"));
    expect(guardBlock).toContain("- guard-analytics");
    expect(guardBlock).not.toContain("ports:");
    expect(relayBlock).toContain('["python", "/opt/guard-lab/tcp_relay.py"]');
    expect(relayBlock).toContain('network_mode: "service:guard"');
    expect(relayBlock).not.toContain("ports:");
    expect(relayBlock).toContain("condition: service_healthy");
    expect(hostRelayBlock).toContain('"127.0.0.1:${HOL_GUARD_LAB_PORT:?set by runner}:4783"');
    expect(hostRelayBlock).toContain("- host-access");
    expect(hostRelayBlock).toContain("- guard-analytics");
    expect(hostRelayBlock).toContain("condition: service_healthy");
    expect(compose).toContain("guard-analytics:\n    internal: true");
    expect(server).toContain('host="127.0.0.1"');
    expect(relay).toContain('"guard": (("0.0.0.0", 4782), ("127.0.0.1", 4781))');
    expect(relay).toContain('"host_relay": (("0.0.0.0", 4783), ("guard", 4782))');
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

  test("surfaces redacted daemon tracebacks instead of timing out", async () => {
    let failure: Error | null = null;
    try {
      await readyFromLogs("guard-command-analytics", {}, async () => result(
        'guard | HOL_GUARD_LAB_READY {"activity_count":7}\n'
        + "guard | Traceback (most recent call last):\n"
        + "guard | RuntimeError: guard-private-command-sentinel\n",
      ));
    } catch (error) {
      if (error instanceof Error) failure = error;
    }
    expect(failure?.message).toContain("installed daemon failed before readiness");
    expect(failure?.message).toContain("[REDACTED]");
    expect(failure?.message).not.toContain("guard-private-command-sentinel");
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

  test("reports a browser failure alongside the proof failure without exposing private values", async () => {
    const session = "secret-session-value";
    let invocation = 0;
    let failure: Error | null = null;
    try {
      await runInstalledPlaywright("http://127.0.0.1:4781", session, 7, "proof", async () => {
        invocation += 1;
        return invocation === 1 ? result() : {
          exitCode: 1,
          stdout: `browser assertion failed: ${session} guard-private-command-sentinel`,
          stderr: "bun wrapper failed",
        };
      }, async () => {
        throw new Error(`private value retained in proof: ${session}`);
      });
    } catch (error) {
      if (error instanceof Error) failure = error;
    }
    expect(failure?.message).toContain("browser assertion failed");
    expect(failure?.message).toContain("private value retained in proof");
    expect(failure?.message).not.toContain(session);
    expect(failure?.message).not.toContain("guard-private-command-sentinel");
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

});
