import { basename, resolve } from "node:path";

import {
  composeCommand,
  LAB_DIR,
  listProjectResources,
  REPO_ROOT,
  requireSuccess,
  runCommand,
  safeProjectName,
  type CommandRunner,
} from "./lab-process";
import { teardownLab, type TeardownEvidence } from "./teardown";

const SENTINEL = "guard-private-command-sentinel";

interface ReadyEvidence {
  activity_count: number;
  containment: {
    enforced: boolean;
    exit_code: number;
    protected_value_unchanged: boolean;
    secret_hidden: boolean;
  };
  dashboard_session: string;
  installed_origin: string;
  version: string;
}

interface ApiEvidence {
  activityCount: number;
  feedbackCount: number;
  filteredCursorCount: number;
  harnesses: string[];
  health: string;
  statuses: string[];
}

export interface LabEvidence {
  api: ApiEvidence;
  cleanup: TeardownEvidence;
  installed: Omit<ReadyEvidence, "dashboard_session">;
  persistence: { afterRestart: number; beforeRestart: number };
  playwright: "passed";
  privacy: { api: "clean"; database: "clean" };
  status: "pass";
}

function packageVersion(pyproject: string): string {
  const match = pyproject.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error("could not read package version");
  return match[1];
}

function repoRelativeWheel(path: string): string {
  const root = `${REPO_ROOT}/`;
  const absolute = resolve(path);
  if (!absolute.startsWith(root) || !absolute.endsWith(".whl")) {
    throw new Error("HOL_GUARD_WHEEL must name a wheel inside this worktree");
  }
  return absolute.slice(root.length);
}

async function resolveWheel(runner: CommandRunner, version: string): Promise<string> {
  if (Bun.env.HOL_GUARD_WHEEL) return repoRelativeWheel(Bun.env.HOL_GUARD_WHEEL);
  requireSuccess(
    await runner(["uv", "build", "--wheel", "--out-dir", "dist"], { cwd: REPO_ROOT }),
    "wheel build",
  );
  const wheels = Array.fromAsync(
    new Bun.Glob(`hol_guard-${version.replaceAll("-", "_")}-*.whl`).scan({ cwd: resolve(REPO_ROOT, "dist") }),
  );
  const matches = await wheels;
  if (matches.length !== 1) throw new Error(`expected exactly one built wheel, found ${matches.length}`);
  return `dist/${basename(matches[0])}`;
}

async function waitForReady(origin: string, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${origin}/healthz`);
      if (response.ok) return;
    } catch {
      // Container health is still converging.
    }
    await Bun.sleep(250);
  }
  throw new Error("installed Guard daemon did not become ready");
}

export async function readyFromLogs(
  project: string,
  environment: Record<string, string>,
  runner: CommandRunner,
): Promise<ReadyEvidence> {
  const logs = requireSuccess(
    await runner(composeCommand(project, "logs", "--no-color", "guard"), { cwd: LAB_DIR, env: environment }),
    "Dockerlabs logs",
  );
  const ready = logs.split("\n").filter((line) => line.includes("HOL_GUARD_LAB_READY ")).at(-1);
  if (!ready) throw new Error("installed daemon did not emit readiness evidence");
  const payload = ready.slice(ready.indexOf("HOL_GUARD_LAB_READY ") + "HOL_GUARD_LAB_READY ".length);
  return JSON.parse(payload) as ReadyEvidence;
}

async function apiJson(
  origin: string,
  path: string,
  session: string,
  init: RequestInit = {},
): Promise<Record<string, unknown>> {
  const response = await fetch(`${origin}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-Guard-Dashboard-Session": session,
      ...init.headers,
    },
  });
  if (!response.ok) throw new Error(`${path} returned ${response.status}: ${await response.text()}`);
  return await response.json() as Record<string, unknown>;
}

function items(payload: Record<string, unknown>): Record<string, unknown>[] {
  if (!Array.isArray(payload.items)) throw new Error("activity response omitted items");
  return payload.items as Record<string, unknown>[];
}

function assertPrivate(payload: unknown): void {
  if (JSON.stringify(payload).includes(SENTINEL)) throw new Error("private command value escaped the API");
}

async function verifyApi(origin: string, session: string): Promise<ApiEvidence> {
  const unauthenticated = await fetch(`${origin}/v1/command-activity`);
  if (unauthenticated.status !== 401) throw new Error("command activity API did not require authentication");
  const [activity, analytics, cursor] = await Promise.all([
    apiJson(origin, "/v1/command-activity?limit=100", session),
    apiJson(origin, "/v1/command-activity/analytics?days=7", session),
    apiJson(origin, "/v1/command-activity?limit=100&harness=cursor", session),
  ]);
  assertPrivate([activity, analytics, cursor]);
  const rows = items(activity);
  const cursorRows = items(cursor);
  const harnesses = [...new Set(rows.map((row) => String(row.harness)))].sort();
  const statuses = [...new Set(rows.map((row) => String(row.execution_status)))].sort();
  if (rows.length !== 5 || Number(analytics.commands_checked) !== rows.length) {
    throw new Error("authenticated list and analytics totals did not reconcile");
  }
  if (!harnesses.includes("codex") || !harnesses.includes("claude-code") || !harnesses.includes("cursor")) {
    throw new Error(`real harness coverage missing: ${harnesses.join(",")}`);
  }
  if (!statuses.includes("confirmed_success") || !statuses.includes("prevented") || !statuses.includes("allowed_unconfirmed")) {
    throw new Error(`execution proof coverage missing: ${statuses.join(",")}`);
  }
  if (cursorRows.length !== 1 || cursorRows[0]?.harness !== "cursor") throw new Error("cursor filter did not reconcile");
  const reasons = new Set(rows.map((row) => row.decision_reason_code));
  if (!reasons.has("containment") || !reasons.has("capability")) throw new Error("workflow evidence is incomplete");
  const health = analytics.health as Record<string, unknown>;
  if (health.status !== "healthy" || health.dropped_events !== 0 || health.persistence_errors !== 0) {
    throw new Error(`analytics health is not clean: ${JSON.stringify(health)}`);
  }
  return {
    activityCount: rows.length,
    feedbackCount: Array.isArray(analytics.feedback) ? analytics.feedback.length : -1,
    filteredCursorCount: cursorRows.length,
    harnesses,
    health: String(health.status),
    statuses,
  };
}

async function verifyDatabasePrivacy(
  project: string,
  environment: Record<string, string>,
  runner: CommandRunner,
): Promise<void> {
  const code = `from pathlib import Path; print(${JSON.stringify(SENTINEL)}.encode() in Path('/guard-home/guard.db').read_bytes())`;
  const result = requireSuccess(
    await runner(composeCommand(project, "exec", "-T", "guard", "python", "-c", code), {
      cwd: LAB_DIR,
      env: environment,
    }),
    "database privacy probe",
  );
  if (result !== "False") throw new Error("private command value escaped into the database");
}

async function runPlaywright(origin: string, session: string, proofDir: string, runner: CommandRunner): Promise<void> {
  requireSuccess(
    await runner(["bun", "install", "--frozen-lockfile", "--ignore-scripts"], { cwd: resolve(REPO_ROOT, "dashboard") }),
    "dashboard dependency install",
  );
  requireSuccess(
    await runner(["bun", "run", "test:e2e:installed"], {
      cwd: resolve(REPO_ROOT, "dashboard"),
      env: {
        GUARD_INSTALLED_ACTIVITY_COUNT: "5",
        GUARD_INSTALLED_DASHBOARD_SESSION: session,
        GUARD_INSTALLED_ORIGIN: origin,
        PLAYWRIGHT_PROOF_DIR: proofDir,
      },
    }),
    "installed dashboard Playwright",
  );
}

export async function runLab(runner: CommandRunner = runCommand): Promise<LabEvidence> {
  const project = safeProjectName(Bun.env.GUARD_TEST_PROJECT ?? `guard-command-analytics-${process.pid}`);
  const port = Number(Bun.env.GUARD_TEST_PORT ?? 48_000 + process.pid % 1_000);
  if (!Number.isInteger(port) || port < 1_024 || port > 65_535) throw new Error("invalid GUARD_TEST_PORT");
  const origin = `http://127.0.0.1:${port}`;
  const version = packageVersion(await Bun.file(resolve(REPO_ROOT, "pyproject.toml")).text());
  const wheel = await resolveWheel(runner, version);
  const environment = {
    GUARD_TEST_PROJECT: project,
    HOL_GUARD_LAB_EXPECTED_VERSION: version,
    HOL_GUARD_LAB_PORT: String(port),
    HOL_GUARD_LAB_WHEEL: wheel,
  };
  let cleanup: TeardownEvidence | null = null;
  try {
    const existing = await listProjectResources(project, runner);
    if (existing.containers.length || existing.volumes.length || existing.networks.length) {
      throw new Error(`Dockerlabs project is not clean before start: ${JSON.stringify(existing)}`);
    }
    requireSuccess(
      await runner(composeCommand(project, "up", "-d", "--build", "--wait"), { cwd: LAB_DIR, env: environment }),
      "Dockerlabs startup",
    );
    await waitForReady(origin);
    const first = await readyFromLogs(project, environment, runner);
    const api = await verifyApi(origin, first.dashboard_session);
    await verifyDatabasePrivacy(project, environment, runner);
    requireSuccess(
      await runner(composeCommand(project, "restart", "guard"), { cwd: LAB_DIR, env: environment }),
      "installed daemon restart",
    );
    await waitForReady(origin);
    const restarted = await readyFromLogs(project, environment, runner);
    const afterRestart = await verifyApi(origin, restarted.dashboard_session);
    if (afterRestart.activityCount !== api.activityCount) throw new Error("activity persistence failed across restart");
    const proofDir = resolve(REPO_ROOT, ".artifacts/command-extension-analytics");
    await runPlaywright(origin, restarted.dashboard_session, proofDir, runner);
    const finalAnalytics = await apiJson(origin, "/v1/command-activity/analytics?days=7", restarted.dashboard_session);
    const feedback = finalAnalytics.feedback;
    if (!Array.isArray(feedback) || feedback.length !== 1) throw new Error("rendered feedback did not persist");
    assertPrivate(finalAnalytics);
    cleanup = await teardownLab(project, async (command, options) => runner(command, { ...options, env: environment }));
    return {
      api: { ...api, feedbackCount: feedback.length },
      cleanup,
      installed: {
        activity_count: first.activity_count,
        containment: first.containment,
        installed_origin: first.installed_origin,
        version: first.version,
      },
      persistence: { beforeRestart: api.activityCount, afterRestart: afterRestart.activityCount },
      playwright: "passed",
      privacy: { api: "clean", database: "clean" },
      status: "pass",
    };
  } finally {
    if (cleanup === null) {
      await teardownLab(project, async (command, options) => runner(command, { ...options, env: environment }));
    }
  }
}

if (import.meta.main) console.log(JSON.stringify(await runLab(), null, 2));
