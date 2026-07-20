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
    output_written: boolean;
    protected_value_unchanged: boolean;
    secret_hidden: boolean;
  };
  dashboard_session: string;
  installed_origin: string;
  prompt_free_hook_count: 2;
  version: string;
  workflow_authorization: {
    activity_proof: "drift-rejected-restored-one-shot-reuse";
    capability_claimed: 1;
    capability_issued: 1;
    drift_claimed: 0;
    request_flow: "authenticated-daemon-api";
  };
}
interface PendingWorkflowEvidence {
  dashboard_session: string;
  request_id: string;
  scope_contract_digest: string;
  scope_contract_version: string;
}
interface ApiEvidence {
  activityCount: number;
  categories: string[];
  diagnosticsActivityCount: number;
  feedbackCount: number;
  filteredCursorCount: number;
  harnesses: string[];
  health: string;
  sseActivityCount: number;
  statuses: string[];
}
export interface LabEvidence {
  api: ApiEvidence;
  cleanup: TeardownEvidence;
  installed: Omit<ReadyEvidence, "dashboard_session">;
  persistence: { afterRestart: number; beforeRestart: number };
  playwright: "passed";
  privacy: { api: "clean"; database: "clean"; export: "clean"; sse: "clean" };
  status: "pass";
  workflowAuthorization: ReadyEvidence["workflow_authorization"];
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
async function pendingFromLogs(
  project: string,
  environment: Record<string, string>,
  runner: CommandRunner,
): Promise<PendingWorkflowEvidence | null> {
  const logs = requireSuccess(
    await runner(composeCommand(project, "logs", "--no-color", "guard"), { cwd: LAB_DIR, env: environment }),
    "Dockerlabs logs",
  );
  const line = logs.split("\n").filter((item) => item.includes("HOL_GUARD_LAB_PENDING ")).at(-1);
  if (!line) return null;
  const payload = line.slice(line.indexOf("HOL_GUARD_LAB_PENDING ") + "HOL_GUARD_LAB_PENDING ".length);
  return JSON.parse(payload) as PendingWorkflowEvidence;
}
async function waitForPendingWorkflow(
  project: string,
  environment: Record<string, string>,
  runner: CommandRunner,
): Promise<PendingWorkflowEvidence> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const pending = await pendingFromLogs(project, environment, runner);
    if (pending) return pending;
    await Bun.sleep(100);
  }
  throw new Error("installed daemon did not emit pending workflow evidence");
}
async function waitForReadyEvidence(
  project: string,
  environment: Record<string, string>,
  runner: CommandRunner,
): Promise<ReadyEvidence> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      return await readyFromLogs(project, environment, runner);
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes("did not emit readiness evidence")) throw error;
    }
    await Bun.sleep(100);
  }
  throw new Error("installed daemon did not complete workflow authorization");
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
async function approveWorkflowAuthorization(origin: string, pending: PendingWorkflowEvidence): Promise<void> {
  const path = `/v1/requests/${encodeURIComponent(pending.request_id)}`;
  const request = await apiJson(origin, path, pending.dashboard_session);
  const eligibility = request.task_capability_eligibility;
  if (typeof eligibility !== "object" || eligibility === null || Array.isArray(eligibility)) {
    throw new Error("workflow request omitted task-capability eligibility");
  }
  if (
    request.scope_contract_version !== pending.scope_contract_version
    || request.scope_contract_digest !== pending.scope_contract_digest
    || (eligibility as Record<string, unknown>).eligible !== true
  ) {
    throw new Error("workflow request scope contract did not reconcile");
  }
  const unauthenticated = await fetch(`${origin}${path}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "allow", scope: "artifact" }),
  });
  if (unauthenticated.status !== 401) throw new Error("workflow approval endpoint did not require authentication");
  const response = await apiJson(origin, `${path}/approve`, pending.dashboard_session, {
    method: "POST",
    body: JSON.stringify({
      action: "allow",
      scope: "artifact",
      scope_contract_digest: pending.scope_contract_digest,
      scope_contract_version: pending.scope_contract_version,
    }),
  });
  const resolved = response.resolved_request;
  if (
    response.resolved !== true
    || typeof resolved !== "object"
    || resolved === null
    || Array.isArray(resolved)
    || (resolved as Record<string, unknown>).resolution_action !== "allow"
    || (resolved as Record<string, unknown>).resolution_scope !== "artifact"
  ) {
    throw new Error("workflow authorization did not resolve through the exact API contract");
  }
}
function items(payload: Record<string, unknown>): Record<string, unknown>[] {
  if (!Array.isArray(payload.items)) throw new Error("activity response omitted items");
  return payload.items as Record<string, unknown>[];
}
function assertPrivate(payload: unknown): void {
  if (JSON.stringify(payload).includes(SENTINEL)) throw new Error("private command value escaped the API");
}
function assertExactKeys(payload: Record<string, unknown>, allowed: readonly string[], surface: string): void {
  const actual = Object.keys(payload).sort();
  const expected = [...allowed].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${surface} returned unexpected fields: ${actual.join(",")}`);
  }
}
async function verifyDiagnosticsExport(
  origin: string,
  session: string,
  expectedActivityCount: number,
): Promise<number> {
  const unauthenticated = await fetch(`${origin}/v1/command-activity/diagnostics`);
  if (unauthenticated.status !== 401) throw new Error("command activity export did not require authentication");
  const diagnostics = await apiJson(origin, "/v1/command-activity/diagnostics", session);
  assertPrivate(diagnostics);
  assertExactKeys(
    diagnostics,
    ["schema_version", "schemas", "counts", "proof_coverage", "stable_ids", "error_classes"],
    "command activity export",
  );
  const counts = diagnostics.counts;
  if (typeof counts !== "object" || counts === null || Array.isArray(counts)) {
    throw new Error("command activity export omitted aggregate counts");
  }
  const activityCount = Number((counts as Record<string, unknown>).activities);
  if (activityCount !== expectedActivityCount) {
    throw new Error("command activity export did not reconcile with the authenticated list");
  }
  return activityCount;
}
async function verifyCommandActivitySse(
  origin: string,
  session: string,
  expectedActivityIds: ReadonlySet<string>,
): Promise<number> {
  const unauthenticated = await fetch(`${origin}/v1/command-activity/events?cursor=0`);
  if (unauthenticated.status !== 401) throw new Error("command activity SSE did not require authentication");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  const seen = new Set<string>();
  try {
    const response = await fetch(`${origin}/v1/command-activity/events?cursor=0`, {
      headers: { "X-Guard-Dashboard-Session": session },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`command activity SSE returned ${response.status}`);
    if (!response.headers.get("content-type")?.startsWith("text/event-stream")) {
      throw new Error("command activity SSE returned the wrong content type");
    }
    if (!response.body) throw new Error("command activity SSE omitted its response body");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (seen.size < expectedActivityIds.size) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buffer += decoder.decode(chunk.value, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const data = frame.split("\n").find((line) => line.startsWith("data: "))?.slice(6);
        if (data) {
          assertPrivate(data);
          const event = JSON.parse(data) as Record<string, unknown>;
          assertExactKeys(event, ["event", "activity_id"], "command activity SSE event");
          if (event.event !== "command_activity_invalidated" || typeof event.activity_id !== "string") {
            throw new Error("command activity SSE returned an invalid event");
          }
          if (!expectedActivityIds.has(event.activity_id)) {
            throw new Error("command activity SSE exposed an unknown activity identifier");
          }
          seen.add(event.activity_id);
        }
        boundary = buffer.indexOf("\n\n");
      }
    }
    await reader.cancel();
  } catch (error) {
    if (controller.signal.aborted) throw new Error("command activity SSE did not reconcile before timeout");
    throw error;
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }
  if (seen.size !== expectedActivityIds.size) {
    throw new Error("command activity SSE did not reconcile with the authenticated list");
  }
  return seen.size;
}
async function verifyApi(
  origin: string,
  session: string,
  containment: ReadyEvidence["containment"],
  promptFreeHookCount: number,
): Promise<ApiEvidence> {
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
  const activityIds = new Set(rows.map((row) => String(row.activity_id)));
  const harnesses = [...new Set(rows.map((row) => String(row.harness)))].sort();
  const statuses = [...new Set(rows.map((row) => String(row.execution_status)))].sort();
  if (rows.length !== 5 || Number(analytics.commands_checked) !== rows.length) {
    throw new Error("authenticated list and analytics totals did not reconcile");
  }
  if (!harnesses.includes("codex") || !harnesses.includes("claude-code") || !harnesses.includes("cursor")) {
    throw new Error(`real harness coverage missing: ${harnesses.join(",")}`);
  }
  if (!statuses.includes("prevented") || !statuses.includes("allowed_unconfirmed")) {
    throw new Error(`execution proof coverage missing: ${statuses.join(",")}`);
  }
  if (cursorRows.length !== 1 || cursorRows[0]?.harness !== "cursor") throw new Error("cursor filter did not reconcile");
  const workflowAuthorized = rows.some((row) => (
    row.policy_action === "allow" && row.approval_reuse_status === "accepted" && row.prompted === false
  ));
  const categories = [
    promptFreeHookCount === 2 ? "prompt-free" : null,
    rows.some((row) => row.prompted === true && ["review", "require-reapproval"].includes(String(row.policy_action)))
      ? "review"
      : null,
    rows.some((row) => row.policy_action === "block") ? "block" : null,
    containment.enforced && containment.output_written && containment.protected_value_unchanged
      ? "contained"
      : null,
    workflowAuthorized ? "workflow" : null,
  ].filter((value): value is string => value !== null);
  if (categories.length !== 5) throw new Error(`decision category coverage missing: ${categories.join(",")}`);
  const health = analytics.health as Record<string, unknown>;
  if (health.status !== "healthy" || health.dropped_events !== 0 || health.persistence_errors !== 0) {
    throw new Error(`analytics health is not clean: ${JSON.stringify(health)}`);
  }
  const [diagnosticsActivityCount, sseActivityCount] = await Promise.all([
    verifyDiagnosticsExport(origin, session, rows.length),
    verifyCommandActivitySse(origin, session, activityIds),
  ]);
  return {
    activityCount: rows.length,
    categories,
    diagnosticsActivityCount,
    feedbackCount: Array.isArray(analytics.feedback) ? analytics.feedback.length : -1,
    filteredCursorCount: cursorRows.length,
    harnesses,
    health: String(health.status),
    sseActivityCount,
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
  const version = Bun.env.HOL_GUARD_LAB_EXPECTED_VERSION
    ?? packageVersion(await Bun.file(resolve(REPO_ROOT, "pyproject.toml")).text());
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
    const pending = await waitForPendingWorkflow(project, environment, runner);
    await approveWorkflowAuthorization(origin, pending);
    const first = await waitForReadyEvidence(project, environment, runner);
    if (JSON.stringify(first.workflow_authorization) !== JSON.stringify({
      activity_proof: "drift-rejected-restored-one-shot-reuse",
      capability_claimed: 1,
      capability_issued: 1,
      drift_claimed: 0,
      request_flow: "authenticated-daemon-api",
    })) throw new Error("workflow authorization evidence did not reconcile");
    const api = await verifyApi(origin, first.dashboard_session, first.containment, first.prompt_free_hook_count);
    await verifyDatabasePrivacy(project, environment, runner);
    requireSuccess(
      await runner(composeCommand(project, "restart", "guard"), { cwd: LAB_DIR, env: environment }),
      "installed daemon restart",
    );
    await waitForReady(origin);
    const restarted = await waitForReadyEvidence(project, environment, runner);
    const afterRestart = await verifyApi(
      origin,
      restarted.dashboard_session,
      restarted.containment,
      restarted.prompt_free_hook_count,
    );
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
        prompt_free_hook_count: first.prompt_free_hook_count,
        version: first.version,
      },
      persistence: { beforeRestart: api.activityCount, afterRestart: afterRestart.activityCount },
      playwright: "passed",
      privacy: { api: "clean", database: "clean", export: "clean", sse: "clean" },
      status: "pass",
      workflowAuthorization: first.workflow_authorization,
    };
  } finally {
    if (cleanup === null) {
      await teardownLab(project, async (command, options) => runner(command, { ...options, env: environment }));
    }
  }
}
if (import.meta.main) console.log(JSON.stringify(await runLab(), null, 2));
