import { daemonApi, expect, expectNoErrorBoundary, test, type IntegrationState } from "./fixtures";
import { contextStatus } from "./context-status";
import { stopContextAssistance } from "./context-stop";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { ContextAgentProbe } from "./context-agent-probe";
import { execFileSync } from "node:child_process";
import { contextHistoryAndRepairFlow, clearContextFromRepair } from "./context-history-flow";
import { contextSharingFlow } from "./context-sharing-flow";

async function saveWithProof(page: import("@playwright/test").Page, state: IntegrationState) {
  const label = new URL(page.url()).pathname === "/cigar" ? "Save CIGAR preferences" : "Save settings";
  await page.getByRole("region", { name: label }).getByRole("button", { name: label, exact: true }).click();
  const proof = page.getByRole("dialog");
  await proof.getByLabel("Approval password").fill(state.approvalPassword);
  await proof.getByRole("button", { name: "Save settings" }).click();
  await expect(proof).toHaveCount(0);
  await expect(page.getByText("Settings saved successfully.")).toBeVisible();
}

test("real candidate sources, proof-backed MCP pairing and opt-out survive reload", async ({ page, state }) => {
  test.setTimeout(240_000);
  const seed = state.seeded.context_assistance;
  test.skip(seed?.candidateEnrolled !== true, "requires an explicitly selected and approved installed candidate");
  const status = () => contextStatus(state);
  await page.goto("/cigar?section=runtime");
  await page.getByRole("button", { name: "Take a walkthrough", exact: true }).click();
  await page.getByRole("button", { name: /Start walkthrough.*Prepare your first cited brief/ }).click();
  const walkthrough = page.getByRole("complementary", { name: "Prepare your first cited brief", exact: true });
  await expect(walkthrough).toBeVisible();
  const toggle = page.getByRole("switch", { name: "Use CIGAR on this machine" });
  await expect(toggle).toHaveAttribute("aria-checked", "false");
  await page.getByRole("button", { name: "Refresh runtime list" }).click();
  await expect(page.getByLabel("Local runtime", { exact: true })).toHaveValue(String(seed.runtimeId));
  await expect(toggle).toBeEnabled();
  await toggle.focus();
  await page.keyboard.press("Space");
  await expect(toggle).toHaveAttribute("aria-checked", "true");
  await page.getByRole("switch", { name: "Context for AI apps", exact: true }).click();
  await page.getByText("Sources, limits and runtime details", { exact: true }).click();
  await page.getByRole("switch", { name: "Allow selected workspace documents" }).click();
  await saveWithProof(page, state);
  expect((await status()).effective_enabled).toBe(false);
  let probe: ContextAgentProbe | undefined;
  try {
    await expect(page.locator(".cigar-status")).toHaveText("Not started");
    await page.getByRole("button", { name: "Turn on CIGAR", exact: true }).click();
    await expect.poll(async () => (await status()).effective_enabled, { timeout: 30_000 }).toBe(true);
    const ready = await status();
    expect(ready.runtime?.interpreter.version.slice(0, 2)).toEqual([3, 14]);
    expect(ready.runtime?.worker_fingerprint).toBe(seed.workerFingerprint);
    await walkthrough.getByRole("button", { name: "Next step", exact: true }).click();
    await walkthrough.getByRole("button", { name: "Next step", exact: true }).click();
    await expect(walkthrough.getByText("Step 3 of 6 · learning progress", { exact: true })).toBeVisible();
    // Source permission requires a separate native proof, even after global opt-in.
    const unproved = await page.request.post(`${state.origin}/v1/context-assistance/workspace-grant`, {
      headers: { "x-guard-token": state.daemonToken }, data: { input: { action: "grant", workspace: state.workspace, app: "dashboard", sources: ["README.md"] } },
    });
    expect([401, 403, 423]).toContain(unproved.status());
    await page.getByRole("tab", { name: "Projects & AI apps", exact: true }).click();
    await page.getByLabel("Workspace folder", { exact: true }).fill(state.workspace);
    await page.getByLabel("Files relative to the workspace, one per line").fill("README.md");
    await page.getByRole("button", { name: "Grant review source access" }).click();
    const sourceProof = page.getByRole("dialog");
    await sourceProof.getByLabel("Approval password").fill(state.approvalPassword);
    await sourceProof.getByRole("button", { name: "Grant source access", exact: true }).click();
    await expect(sourceProof).toHaveCount(0);
    await expect(page.getByText(/Recent native receipt facts: 0 of at most 16 retained/)).toBeVisible();
    await page.getByLabel("What would you like context about?").fill("reviewed release process");
    await page.getByRole("button", { name: "Prepare cited context" }).click();
    const prepared = page.getByRole("region", { name: "Prepared context", exact: true });
    await expect(prepared.getByText("Integration workspace uses a reviewed release process.", { exact: true })).toBeVisible();
    await prepared.getByText("Sources and revisions", { exact: true }).click();
    await expect(prepared.getByText(/README.md, lines/)).toBeVisible();
    writeFileSync(resolve(state.workspace, "README.md"), "Updated workspace now uses a different release procedure.\n");
    await page.getByRole("button", { name: "Prepare cited context" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "Sources or access changed" })).toBeVisible();
    await expect(prepared).toHaveCount(0);
    await page.getByRole("button", { name: "Refresh selected files" }).click();
    await expect(page.getByRole("button", { name: "Prepare cited context" })).toBeEnabled();
    await page.getByRole("button", { name: "Prepare cited context" }).click();
    await expect(prepared.getByText("Updated workspace now uses a different release procedure.", { exact: true })).toBeVisible();
    await prepared.getByText("Compare with earlier context", { exact: true }).click();
    await expect(prepared.getByText("Integration workspace uses a reviewed release process.", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Withdraw README.md" }).click();
    await expect(prepared).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Withdraw README.md" })).toHaveCount(0);
    await page.getByRole("button", { name: "Revoke workspace access" }).click();
    await expect(page.getByText("No workspace has context access.", { exact: true })).toBeVisible();
    // A real MCP client has no operator authority. Its public code is paired
    // by the browser only after separate native source and connection proofs.
    probe = new ContextAgentProbe(String(seed.pythonExecutable), state.guardHome);
    const initialTools = await probe.request("list");
    expect(initialTools.list_changed).toBe(true);
    expect(initialTools.tools).toContain("get_context_status");
    expect(initialTools.tools).not.toContain("get_guard_context");
    const pending = await probe.request("get_context_status");
    expect(pending.data.phase).toBe("pending");
    expect(JSON.stringify(pending)).not.toContain("credential");
    expect((await probe.request("get_guard_context", { query: "release procedure" })).ok).toBe(false);
    await page.getByRole("combobox", { name: "Context consumer", exact: true }).selectOption("codex");
    await page.getByLabel("Files relative to the workspace, one per line").fill("README.md");
    await page.getByRole("button", { name: "Grant review source access" }).click();
    const appSourceProof = page.getByRole("dialog");
    await appSourceProof.getByLabel("Approval password").fill(state.approvalPassword);
    await appSourceProof.getByRole("button", { name: "Grant source access", exact: true }).click();
    await expect(appSourceProof).toHaveCount(0);
    await page.getByRole("button", { name: "Refresh app connections", exact: true }).click();
    const connection = page.getByRole("region", { name: `Context connection ${pending.data.session_id}`, exact: true });
    await expect(connection.getByText("Waiting for your permission", { exact: false })).toBeVisible();
    await connection.getByRole("combobox", { name: "Workspace and app grant", exact: true }).selectOption({ index: 1 });
    const unprovedPair = await page.request.post(`${state.origin}/v1/context-assistance/workspace-grant`, {
      headers: { "x-guard-token": state.daemonToken }, data: { input: {
        action: "authorize_agent", session_id: pending.data.session_id,
        scope_id: await connection.getByRole("combobox", { name: "Workspace and app grant", exact: true }).inputValue(),
      } },
    });
    expect([401, 403, 423]).toContain(unprovedPair.status());
    await connection.getByRole("button", { name: "Authorize context connection", exact: true }).click();
    const pairingProof = page.getByRole("dialog");
    await expect(pairingProof).toContainText(pending.data.session_id);
    await expect(pairingProof).toContainText(state.workspace);
    await expect(pairingProof).toContainText("Codex");
    await pairingProof.getByLabel("Approval password").fill(state.approvalPassword);
    await pairingProof.getByRole("button", { name: "Authorize connection", exact: true }).click();
    await expect(pairingProof).toHaveCount(0);
    await expect(connection.getByText("Grant assigned", { exact: false })).toBeVisible();
    const authorized = await probe.request("get_context_status");
    expect(authorized.data.app).toBe("codex");
    expect(authorized.data.harness_route_qualification).toBe("not_established");
    const agentContext = await probe.request("get_guard_context", { query: "release procedure" });
    expect(agentContext.ok).toBe(true);
    const agentBrief = agentContext.data.result.brief;
    expect(agentBrief.rendered).toContain("Updated workspace now uses a different release procedure.");
    expect(agentBrief.citations.length).toBeGreaterThanOrEqual(2);
    expect((await probe.request("explain_guard_context", { snapshot_id: agentBrief.snapshot_id })).ok).toBe(true);
    expect((await probe.request("get_guard_context", { query: "release procedure", scope_id: "foreign", app: "cursor" })).ok).toBe(false);
    await page.getByRole("combobox", { name: "Context consumer", exact: true }).selectOption("dashboard");
    await page.getByLabel("Files relative to the workspace, one per line").fill("README.md");
    await page.getByRole("button", { name: "Grant review source access" }).click();
    const reviewSourceProof = page.getByRole("dialog");
    await reviewSourceProof.getByLabel("Approval password").fill(state.approvalPassword);
    await reviewSourceProof.getByRole("button", { name: "Grant source access", exact: true }).click();
    await expect(reviewSourceProof).toHaveCount(0);
    const nativeReview = JSON.parse(execFileSync(String(seed.pythonExecutable), ["-B",
      resolve(import.meta.dirname, "../../../scripts/ci/dashboard_context_native_review.py"),
      "--guard-home", state.guardHome, "--workspace", state.workspace], { encoding: "utf8", timeout: 15_000 }));
    expect((await probe.request("list")).tools).toContain("explain_guard_action");
    const nativeAgentContext = await probe.request("explain_guard_action", { decision_id: nativeReview.decision_id });
    expect(nativeAgentContext.ok).toBe(true);
    expect(nativeAgentContext.data.result.association.binding).toBe("authenticated_native_decision");
    expect(nativeAgentContext.data.result.association.execution_binding).toBe("unqualified");
    expect(nativeAgentContext.data.result.brief.citations.some((citation: { source: string }) => citation.source === "guard:action")).toBe(true);
    expect((await probe.request("explain_guard_action", { decision_id: nativeReview.decision_id,
      snapshot_id: nativeAgentContext.data.result.brief.snapshot_id })).ok).toBe(true);
    expect((await probe.request("explain_guard_action", { decision_id: nativeReview.decision_id, app: "cursor" })).ok).toBe(false);
    await page.goto(`/requests/${nativeReview.request_id}`);
    const optionalContext = page.getByRole("region", { name: "Optional decision context", exact: true });
    await expect(optionalContext).toBeVisible();
    const allowOnce = page.getByRole("button", { name: "Allow just this once", exact: true });
    const alwaysAllow = page.getByRole("radio", { name: /^Always allow exact action/ });
    await expect(allowOnce).toBeEnabled();
    await expect(alwaysAllow).toBeEnabled();
    await optionalContext.getByRole("button", { name: "Prepare decision context", exact: true }).click();
    await expect(allowOnce).toBeEnabled();
    const actionContext = optionalContext.getByRole("region", { name: "Native decision context", exact: true });
    await expect(actionContext.getByText(/Authenticated native Guard decision/)).toBeVisible();
    await actionContext.getByText("Sources and revisions", { exact: true }).click();
    await expect(actionContext.getByText(/Authenticated native decision facts, lines/)).toBeVisible();
    await optionalContext.getByRole("button", { name: "Verify context sources", exact: true }).click();
    await expect(optionalContext.getByText("The retained selection and its sources were verified again.", { exact: true })).toBeVisible();
    await expect(allowOnce).toBeEnabled();
    await expect(alwaysAllow).toBeEnabled();
    await contextHistoryAndRepairFlow(page, state, nativeReview, probe);
    await page.goto("/cigar?section=access");
    await page.getByRole("button", { name: "Refresh app connections", exact: true }).click();
    await connection.getByRole("button", { name: "Revoke context connection", exact: true }).click();
    await expect(connection).toHaveCount(0);
    const revoked = await probe.request("get_guard_context", { query: "release procedure" });
    expect(revoked.ok).toBe(false);
    expect(revoked.error.code).toBe("native_context_assistance_context_scope_denied");
    await clearContextFromRepair(page);
    await page.goto("/settings?section=protection");
    // An unrelated settings save must preserve raw local consent and the verified generation.
    const timeout = page.getByRole("spinbutton", { name: "How long to wait for your answer" });
    await timeout.fill(String(Number(await timeout.inputValue()) + 30));
    await saveWithProof(page, state);
    expect((await status()).requested_enabled).toBe(true);
    expect((await status()).effective_enabled).toBe(true);
    await page.reload();
    await page.goto("/cigar?section=runtime");
    await expect(toggle).toHaveAttribute("aria-checked", "true");
    await page.goto("/");
    const overview = page.getByRole("region", { name: "Context assistance overview" });
    await expect(overview.getByRole("status")).toHaveText("Ready");
    await overview.getByRole("button", { name: "Turn off context assistance", exact: true }).click();
    await expect(overview.getByRole("status")).toHaveText("Off");
    expect((await status()).requested_enabled).toBe(false);
    expect((await status()).runtime).toBeNull();
    expect((await probe.request("list")).tools).not.toContain("get_guard_context");
    const disabled = await probe.request("get_guard_context", { query: "release procedure" });
    expect(disabled.error.code).toBe("native_context_assistance_disabled");
    await overview.getByRole("button", { name: "Open CIGAR" }).click();
    await page.getByRole("tab", { name: "Settings", exact: true }).click();
    await expect(toggle).toHaveAttribute("aria-checked", "false");
    await page.getByRole("button", { name: "Refresh runtime list" }).click();
    await expect(page.getByLabel("Local runtime", { exact: true })).toHaveValue(String(seed.runtimeId));
    await expect(toggle).toBeEnabled();
    await toggle.click();
    await saveWithProof(page, state);
    await page.getByRole("button", { name: "Start context assistance" }).click();
    await expect.poll(async () => (await status()).effective_enabled, { timeout: 30_000 }).toBe(true);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByRole("tab", { name: "Projects & AI apps", exact: true }).click();
    await expect(page.getByText("No workspace has context access.", { exact: true })).toBeVisible();
    const off = page.getByRole("button", { name: "Turn off CIGAR", exact: true });
    await off.scrollIntoViewIfNeeded();
    await expect(off).toBeVisible();
    await stopContextAssistance(page, off);
    await expect.poll(async () => (await status()).requested_enabled).toBe(false);
    expect((await status()).runtime).toBeNull();
    await page.reload();
    await page.getByRole("tab", { name: "Settings", exact: true }).click();
    await expect(toggle).toHaveAttribute("aria-checked", "false");
    await expectNoErrorBoundary(page);
    // Browser-supplied runtime assertions cannot replace native verification.
    const forged = await page.request.post(`${state.origin}/v1/context-assistance/activate`, {
      headers: { "x-guard-token": state.daemonToken }, data: { python_version: [3, 14], approved: true },
    });
    expect(forged.status()).toBe(400);
    expect(await forged.json()).toEqual({
      error: "context_assistance_unavailable", code: "native_context_assistance_control_input_invalid",
    });
    expect((await status()).effective_enabled).toBe(false);
    await contextSharingFlow(page, state, saveWithProof);
  } finally {
    await daemonApi(state, "/v1/context-assistance/stop", { method: "POST", body: "{}" });
    await probe?.close();
  }
});
