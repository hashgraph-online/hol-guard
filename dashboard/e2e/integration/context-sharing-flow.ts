import { daemonApi, expect, expectNoErrorBoundary, type IntegrationState } from "./fixtures";
import type { Page } from "@playwright/test";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { ContextAgentProbe } from "./context-agent-probe";
import { contextStatus } from "./context-status";
import { contextPairingCapacityFlow } from "./context-pairing-capacity-flow";

export async function contextSharingFlow(page: Page, state: IntegrationState, save: (page: Page, state: IntegrationState) => Promise<void>) {
  const seed = state.seeded.context_assistance;
  const status = () => contextStatus(state);
  await page.goto("/cigar?section=runtime");
  await page.getByRole("button", { name: "Refresh runtime list", exact: true }).click();
  for (const name of ["Use CIGAR on this machine", "Context for AI apps", "Share context between paired AI connections"]) {
    const toggle = page.getByRole("switch", { name, exact: true });
    if (await toggle.getAttribute("aria-checked") !== "true") await toggle.click();
  }
  await save(page, state);
  await page.getByRole("button", { name: "Start context assistance", exact: true }).click();
  await expect.poll(async () => (await status()).runtime?.shared_compile_verified, { timeout: 30_000 }).toBe(true);
  await page.getByRole("tab", { name: "Sources & AI apps", exact: true }).click();
  writeFileSync(resolve(state.workspace, "README.md"), "Shared deployment workspace uses a reviewed release process.\n");
  const probes = [new ContextAgentProbe(String(seed.pythonExecutable), state.guardHome), new ContextAgentProbe(String(seed.pythonExecutable), state.guardHome)];
  try {
    const pending = [];
    for (const probe of probes) {
      expect((await probe.request("list")).tools).not.toContain("propose_guard_context_note");
      pending.push((await probe.request("get_context_status")).data);
    }
    await page.getByRole("combobox", { name: "Context consumer", exact: true }).selectOption("codex");
    await page.getByLabel("Workspace folder", { exact: true }).fill(state.workspace);
    await page.getByLabel("Files relative to the workspace, one per line").fill("README.md");
    await page.getByRole("checkbox", { name: "Allow reviewed shared notes in this app's context", exact: true }).check();
    await page.getByRole("checkbox", { name: "Allow paired connections to propose shared notes", exact: true }).check();
    await page.getByRole("button", { name: "Grant review source access", exact: true }).click();
    const sourceProof = page.getByRole("dialog");
    await sourceProof.getByLabel("Approval password").fill(state.approvalPassword);
    await sourceProof.getByRole("button", { name: "Grant source access", exact: true }).click();
    await expect(sourceProof).toHaveCount(0);
    for (const connection of pending) {
      await page.getByRole("button", { name: "Refresh app connections", exact: true }).click();
      const region = page.getByRole("region", { name: `Context connection ${connection.session_id}`, exact: true });
      await region.getByRole("combobox", { name: "Workspace and app grant", exact: true }).selectOption({ index: 1 });
      await region.getByRole("button", { name: "Authorize context connection", exact: true }).click();
      const proof = page.getByRole("dialog");
      await proof.getByLabel("Approval password").fill(state.approvalPassword);
      await proof.getByRole("button", { name: "Authorize connection", exact: true }).click();
      await expect(proof).toHaveCount(0);
      await expect(region.getByText(/Grant assigned/)).toBeVisible();
    }
    await contextPairingCapacityFlow(page, state);
    const [a, b] = probes;
    for (const probe of probes) expect((await probe.request("list")).tools).toContain("propose_guard_context_note");
    const first = await a.request("get_guard_context", { query: "reviewed release process" });
    expect(first.ok).toBe(true);
    const snapshot = first.data.result.brief.snapshot_id;
    const note = "Shared release checklist: require the deployment review.";
    const proposed = await a.request("propose_guard_context_note", { snapshot_id: snapshot, request_key: "browser:one", text: note });
    expect(proposed.ok).toBe(true);
    expect(proposed.data.outcome.status).toBe("pending");
    const hidden = await b.request("get_guard_context", { query: "shared release checklist deployment review" });
    expect(hidden.ok).toBe(true);
    expect(hidden.data.result.brief.rendered).not.toContain(note);
    const notes = page.getByRole("region", { name: "Reviewed shared notes", exact: true });
    await notes.getByRole("button", { name: "Refresh proposals", exact: true }).click();
    const open = notes.getByRole("button", { name: `Review ${proposed.data.proposal_id}`, exact: true });
    await open.focus(); await page.keyboard.press("Enter");
    const detail = notes.getByRole("region", { name: "Shared note proposal", exact: true });
    await expect(detail.getByText(note, { exact: true }).first()).toBeVisible();
    const unproved = await page.request.post(`${state.origin}/v1/context-assistance/workspace-grant`, {
      headers: { "x-guard-token": state.daemonToken }, data: { input: { action: "admit_proposal", scope_id: pending[0].scope_id ?? (await a.request("get_context_status")).data.scope_id,
        proposal_id: proposed.data.proposal_id } },
    });
    expect([401, 403, 423]).toContain(unproved.status());
    await detail.getByRole("button", { name: "Admit shared note", exact: true }).click();
    const admission = page.getByRole("dialog");
    await expect(admission).toContainText("supporting evidence");
    await admission.getByLabel("Approval password").fill(state.approvalPassword);
    await admission.getByRole("button", { name: "Admit shared note", exact: true }).click();
    await expect(admission).toHaveCount(0);
    await expect.poll(async () => (await a.request("get_guard_context_proposal_status", { request_key: "browser:one" })).data?.outcome?.status).toBe("admitted");
    const shared = await b.request("get_guard_context", { query: "shared release checklist deployment review" });
    expect(shared.ok).toBe(true);
    expect(shared.data.result.brief.rendered).toContain(note);
    expect(shared.data.result.brief.citations.some((citation: { source: string }) => citation.source === "guard:notes")).toBe(true);
    const current = await a.request("get_guard_context", { query: "shared release checklist deployment review" });
    const secondText = "Additional shared checklist note awaiting review.";
    const second = await a.request("propose_guard_context_note", { snapshot_id: current.data.result.brief.snapshot_id, request_key: "browser:two", text: secondText });
    expect(second.ok).toBe(true);
    await notes.getByRole("button", { name: "Refresh proposals", exact: true }).click();
    await notes.getByRole("button", { name: `Review ${second.data.proposal_id}`, exact: true }).click();
    await expect(detail.getByText("Proposed changes", { exact: true })).toBeVisible();
    await expect(detail.getByText(secondText, { exact: true }).first()).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    const reject = detail.getByRole("button", { name: "Reject proposal", exact: true });
    await reject.focus(); await page.keyboard.press("Enter");
    await expect.poll(async () => (await a.request("get_guard_context_proposal_status", { request_key: "browser:two" })).data?.outcome?.status).toBe("rejected");
    writeFileSync(resolve(state.workspace, "README.md"), "Changed release guidance requires the revised review process.\n");
    expect((await b.request("explain_guard_context", { snapshot_id: shared.data.result.brief.snapshot_id })).ok).toBe(false);
    await page.getByRole("button", { name: "Refresh selected files", exact: true }).click();
    await expect(notes.getByText(/0 admitted notes/)).toBeVisible();
    const refreshed = await b.request("get_guard_context", { query: "shared release checklist deployment review" });
    expect(refreshed.ok).toBe(true); expect(refreshed.data.result.brief.rendered).not.toContain(note);
    await notes.getByRole("button", { name: "Clear shared notes and proposals", exact: true }).click();
    await expect(notes.getByText(/No retained proposals/)).toBeVisible();
    await page.getByRole("button", { name: "Refresh app connections", exact: true }).click();
    await page.getByRole("region", { name: `Context connection ${pending[1].session_id}`, exact: true }).getByRole("button", { name: "Revoke context connection", exact: true }).click();
    await expect(page.getByRole("region", { name: `Context connection ${pending[1].session_id}`, exact: true })).toHaveCount(0);
    expect((await b.request("get_guard_context", { query: "release" })).ok).toBe(false);
    await page.getByRole("button", { name: "Turn off CIGAR", exact: true }).click();
    await expect.poll(async () => (await status()).requested_enabled).toBe(false);
    expect((await a.request("list")).tools).not.toContain("propose_guard_context_note");
    expect((await a.request("get_guard_context_proposal_status", { request_key: "browser:one" })).error.code).toBe("native_context_assistance_disabled");
    await expectNoErrorBoundary(page);
  } finally {
    await daemonApi(state, "/v1/context-assistance/stop", { method: "POST", body: "{}" });
    for (const probe of probes) await probe.close();
  }
}
