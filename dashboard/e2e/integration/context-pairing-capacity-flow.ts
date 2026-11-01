import type { Page, Response, Route } from "@playwright/test";
import { daemonApi, expect, type IntegrationState } from "./fixtures";
import { ContextAgentProbe } from "./context-agent-probe";

// A classified capacity response is injected only at the browser boundary.
// Native saturation and removal of refused authority have separate real tests.
export async function contextPairingCapacityFlow(page: Page, state: IntegrationState) {
  const probe = new ContextAgentProbe(String(state.seeded.context_assistance.pythonExecutable), state.guardHome);
  let sessionId: string | null = null;
  let pairingRequests = 0, completedPolls = 0;
  const capturePoll = (response: Response) => {
    if (response.status() === 200 && response.url().endsWith("/v1/context-assistance/workspace")
      && response.request().postDataJSON()?.input?.action === "list_agents") completedPolls += 1;
  };
  const refusePairing = async (route: Route) => {
    if (route.request().postDataJSON()?.input?.session_id !== sessionId) return route.continue();
    pairingRequests += 1;
    await route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({
      code: "native_context_assistance_context_resource_limit", message: "private-server-diagnostic-must-not-render",
    }) });
  };
  try {
    const pending = (await probe.request("get_context_status")).data;
    expect(typeof pending.session_id).toBe("string");
    sessionId = pending.session_id;
    page.on("response", capturePoll);
    await page.route("**/v1/context-assistance/workspace-grant", refusePairing);
    await page.getByRole("button", { name: "Refresh app connections", exact: true }).click();
    const region = page.getByRole("region", { name: `Context connection ${pending.session_id}`, exact: true });
    await region.getByRole("combobox", { name: "Workspace and app grant", exact: true }).selectOption({ index: 1 });
    await region.getByRole("button", { name: "Authorize context connection", exact: true }).click();
    const proof = page.getByRole("dialog");
    await proof.getByLabel("Approval password").fill(state.approvalPassword);
    const before = completedPolls;
    await proof.getByRole("button", { name: "Authorize connection", exact: true }).click();
    await expect(proof).toContainText("Context client capacity is full.");
    await expect.poll(() => completedPolls - before, { timeout: 10_000 }).toBeGreaterThanOrEqual(2);
    await expect(proof).toContainText("pair its new code");
    await expect(page.getByText("private-server-diagnostic-must-not-render", { exact: false })).toHaveCount(0);
    expect(pairingRequests).toBe(1);
    await proof.getByRole("button", { name: "Go back", exact: true }).click();
    await expect(proof).toHaveCount(0);
  } finally {
    try {
      await page.unroute("**/v1/context-assistance/workspace-grant", refusePairing);
      if (sessionId) await daemonApi(state, "/v1/context-assistance/workspace-access", { method: "POST", body: JSON.stringify({
        input: { action: "revoke_agent", session_id: sessionId },
      }) });
    } finally {
      page.off("response", capturePoll);
      await probe.close();
    }
  }
}
