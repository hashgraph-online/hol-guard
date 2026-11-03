import { expect, test as base, type Page, type Response } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// State the integration server hands over in a mode-0600 file. See
// scripts/ci/dashboard_integration_server.py.
export type IntegrationState = {
  origin: string;
  session: string;
  daemonToken: string;
  approvalPassword: string;
  guardHome: string;
  workspace: string;
  seeded: Record<string, Record<string, unknown>>;
};

let cachedState: IntegrationState | undefined;

export async function readIntegrationState(): Promise<IntegrationState> {
  if (cachedState) return cachedState;
  const root = process.env.DASHBOARD_E2E_ROOT;
  if (!root) throw new Error("DASHBOARD_E2E_ROOT is not set; run with playwright.integration.config.ts");
  const path = resolve(root, "state.json");
  // The daemon answers /healthz a moment before the server writes the state
  // file, so wait briefly for it.
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      cachedState = JSON.parse(readFileSync(path, "utf8")) as IntegrationState;
      return cachedState;
    } catch {
      await new Promise((done) => setTimeout(done, 100));
    }
  }
  throw new Error(`integration state file never appeared at ${path}`);
}

export type ServerErrors = { failures: string[] };

type Fixtures = {
  state: IntegrationState;
  serverErrors: ServerErrors;
  // Authenticated page. Fails the test if any daemon API call returns 5xx.
  page: Page;
};

export const test = base.extend<Fixtures>({
  // biome-ignore lint/correctness/noEmptyPattern: Playwright fixture signature.
  state: async ({}, use) => {
    await use(await readIntegrationState());
  },
  serverErrors: async ({}, use) => {
    await use({ failures: [] });
  },
  page: async ({ page, state, serverErrors }, use) => {
    const pending: Promise<void>[] = [];
    page.on("response", (response: Response) => {
      if (response.status() < 500 || !response.url().startsWith(state.origin)) return;
      const label = `${response.status()} ${response.request().method()} ${new URL(response.url()).pathname}`;
      pending.push(
        response
          .text()
          .then((body) => body.slice(0, 300))
          .catch(() => "")
          .then((body) => {
            serverErrors.failures.push(body ? `${label}: ${body}` : label);
          }),
      );
    });
    await page.addInitScript(
      ({ daemon, token }) => {
        sessionStorage.setItem("guard-token", token);
        sessionStorage.setItem("guardDaemon", daemon);
      },
      { daemon: state.origin, token: state.session },
    );
    await use(page);
    await Promise.all(pending);
    expect(serverErrors.failures, "daemon returned 5xx responses").toEqual([]);
  },
});

export { expect };

// Fails when the dashboard's error boundary replaced the screen.
export async function expectNoErrorBoundary(page: Page): Promise<void> {
  await expect(page.getByRole("button", { name: "Reload dashboard" })).toHaveCount(0);
}

// Call the daemon API directly with the daemon token, for setup and for
// checking that a browser action really changed Guard's state.
export async function daemonApi<T>(state: IntegrationState, path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("x-guard-token", state.daemonToken);
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  const response = await fetch(new URL(path, state.origin), { ...init, headers });
  if (!response.ok) throw new Error(`${init.method ?? "GET"} ${path} -> ${response.status}`);
  return (await response.json()) as T;
}
