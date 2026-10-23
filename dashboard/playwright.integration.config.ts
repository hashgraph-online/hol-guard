import { defineConfig, devices } from "@playwright/test";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { resolveProofDir } from "./e2e/proof-dir";

// The integration suite runs the dashboard against a real, seeded Guard daemon.
// Playwright starts the daemon itself; scripts/ci/dashboard_integration_server.py
// rebuilds a fresh private Guard home on every start.
const port = Number(process.env.DASHBOARD_E2E_PORT ?? "4791");
const root = resolve(process.env.DASHBOARD_E2E_ROOT ?? resolve(tmpdir(), `hol-guard-dashboard-e2e-${port}`));
const python = process.env.DASHBOARD_E2E_PYTHON ?? "uv run --no-sync python";
process.env.DASHBOARD_E2E_ROOT = root;
process.env.DASHBOARD_E2E_PORT = String(port);

const chrome = process.env.CI ? { channel: "chrome" } : {};

export default defineConfig({
  testDir: "./e2e/integration",
  globalSetup: "./e2e/integration/global-setup.ts",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  workers: process.env.CI ? 4 : 2,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["github"]] : "list",
  outputDir: resolve(resolveProofDir(), "integration-output"),
  use: {
    ...devices["Desktop Chrome"],
    ...chrome,
    baseURL: `http://127.0.0.1:${port}`,
    screenshot: "only-on-failure",
    // Traces record URLs, and sidebar links carry the session in the fragment.
    // Keep them to local runs.
    trace: process.env.CI ? "off" : "retain-on-failure",
    viewport: { width: 1440, height: 1000 },
  },
  projects: [
    // Read-only specs share the seeded home and run in parallel.
    { name: "read", testIgnore: /\.mutating\.spec\.ts$/ },
    // Specs that change Guard state run one at a time after the read pass, so
    // no read-only assertion sees a half-applied change.
    {
      name: "mutating",
      testMatch: /\.mutating\.spec\.ts$/,
      dependencies: ["read"],
      fullyParallel: false,
      workers: 1,
    },
  ],
  webServer: {
    command: `${python} scripts/ci/dashboard_integration_server.py`,
    cwd: resolve(import.meta.dirname, ".."),
    url: `http://127.0.0.1:${port}/healthz`,
    reuseExistingServer: false,
    timeout: 90_000,
    stdout: "pipe",
    stderr: "pipe",
    env: { DASHBOARD_E2E_ROOT: root, DASHBOARD_E2E_PORT: String(port) },
  },
});
