import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";

const PROOF_DIR = resolve(
  "/tmp/hol-guard-user/.copilot/session-state/e7da8953-ad9e-4481-ad56-31e82b2339d2/files/proofs/scrg/phase12-scrg171-172",
);

const E2E_PORT = 4175;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: `http://127.0.0.1:${E2E_PORT}`,
    screenshot: "only-on-failure",
    trace: "off",
    viewport: { width: 1280, height: 800 },
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  outputDir: resolve(PROOF_DIR, "playwright-output"),
  webServer: {
    command: `node e2e/static-server.mjs ${E2E_PORT}`,
    url: `http://127.0.0.1:${E2E_PORT}`,
    reuseExistingServer: true,
    timeout: 30000,
  },
});
