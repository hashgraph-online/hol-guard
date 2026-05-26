import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";
import { resolveProofDir } from "./e2e/proof-dir";

const PROOF_DIR = resolveProofDir();

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
