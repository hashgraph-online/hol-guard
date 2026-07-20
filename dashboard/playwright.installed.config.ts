import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";

import { resolveProofDir } from "./e2e/proof-dir";

const origin = process.env.GUARD_INSTALLED_ORIGIN;
if (!origin) throw new Error("GUARD_INSTALLED_ORIGIN is required");

export default defineConfig({
  testDir: "./e2e",
  testMatch: "installed-command-activity.spec.ts",
  fullyParallel: false,
  retries: 0,
  reporter: "list",
  outputDir: resolve(resolveProofDir(), "playwright-output"),
  use: {
    ...devices["Desktop Chrome"],
    baseURL: origin,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    viewport: { width: 1440, height: 1000 },
  },
});
