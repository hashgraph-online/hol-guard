import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";

import { resolveProofDir } from "./e2e/proof-dir";

const origin = process.env.GUARD_INSTALLED_ORIGIN;
if (!origin) throw new Error("GUARD_INSTALLED_ORIGIN is required");

export default defineConfig({
  testDir: "./e2e",
  testMatch: [
    "installed-command-activity.spec.ts",
    "installed-extension-control-center.spec.ts",
    "installed-git-worktree-control.spec.ts",
  ],
  fullyParallel: false,
  // Both policy specs mutate the one installed authority, so they must not
  // race each other for the current revision.
  workers: 1,
  retries: 0,
  reporter: "list",
  outputDir: resolve(resolveProofDir(), "playwright-output"),
  use: {
    ...devices["Desktop Chrome"],
    baseURL: origin,
    screenshot: "only-on-failure",
    trace: "off",
    viewport: { width: 1440, height: 1000 },
  },
});