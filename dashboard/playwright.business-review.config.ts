import { defineConfig } from "@playwright/test";
import base from "./playwright.config";

export default defineConfig({
  ...base,
  testMatch: "business-review-summary.spec.ts",
  use: { ...base.use, baseURL: "http://127.0.0.1:4277" },
  webServer: {
    command: "node e2e/static-server.mjs 4277",
    url: "http://127.0.0.1:4277",
    reuseExistingServer: false,
    timeout: 30000,
  },
});
