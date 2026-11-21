import { defineConfig } from "@playwright/test";
import base from "./playwright.config";

const port = 5197;

export default defineConfig({
  ...base,
  testMatch: ["mcp-catalog-discovery.spec.ts", "observed-mcp-extension.spec.ts", "local-skill-metadata.spec.ts"],
  use: { ...base.use, baseURL: `http://127.0.0.1:${port}` },
  webServer: {
    command: `node e2e/static-server.mjs ${port}`,
    url: `http://127.0.0.1:${port}`,
    reuseExistingServer: false,
    timeout: 30000,
  },
});
