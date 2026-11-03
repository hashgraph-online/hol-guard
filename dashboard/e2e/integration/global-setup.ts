import { existsSync } from "node:fs";
import { resolve } from "node:path";

// The daemon answers /healthz before the server has seeded it, warmed its
// extension catalog and written the state file. Wait for that file once here,
// so a server that fails during setup stops the run instead of failing every
// spec on its own timeout.
export default async function globalSetup(): Promise<void> {
  const root = process.env.DASHBOARD_E2E_ROOT;
  if (!root) throw new Error("DASHBOARD_E2E_ROOT is not set; run with playwright.integration.config.ts");
  const path = resolve(root, "state.json");
  const deadline = Date.now() + 90_000;
  while (!existsSync(path)) {
    if (Date.now() > deadline) {
      throw new Error(`integration server never finished setup; see the [WebServer] output above (${path})`);
    }
    await new Promise((done) => setTimeout(done, 250));
  }
}
