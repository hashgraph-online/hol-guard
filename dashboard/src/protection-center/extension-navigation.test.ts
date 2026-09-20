import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const workspaceSource = readFileSync(new URL("./protection-center-workspace.tsx", import.meta.url), "utf8");
const searchConsoleSource = readFileSync(new URL("./components/pattern-search-console.tsx", import.meta.url), "utf8");
const modalLayerSource = readFileSync(new URL("../guard-modal-layer.tsx", import.meta.url), "utf8");
const overlayRootSource = readFileSync(new URL("../guard-overlay-root.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../app.tsx", import.meta.url), "utf8");
const appDataSource = readFileSync(new URL("../use-app-data.ts", import.meta.url), "utf8");
const appRoutingSource = readFileSync(new URL("../app-routing.ts", import.meta.url), "utf8");

assert.match(workspaceSource, /data-testid="extensions-workspace"/);
assert.match(workspaceSource, /pushExtensionHistory/);
assert.match(workspaceSource, /replaceExtensionHistory/);
assert.doesNotMatch(workspaceSource, /window\.history\.pushState/);
assert.doesNotMatch(workspaceSource, /window\.history\.replaceState/);
assert.doesNotMatch(workspaceSource, /return <>/);

assert.match(searchConsoleSource, /role="searchbox"/);
assert.doesNotMatch(searchConsoleSource, /type="search"/);

assert.match(modalLayerSource, /ensureGuardOverlayRoot/);
assert.match(modalLayerSource, /setOverlayRoot\(ensureGuardOverlayRoot\(\)\)/);
assert.match(appRoutingSource, /input\[role="searchbox"\]/);
assert.match(appRoutingSource, /closest\("\[hidden\], \[inert\]"\)/);
assert.match(appRoutingSource, /function focusVisibleDashboardSearch/);
assert.match(appSource, /const data = useAppData\(\)/);
assert.match(appDataSource, /focusVisibleDashboardSearch,?\s*\} from "\.\/app-routing"/);
assert.match(appDataSource, /if \(focusVisibleDashboardSearch\(\)\)/);

assert.match(overlayRootSource, /guard-dashboard-root/);
assert.match(overlayRootSource, /insertBefore/);
assert.match(overlayRootSource, /nextSibling/);
assert.doesNotMatch(
  overlayRootSource,
  /document\.body\.appendChild/,
  "overlay root must be a sibling of guard-dashboard-root, not only document.body",
);

console.log("extension-navigation.test.ts: all assertions passed");
