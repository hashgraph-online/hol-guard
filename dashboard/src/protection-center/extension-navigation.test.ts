import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const workspaceSource = readFileSync(new URL("./protection-center-workspace.tsx", import.meta.url), "utf8");
const searchConsoleSource = readFileSync(new URL("./components/pattern-search-console.tsx", import.meta.url), "utf8");
const modalLayerSource = readFileSync(new URL("../guard-modal-layer.tsx", import.meta.url), "utf8");
const overlayRootSource = readFileSync(new URL("../guard-overlay-root.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../app.tsx", import.meta.url), "utf8");

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
assert.match(appSource, /input\[role="searchbox"\]/);
assert.match(appSource, /closest\("\[hidden\], \[inert\]"\)/);
assert.match(appSource, /function focusVisibleDashboardSearch/);

assert.match(overlayRootSource, /guard-dashboard-root/);
assert.match(overlayRootSource, /insertBefore/);
assert.match(overlayRootSource, /nextSibling/);
assert.doesNotMatch(
  overlayRootSource,
  /document\.body\.appendChild/,
  "overlay root must be a sibling of guard-dashboard-root, not only document.body",
);

console.log("extension-navigation.test.ts: all assertions passed");
