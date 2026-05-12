import { shouldShowFirstRunGuide } from "./apps/app-detail-workspace";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(
  shouldShowFirstRunGuide({ status: "unknown", totalActions: 0, inventoryCount: 0, pendingCount: 0 }),
  "inactive app with no data should show first-run guide"
);

assert(
  shouldShowFirstRunGuide({ status: "needs_setup", totalActions: 0, inventoryCount: 0, pendingCount: 0 }),
  "known inactive app with no data should show first-run guide"
);

assert(
  !shouldShowFirstRunGuide({ status: "active", totalActions: 0, inventoryCount: 0, pendingCount: 0 }),
  "active app should not show first-run guide"
);

assert(
  !shouldShowFirstRunGuide({ status: "observed", totalActions: 1, inventoryCount: 0, pendingCount: 0 }),
  "app with history should show activity overview instead of first-run guide"
);

assert(
  !shouldShowFirstRunGuide({ status: "unknown", totalActions: 0, inventoryCount: 0, pendingCount: 1 }),
  "app with pending review should prioritize review queue"
);
