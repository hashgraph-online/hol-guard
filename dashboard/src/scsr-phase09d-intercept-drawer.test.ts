import { parsePackageFirewallActionResult } from "./supply-chain-firewall-action-result";
import { parseInterceptProofSnapshot } from "./supply-chain-intercept-proof";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const provedPayload = {
  operation: "test",
  status: "completed",
  result: "completed",
  result_detail: {
    intercept_proved: true,
    tested_managers: ["npm"],
    path_repair_required: [],
    manager_results: [
      {
        manager: "npm",
        intercept_ran: true,
        evaluator_invoked: true,
      },
    ],
  },
  receipt: {
    id: "receipt-test-1",
    operation: "test",
    status: "completed",
    timestamp: "2026-06-09T16:00:00.000Z",
  },
};

const failedPayload = {
  operation: "test",
  status: "completed",
  result_detail: {
    intercept_proved: false,
    tested_managers: ["npm"],
    path_repair_required: ["npm"],
    manager_results: [
      {
        manager: "npm",
        intercept_ran: false,
        skipped_reason: "path_inactive",
      },
    ],
  },
};

const proved = parseInterceptProofSnapshot(provedPayload);
assert(proved !== null, "SCSR157: intercept proof snapshot parses from test response");
assert(proved!.interceptProved, "SCSR157: intercept_proved true surfaces in snapshot");
assert(proved!.managerResults.length === 1, "SCSR157: manager_results normalize");
assert(proved!.receiptId === "receipt-test-1", "SCSR157: proof receipt id surfaces");
assert(proved!.tone === "success", "SCSR157: proved test uses success tone");

const failed = parseInterceptProofSnapshot(failedPayload);
assert(failed !== null, "SCSR157-B: failed intercept proof still parses");
assert(!failed!.interceptProved, "SCSR157-B: intercept_proved false preserved");
assert(
  failed!.managerResults[0]?.skippedReason === "path_inactive",
  "SCSR157-B: skipped reason preserved",
);
assert(
  failed!.pathRepairRequired.includes("npm"),
  "SCSR157-B: path repair managers preserved",
);

const parsedResult = parsePackageFirewallActionResult("test", failedPayload);
assert(parsedResult !== null, "SCSR157-C: action result parser handles intercept proof");
assert(parsedResult!.tone === "warning", "SCSR157-C: failed intercept proof warns in inline result");
assert(
  parsedResult!.lines.some((line) => line.includes("path inactive")),
  "SCSR157-C: skipped reason appears in inline lines",
);

console.log("scsr-phase09d-intercept-drawer.test.ts: all assertions passed");
