import type { GuardReceipt } from "../guard-types";
import type { EvidenceSortKey } from "./evidence-types";
import { detectCategory } from "./categories";
import { harnessDisplayName } from "../approval-center-utils";

function stableCompare(a: GuardReceipt, b: GuardReceipt, primary: number): number {
  if (primary !== 0) return primary;
  return a.receipt_id < b.receipt_id ? -1 : a.receipt_id > b.receipt_id ? 1 : 0;
}

export function sortEvidence(
  receipts: GuardReceipt[],
  key: EvidenceSortKey
): GuardReceipt[] {
  const copy = [...receipts];

  if (key === "newest") {
    copy.sort((a, b) =>
      stableCompare(a, b, +new Date(b.timestamp) - +new Date(a.timestamp))
    );
    return copy;
  }

  if (key === "oldest") {
    copy.sort((a, b) =>
      stableCompare(a, b, +new Date(a.timestamp) - +new Date(b.timestamp))
    );
    return copy;
  }

  if (key === "app") {
    copy.sort((a, b) =>
      stableCompare(
        a,
        b,
        harnessDisplayName(a.harness).localeCompare(harnessDisplayName(b.harness))
      )
    );
    return copy;
  }

  if (key === "decision") {
    copy.sort((a, b) =>
      stableCompare(a, b, a.policy_decision.localeCompare(b.policy_decision))
    );
    return copy;
  }

  if (key === "category") {
    copy.sort((a, b) =>
      stableCompare(a, b, detectCategory(a).localeCompare(detectCategory(b)))
    );
    return copy;
  }

  if (key === "artifact") {
    copy.sort((a, b) => {
      const nameA = (a.artifact_name ?? a.artifact_id).toLowerCase();
      const nameB = (b.artifact_name ?? b.artifact_id).toLowerCase();
      return stableCompare(a, b, nameA.localeCompare(nameB));
    });
    return copy;
  }

  return copy;
}
