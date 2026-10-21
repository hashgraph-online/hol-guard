import { useCallback, useState } from "react";

import { ActionButton } from "../approval-center-primitives";
import { repairProtectionCheck } from "../guard-api";

type RepairState = { kind: "idle" } | { kind: "repairing" } | { kind: "failed"; message: string };

// Kept local so this notice does not pull the lazily loaded repair page into
// the main bundle.
const PROTECTION_REPAIR_ROUTE = "/protection/repair";
const REPAIR_FAILED_COPY = "Guard could not repair the command evidence store.";

export function CommandActivityHealthNotice(props: { copy: string; onRepaired: () => void }) {
  const [repair, setRepair] = useState<RepairState>({ kind: "idle" });
  const { onRepaired } = props;

  const handleRepair = useCallback(() => {
    setRepair({ kind: "repairing" });
    repairProtectionCheck("decision_stream")
      .then((result) => {
        if (result.repaired) {
          setRepair({ kind: "idle" });
          onRepaired();
          return;
        }
        setRepair({ kind: "failed", message: result.message || REPAIR_FAILED_COPY });
      })
      .catch((error: unknown) => {
        setRepair({ kind: "failed", message: error instanceof Error && error.message ? error.message : REPAIR_FAILED_COPY });
      });
  }, [onRepaired]);

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900" role="status">
      <div className="min-w-0 space-y-1">
        <p>{props.copy}</p>
        {repair.kind === "failed" ? <p className="text-xs">{repair.message}</p> : null}
      </div>
      <div className="flex shrink-0 flex-wrap gap-2">
        <ActionButton variant="outline" onClick={handleRepair} disabled={repair.kind === "repairing"}>
          {repair.kind === "repairing" ? "Repairing…" : "Repair evidence"}
        </ActionButton>
        {repair.kind === "failed" ? (
          <ActionButton variant="ghost" href={PROTECTION_REPAIR_ROUTE}>Open Protect repair</ActionButton>
        ) : null}
      </div>
    </div>
  );
}
