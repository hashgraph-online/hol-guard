import { useCallback, useEffect, useMemo, useState } from "react";
import { HiMiniArrowDownTray } from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import type { EvidenceFilterState, EvidenceSortKey } from "./evidence-types";
import { sortEvidence } from "./evidence-sort";
import { EvidenceActionList } from "./evidence-action-list";
import { EvidenceExportDrawer } from "./evidence-export-drawer";
import { ActionButton } from "../approval-center-primitives";

const PAGE_SIZE = 50;

export type ScopedEvidenceTableProps = {
  receipts: GuardReceipt[];
  exportFilters: Pick<EvidenceFilterState, "harness" | "decision" | "category">;
  hideHarnessColumn?: boolean;
  tableLabel?: string;
  onFilterCategory?: (category: string) => void;
  onFilterHarness?: (harness: string) => void;
};

export function ScopedEvidenceTable({
  receipts,
  exportFilters,
  hideHarnessColumn = true,
  tableLabel = "Evidence actions",
  onFilterCategory,
  onFilterHarness,
}: ScopedEvidenceTableProps) {
  const [sort, setSort] = useState<EvidenceSortKey>("newest");
  const [page, setPage] = useState(0);
  const [selectedId, setSelectedId] = useState("");
  const [exportOpen, setExportOpen] = useState(false);

  const sorted = useMemo(() => sortEvidence(receipts, sort), [receipts, sort]);

  const exportFilterState = useMemo(
    (): EvidenceFilterState => ({
      search: "",
      time: "all",
      decision: exportFilters.decision,
      harness: exportFilters.harness,
      category: exportFilters.category,
      sourceScope: "",
      day: "",
      sort,
      view: "apps",
      selectedId: "",
    }),
    [exportFilters.decision, exportFilters.harness, exportFilters.category, sort],
  );

  useEffect(() => {
    setPage(0);
    setSelectedId("");
    setSort("newest");
  }, [receipts]);

  const handleSortChange = useCallback((next: EvidenceSortKey) => {
    setSort(next);
    setPage(0);
  }, []);

  const handleLoadMore = useCallback(() => {
    setPage((prev) => prev + 1);
  }, []);

  const handleSelectId = useCallback((id: string) => {
    setSelectedId((prev) => (prev === id ? "" : id));
  }, []);

  const handleOpenExport = useCallback(() => {
    setExportOpen(true);
  }, []);

  const handleCloseExport = useCallback(() => {
    setExportOpen(false);
  }, []);

  const noopHarness = useCallback(() => {}, []);
  // Parent owns filter state when onFilterCategory is omitted.
  const noopCategory = useCallback(() => {}, []);

  if (receipts.length === 0) {
    return (
      <div className="py-8 text-center">
        <p className="text-sm text-slate-500">No actions match the selected filters.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <ActionButton variant="outline" onClick={handleOpenExport}>
          <HiMiniArrowDownTray className="mr-1.5 h-4 w-4" aria-hidden="true" />
          Export filtered
        </ActionButton>
      </div>

      <EvidenceActionList
        receipts={sorted}
        selectedId={selectedId}
        onSelectId={handleSelectId}
        onFilterHarness={onFilterHarness ?? noopHarness}
        onFilterCategory={onFilterCategory ?? noopCategory}
        sort={sort}
        onSortChange={handleSortChange}
        page={page}
        pageSize={PAGE_SIZE}
        onLoadMore={handleLoadMore}
        hideHarnessColumn={hideHarnessColumn}
        tableLabel={tableLabel}
      />

      <EvidenceExportDrawer
        receipts={sorted}
        filters={exportFilterState}
        isOpen={exportOpen}
        onClose={handleCloseExport}
      />
    </div>
  );
}
