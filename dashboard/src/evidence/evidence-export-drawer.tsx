import { useCallback, useState } from "react";
import {
  HiMiniXMark,
  HiMiniArrowDownTray,
} from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import type { EvidenceFilterState } from "./evidence-types";
import { downloadEvidence } from "./evidence-export";
import { exportDiagnostics } from "../guard-api";
import { downloadBlob } from "../history-export";
import { ActionButton, SectionLabel } from "../approval-center-primitives";

interface EvidenceExportDrawerProps {
  receipts: GuardReceipt[];
  filters: EvidenceFilterState;
  isOpen: boolean;
  onClose: () => void;
}

type ExportStatus = "idle" | "success" | "error";

export function EvidenceExportDrawer({
  receipts,
  filters,
  isOpen,
  onClose,
}: EvidenceExportDrawerProps) {
  const [status, setStatus] = useState<ExportStatus>("idle");

  const handleCsvExport = useCallback(() => {
    try {
      downloadEvidence("csv", receipts, filters);
      setStatus("success");
      setTimeout(() => setStatus("idle"), 3000);
    } catch {
      setStatus("error");
    }
  }, [receipts, filters]);

  const handleJsonExport = useCallback(() => {
    try {
      downloadEvidence("json", receipts, filters);
      setStatus("success");
      setTimeout(() => setStatus("idle"), 3000);
    } catch {
      setStatus("error");
    }
  }, [receipts, filters]);

  const handleDiagnosticsExport = useCallback(async () => {
    try {
      const blob = await exportDiagnostics();
      const today = new Date().toISOString().slice(0, 10);
      downloadBlob(blob, `hol-guard-diagnostics-${today}.json`);
      setStatus("success");
      setTimeout(() => setStatus("idle"), 3000);
    } catch {
      setStatus("error");
    }
  }, []);

  if (!isOpen) return null;

  const isEmpty = receipts.length === 0;

  const dateRange =
    receipts.length > 0
      ? (() => {
          const timestamps = receipts.map((r) => r.timestamp).sort();
          const from = new Date(timestamps[0]).toLocaleDateString(undefined, {
            month: "short",
            day: "numeric",
            year: "numeric",
          });
          const to = new Date(
            timestamps[timestamps.length - 1]
          ).toLocaleDateString(undefined, {
            month: "short",
            day: "numeric",
            year: "numeric",
          });
          return from === to ? from : `${from} – ${to}`;
        })()
      : null;

  return (
    <div
      role="dialog"
      aria-label="Export evidence"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-end sm:items-center justify-center"
    >
      <div
        className="absolute inset-0 bg-black/30 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <div className="relative w-full max-w-md rounded-t-2xl sm:rounded-2xl bg-white shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4">
          <h2 className="text-base font-semibold text-brand-dark">
            Export evidence
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close export drawer"
            className="flex h-8 w-8 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 hover:text-slate-600 transition-colors"
          >
            <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-4">
          <div className="rounded-lg bg-slate-50 px-4 py-3 text-sm space-y-1">
            <p className="font-medium text-brand-dark">
              {isEmpty
                ? "No records to export"
                : `${receipts.length} record${receipts.length !== 1 ? "s" : ""}`}
            </p>
            {dateRange && (
              <p className="text-xs text-slate-500">Date range: {dateRange}</p>
            )}
            {(filters.decision !== "all" ||
              filters.harness !== "all" ||
              filters.search) && (
              <p className="text-xs text-slate-500">Active filters applied</p>
            )}
          </div>

          {status === "success" && (
            <p className="text-sm font-medium text-green-700 bg-green-50 rounded-lg px-4 py-2.5">
              Export downloaded successfully.
            </p>
          )}

          {status === "error" && (
            <p className="text-sm font-medium text-brand-attention bg-amber-50 rounded-lg px-4 py-2.5">
              Export failed. Please try again.
            </p>
          )}

          <div className="flex flex-col gap-2">
            <ActionButton
              onClick={handleCsvExport}
              disabled={isEmpty}
            >
              <HiMiniArrowDownTray className="h-4 w-4" aria-hidden="true" />
              Download CSV
            </ActionButton>
            <ActionButton
              variant="outline"
              onClick={handleJsonExport}
              disabled={isEmpty}
            >
              <HiMiniArrowDownTray className="h-4 w-4" aria-hidden="true" />
              Download JSON
            </ActionButton>
            <ActionButton
              variant="outline"
              onClick={handleDiagnosticsExport}
            >
              <HiMiniArrowDownTray className="h-4 w-4" aria-hidden="true" />
              Download diagnostics
            </ActionButton>
          </div>
        </div>
      </div>
    </div>
  );
}
