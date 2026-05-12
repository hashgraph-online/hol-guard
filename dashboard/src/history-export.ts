import type { GuardReceipt } from "./guard-types";
import { harnessDisplayName } from "./approval-center-utils";

export interface ExportFilters {
  search?: string;
  time?: string;
  decision?: string;
  harness?: string;
}

export function exportReceiptsAsCsv(
  receipts: GuardReceipt[],
  filters?: ExportFilters
): { blob: Blob; filename: string } {
  const headers = [
    "timestamp",
    "date_iso",
    "harness",
    "artifact_id",
    "artifact_name",
    "policy_decision",
    "artifact_hash",
    "capabilities_summary",
    "provenance_summary",
    "source_scope",
  ];

  const rows = receipts.map((r) => [
    r.timestamp,
    formatDateIso(new Date(r.timestamp)),
    r.harness,
    r.artifact_id,
    r.artifact_name ?? "",
    r.policy_decision,
    r.artifact_hash,
    r.capabilities_summary ?? "",
    r.provenance_summary ?? "",
    r.source_scope ?? "",
  ]);

  const csv = [headers.join(","), ...rows.map((row) => row.map(escapeCsvCell).join(","))].join("\n");

  const today = formatDateIso(new Date());
  const fromDate = receipts.length > 0 ? formatDateIso(new Date(receipts[receipts.length - 1].timestamp)) : "all";
  const toDate = receipts.length > 0 ? formatDateIso(new Date(receipts[0].timestamp)) : "all";
  const filename = `guard-history-${today}-${fromDate}-to-${toDate}.csv`;

  return { blob: new Blob([csv], { type: "text/csv;charset=utf-8;" }), filename };
}

export function exportReceiptsAsJson(
  receipts: GuardReceipt[],
  filters?: ExportFilters
): { blob: Blob; filename: string } {
  const payload: {
    exported_at: string;
    filter_summary: ExportFilters | Record<string, never>;
    total_rows: number;
    items: GuardReceipt[];
  } = {
    exported_at: new Date().toISOString(),
    filter_summary: filters ?? {},
    total_rows: receipts.length,
    items: receipts,
  };

  const today = formatDateIso(new Date());
  const fromDate = receipts.length > 0 ? formatDateIso(new Date(receipts[receipts.length - 1].timestamp)) : "all";
  const toDate = receipts.length > 0 ? formatDateIso(new Date(receipts[0].timestamp)) : "all";
  const filename = `guard-history-${today}-${fromDate}-to-${toDate}.json`;

  return { blob: new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }), filename };
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function escapeCsvCell(value: string): string {
  const needsQuotes = /[",\n\r]/.test(value);
  if (needsQuotes) {
    return `"${value.replaceAll("\"", "\"\"")}"`;
  }
  return value;
}

function formatDateIso(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}
