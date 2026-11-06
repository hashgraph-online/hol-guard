import type { GuardReceipt } from "../guard-types";
import type { EvidenceFilterState } from "./evidence-types";
import {
  exportReceiptsAsCsv,
  exportReceiptsAsJson,
  downloadBlob as baseDownloadBlob,
} from "../history-export";

export { downloadBlob } from "../history-export";

function buildFileSuffix(filters?: Partial<EvidenceFilterState>): string {
  if (!filters) return "";
  const parts: string[] = [];
  if (filters.decision && filters.decision !== "all")
    parts.push(filters.decision);
  if (filters.harness && filters.harness !== "all")
    parts.push(filters.harness);
  if (filters.time && filters.time !== "all") parts.push(filters.time);
  return parts.length > 0 ? `-${parts.join("-")}` : "";
}

export function exportEvidenceCsv(
  receipts: GuardReceipt[],
  filters?: Partial<EvidenceFilterState>
): { blob: Blob; filename: string } {
  const result = exportReceiptsAsCsv(receipts);
  const suffix = buildFileSuffix(filters);
  const today = new Date()
    .toISOString()
    .slice(0, 10);
  const filename = `hol-guard-evidence${suffix}-${today}.csv`;
  return { blob: result.blob, filename };
}

export function exportEvidenceJson(
  receipts: GuardReceipt[],
  filters?: Partial<EvidenceFilterState>
): { blob: Blob; filename: string } {
  const result = exportReceiptsAsJson(receipts, {
    decision: filters?.decision,
    harness: filters?.harness,
    time: filters?.time,
    search: filters?.search,
  });
  const suffix = buildFileSuffix(filters);
  const today = new Date()
    .toISOString()
    .slice(0, 10);
  const filename = `hol-guard-evidence${suffix}-${today}.json`;
  return { blob: result.blob, filename };
}

export function downloadEvidence(
  format: "csv" | "json",
  receipts: GuardReceipt[],
  filters?: Partial<EvidenceFilterState>
): void {
  const result =
    format === "csv"
      ? exportEvidenceCsv(receipts, filters)
      : exportEvidenceJson(receipts, filters);
  baseDownloadBlob(result.blob, result.filename);
}
