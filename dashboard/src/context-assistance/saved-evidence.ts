import { ContextAssistanceApiError } from "./api";

export type SavedEvidence = {
  schema: "guard-cigar-saved-evidence.v1";
  status: "empty" | "saved" | "busy" | "repair_required" | "unavailable" | "unsupported";
  slots: number | null; active_slots: number | null; bytes: number | null;
  max_slots: 8; max_bytes: 553648128;
  unresolved_writes: number | null; invalid_records: number | null; expired_slots: number | null;
  diagnostic: string | null; authority_restored: false; storage: "private_posix_files";
};
const count = (value: unknown, max: number) => Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= max;
export function parseSavedEvidence(value: unknown): SavedEvidence {
  const v = value as Record<string, unknown> | null;
  if (!v || typeof v !== "object" || Array.isArray(v) || v.schema !== "guard-cigar-saved-evidence.v1"
      || !["empty", "saved", "busy", "repair_required", "unavailable", "unsupported"].includes(String(v.status))
      || v.max_slots !== 8 || v.max_bytes !== 553648128 || v.authority_restored !== false || v.storage !== "private_posix_files"
      || !(v.diagnostic === null || typeof v.diagnostic === "string" && /^[a-z0-9_]{1,160}$/.test(v.diagnostic))
      || !["slots", "active_slots", "unresolved_writes", "invalid_records", "expired_slots"].every((k) => v[k] === null || count(v[k], 8))
      || !(v.bytes === null || count(v.bytes, 553648128))
      || (v.slots !== null && ["active_slots", "unresolved_writes", "invalid_records", "expired_slots"].some((k) => v[k] !== null && Number(v[k]) > Number(v.slots)))
      || (["empty", "saved"].includes(String(v.status)) && (v.diagnostic !== null || v.slots === null || v.bytes === null
        || Number(v.invalid_records) !== 0 || Number(v.unresolved_writes) !== 0
        || ["active_slots", "unresolved_writes", "invalid_records", "expired_slots"].some((k) => v[k] === null)
        || (v.status === "empty" ? v.slots !== 0 || v.bytes !== 0 : Number(v.slots) === 0)))
      || (!["empty", "saved"].includes(String(v.status)) && v.diagnostic === null)) {
    throw new ContextAssistanceApiError("saved_evidence_payload_invalid", "Guard returned incompatible saved-data status. Refresh or update Guard.");
  }
  return value as SavedEvidence;
}
export function savedEvidenceCopy(value: SavedEvidence): string {
  if (value.status === "empty") return "No saved evidence remains on this machine.";
  if (value.status === "saved") return "Saved evidence remains until its retention period expires or you remove it. Saved data does not restore source or app permissions.";
  if (value.status === "busy") return "Saved storage is in use or cleanup is still running. Refresh after it finishes.";
  if (value.status === "repair_required") return "Saved evidence needs reconciliation or repair. It has been preserved. Remove saved evidence to start again with fresh source grants.";
  if (value.status === "unsupported") return "Private saved storage is unavailable on this platform.";
  return "Saved storage could not be inspected. Refresh its status before trying removal again.";
}
