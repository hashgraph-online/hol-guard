export type BusinessReviewSummary = {
  schema: "guard-native-local-business-review-summary.v1";
  version: 1;
  request_id: string;
  request_snapshot_digest: string;
  prepared_input_binding: string;
  service: "google_gmail" | "google_drive" | "google_calendar";
  operation: keyof typeof businessOperationLabels;
  audience_kind: "private" | "named" | "public" | "unknown";
  audience_expansion_state: "known" | "unknown" | "unsupported";
  recipient_count: number;
  record_count: number;
  byte_count: number;
  attachment_count: number;
  inspection_state: "known" | "unknown" | "unsupported";
  sensitivity_labels: ("public" | "personal" | "confidential" | "secret" | "unknown")[];
  snapshot_fact_completeness: "known" | "unknown" | "unsupported";
  account_currentness: "not_asserted";
  execution_state: "not_checked";
};

export const businessOperationLabels = {
  mail_read: "Read email", mail_draft: "Prepare an email draft", mail_send: "Send email",
  mail_label: "Change email labels", mail_permanent_delete: "Permanently delete email",
  mail_settings: "Change email settings", drive_read: "Read Drive files", drive_edit: "Edit Drive files",
  drive_share: "Share Drive files", calendar_read: "Read calendar events", calendar_invite: "Invite calendar attendees",
} as const;

export const businessServiceLabels = {
  google_gmail: "Gmail", google_drive: "Google Drive", google_calendar: "Google Calendar",
} as const;

const fields = ["schema", "version", "request_id", "request_snapshot_digest", "prepared_input_binding", "service", "operation", "audience_kind", "audience_expansion_state", "recipient_count", "record_count", "byte_count", "attachment_count", "inspection_state", "sensitivity_labels", "snapshot_fact_completeness", "account_currentness", "execution_state"];
export function parseBusinessReviewSummary(value: unknown, requestId: string): BusinessReviewSummary | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  if (Object.keys(item).length !== fields.length || !fields.every(field => Object.hasOwn(item, field))) return null;
  if (item.schema !== "guard-native-local-business-review-summary.v1" || item.version !== 1 || item.request_id !== requestId || item.account_currentness !== "not_asserted" || item.execution_state !== "not_checked") return null;
  if (![item.request_snapshot_digest, item.prepared_input_binding].every(digest => typeof digest === "string" && /^[0-9a-f]{64}$/.test(digest))) return null;
  if (typeof item.service !== "string" || !Object.hasOwn(businessServiceLabels, item.service) || typeof item.operation !== "string" || !Object.hasOwn(businessOperationLabels, item.operation)) return null;
  const servicePrefix = { google_gmail: "mail_", google_drive: "drive_", google_calendar: "calendar_" }[item.service as BusinessReviewSummary["service"]];
  if (!item.operation.startsWith(servicePrefix)) return null;
  if (typeof item.audience_kind !== "string" || !["private", "named", "public", "unknown"].includes(item.audience_kind)) return null;
  if (![item.audience_expansion_state, item.inspection_state, item.snapshot_fact_completeness].every(state => typeof state === "string" && ["known", "unknown", "unsupported"].includes(state))) return null;
  if (![item.recipient_count, item.record_count, item.byte_count, item.attachment_count].every(count => typeof count === "number" && Number.isSafeInteger(count) && count >= 0)) return null;
  const labels = item.sensitivity_labels;
  if (!Array.isArray(labels) || labels.length > 5 || !labels.every(label => typeof label === "string" && ["public", "personal", "confidential", "secret", "unknown"].includes(label)) || new Set(labels).size !== labels.length) return null;
  return item as BusinessReviewSummary;
}
