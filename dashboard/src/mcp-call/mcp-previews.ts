import type { McpValueKind } from "./mcp-call-types";
import { nameWords } from "./mcp-effects";

/** One line of a tool's preview: the label to show and the input keys it may arrive under. */
export type McpPreviewField = { label: string; keys: string[]; kind?: McpValueKind };

const MESSAGE_BODY = ["body", "message", "text", "content", "message_body", "markdown_text"];
const EMAIL_FIELDS: McpPreviewField[] = [
  { label: "To", keys: ["to", "recipient", "recipients", "recipient_email", "to_email", "email"] },
  { label: "Cc", keys: ["cc"] },
  { label: "Bcc", keys: ["bcc"] },
  { label: "Subject", keys: ["subject", "title"] },
  { label: "Message", keys: MESSAGE_BODY, kind: "long" },
];
const CHAT_FIELDS: McpPreviewField[] = [
  { label: "Where", keys: ["channel", "channel_id", "channel_name", "conversation", "thread"] },
  { label: "To", keys: ["user", "user_id", "recipient", "to"] },
  { label: "Message", keys: MESSAGE_BODY, kind: "long" },
];
const ISSUE_FIELDS: McpPreviewField[] = [
  { label: "Repository", keys: ["repo", "repository", "project", "team"] },
  { label: "Title", keys: ["title", "summary", "name"] },
  { label: "Details", keys: ["body", "description", "details"], kind: "long" },
  { label: "Assigned to", keys: ["assignees", "assignee"] },
  { label: "Labels", keys: ["labels", "label"] },
];
const EVENT_FIELDS: McpPreviewField[] = [
  { label: "Title", keys: ["summary", "title", "name"] },
  { label: "Starts", keys: ["start", "start_time", "start_datetime", "starts_at"] },
  { label: "Ends", keys: ["end", "end_time", "end_datetime", "ends_at"] },
  { label: "Guests", keys: ["attendees", "guests", "invitees"] },
  { label: "Where", keys: ["location"] },
  { label: "Details", keys: ["description", "details"], kind: "long" },
];
const QUERY_FIELDS: McpPreviewField[] = [
  { label: "Query", keys: ["query", "sql", "statement"], kind: "code" },
  { label: "Database", keys: ["database", "db", "dataset"] },
];
const PAGE_FIELDS: McpPreviewField[] = [
  { label: "Title", keys: ["title", "name"] },
  { label: "Where", keys: ["parent", "parent_id", "database_id", "folder", "folder_id"] },
  { label: "Content", keys: ["content", "body", "text", "markdown"], kind: "long" },
];

// Keyed by the action part of a tool's name, so `send_email` also covers `GMAIL_SEND_EMAIL`.
const PREVIEWS = new Map<string, McpPreviewField[]>([
  ["send_email", EMAIL_FIELDS],
  ["create_email_draft", EMAIL_FIELDS],
  ["create_draft", EMAIL_FIELDS],
  ["reply_to_thread", EMAIL_FIELDS],
  ["forward_email", EMAIL_FIELDS],
  ["send_message", CHAT_FIELDS],
  ["post_message", CHAT_FIELDS],
  ["chat_post_message", CHAT_FIELDS],
  ["send_direct_message", CHAT_FIELDS],
  ["create_issue", ISSUE_FIELDS],
  ["update_issue", ISSUE_FIELDS],
  ["create_pull_request", [{ label: "From", keys: ["head", "branch"] }, { label: "Into", keys: ["base"] }, ...ISSUE_FIELDS]],
  ["create_event", EVENT_FIELDS],
  ["create_calendar_event", EVENT_FIELDS],
  ["update_event", EVENT_FIELDS],
  ["run_query", QUERY_FIELDS],
  ["execute_sql", QUERY_FIELDS],
  ["query", QUERY_FIELDS],
  ["create_page", PAGE_FIELDS],
  ["append_block_children", PAGE_FIELDS],
]);

/**
 * The preview fields for a tool, if Guard knows its shape. A service prefix is
 * dropped one word at a time, so `GMAIL_SEND_EMAIL` and `send_email` both match.
 */
export function previewFieldsFor(toolName: string): McpPreviewField[] | null {
  const words = nameWords(toolName);
  for (let start = 0; start < words.length; start += 1) {
    const fields = PREVIEWS.get(words.slice(start).join("_"));
    if (fields !== undefined) return fields;
  }
  return null;
}
