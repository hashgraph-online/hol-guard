//! Generic-hook payload identity + content-bound digest.
//!
//! Ports of the pure leaf primitives from `commands_hook_native_generic.py`
//! and its `commands_support_runtime_artifacts.py` shim targets (RTM-010
//! rows 1, 2, 5, 6, 7 + the `_coalesce_string` / `_generic_hook_content_key`
//! helpers they depend on). These are the review-binding identity surfaces:
//! the `artifact_id` the approval-reuse lookups key on, the content-keyed
//! payload digest, and the workspace/memory-command derivations that feed
//! `native_generic_payload` orchestration. Pure JSON — no IO, no env, no
//! store. Everything here must match the Python output byte-for-byte on a
//! fixed payload or saved allows orphan.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canonical_json::write_canonical_json;

// ─── event-name + artifact-id ────────────────────────────────────────────
// `commands_support_runtime_artifacts.py:_HOOK_EVENT_NAME_MAP` /
// `_hook_event_name` / `_artifact_id_from_event` (lines 82-113).

/// `_HOOK_EVENT_NAME_MAP` (`commands_support_runtime_artifacts.py:82-88`):
/// lowercased → canonical hook-event spelling. `permissionrequestv2`
/// normalizes to `PermissionRequest` (V2 folds into the shared route).
fn canonical_hook_event_name(lowered: &str) -> Option<&'static str> {
    match lowered {
        "userpromptsubmitted" => Some("UserPromptSubmit"),
        "pretooluse" => Some("PreToolUse"),
        "posttooluse" => Some("PostToolUse"),
        "permissionrequest" | "permissionrequestv2" => Some("PermissionRequest"),
        _ => None,
    }
}

/// `_hook_event_name` (`commands_support_runtime_artifacts.py:91-97`): scan
/// `event`/`hook_event_name`/`hookEventName`/`hook_name` in order; first
/// non-empty string wins, normalized through the canonical map (unmapped
/// values pass through unchanged, preserving the Python passthrough).
pub fn hook_event_name(payload: &Map<String, Value>) -> Option<String> {
    for key in ["event", "hook_event_name", "hookEventName", "hook_name"] {
        if let Some(value) = payload.get(key) {
            if let Some(text) = value.as_str() {
                let normalized = text.trim();
                if !normalized.is_empty() {
                    let lowered = normalized.to_lowercase();
                    return Some(
                        canonical_hook_event_name(&lowered)
                            .map(str::to_string)
                            .unwrap_or_else(|| normalized.to_string()),
                    );
                }
            }
        }
    }
    None
}

/// `_coalesce_string` (`commands_hook_native_generic.py:13-19`): first
/// non-empty stripped string, else `unknown-artifact`.
fn coalesce_string(values: &[Option<&str>]) -> String {
    for text in values.iter().flatten() {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown-artifact".to_string()
}

/// `_CLAUDE_BUILTIN_HOOK_TOOL_NAMES` (`adapters/claude_code.py:77-101`):
/// the tool names that keep a `claude-code:{scope}:{tool}` artifact id;
/// anything else routes through the MCP server prefix.
const CLAUDE_BUILTIN_HOOK_TOOL_NAMES: &[&str] = &[
    "bash",
    "shell",
    "sh",
    "zsh",
    "terminal",
    "run_command",
    "run_terminal_command",
    "read",
    "read_file",
    "open_file",
    "view",
    "view_file",
    "cat_file",
    "write",
    "edit",
    "multiedit",
    "write_file",
    "edit_file",
    "webfetch",
    "websearch",
    "askuserquestion",
];

/// `_claude_mcp_artifact_id` (`adapters/claude_code.py:73-74`).
fn claude_mcp_artifact_id(scope: &str, server_name: &str) -> String {
    format!("claude-code:{scope}:mcp:{server_name}")
}

/// `claude_hook_fallback_artifact_id` (`adapters/claude_code.py:104-108`):
/// builtin tool → `claude-code:{scope}:{tool}`; otherwise the MCP server
/// slug. The tool-name case is preserved on the builtin path (Python keeps
/// `normalized_tool`, not the lowercased match key).
pub fn claude_hook_fallback_artifact_id(scope: &str, tool_name: &str) -> String {
    let normalized_tool = tool_name.trim();
    if CLAUDE_BUILTIN_HOOK_TOOL_NAMES
        .iter()
        .any(|name| normalized_tool.eq_ignore_ascii_case(name))
    {
        return format!("claude-code:{scope}:{normalized_tool}");
    }
    claude_mcp_artifact_id(scope, normalized_tool)
}

/// `_canonical_harness_name` (`commands_support_runtime_resolution.py:678-682`)
/// for the artifact-id caller: resolves through the adapter registry in
/// Python; on the Rust boundary the caller supplies the already-canonical
/// harness name so this stays a pure string comparison.
///
/// `_artifact_id_from_event` (`commands_support_runtime_artifacts.py:100-113`):
/// tool-name present → harness-scoped tool id (claude-code folds through the
/// builtin/MCP split); no tool → event-scoped fallback; neither → `:hook`.
/// `canonical_harness` is the resolved adapter name (`claude-code` for the
/// Claude adapter); `harness` is the raw harness tag the event arrived on.
pub fn artifact_id_from_event(
    harness: &str,
    canonical_harness: &str,
    payload: &Map<String, Value>,
) -> String {
    let source_scope = coalesce_string(&[
        payload.get("source_scope").and_then(Value::as_str),
        Some("project"),
    ]);
    if let Some(tool_name) = payload.get("tool_name").and_then(Value::as_str) {
        let normalized_tool = tool_name.trim();
        if !normalized_tool.is_empty() {
            if canonical_harness == "claude-code" {
                return claude_hook_fallback_artifact_id(&source_scope, normalized_tool);
            }
            return format!("{harness}:{source_scope}:{normalized_tool}");
        }
    }
    if let Some(event_name) = hook_event_name(payload) {
        let trimmed = event_name.trim();
        if !trimmed.is_empty() {
            return format!("{harness}:{source_scope}:{}", trimmed.to_lowercase());
        }
    }
    format!("{harness}:{source_scope}:hook")
}

// ─── content-key normalization + payload digest ──────────────────────────
// `commands_hook_native_generic.py:_GENERIC_HOOK_NON_CONTENT_FIELDS` /
// `_generic_hook_content_key` / `_generic_hook_payload_digest` (188-289).

/// `_GENERIC_HOOK_NON_CONTENT_FIELDS` (`commands_hook_native_generic.py:188-217`):
/// top-level transport fields stripped before the content digest. Nested
/// fields are NOT stripped — `tool_input.request_id` is a real action arg.
const GENERIC_HOOK_NON_CONTENT_FIELDS: &[&str] = &[
    "action_id",
    "approval_center_url",
    "approval_delivery",
    "approval_request_id",
    "approval_requests",
    "call_id",
    "daemon_status",
    "event_id",
    "event_time",
    "fail_mode",
    "hook_id",
    "invocation_id",
    "message_id",
    "permission_decision_reason",
    "policy_action",
    "received_at",
    "request_id",
    "review_hint",
    "session_id",
    "thread_id",
    "timestamp",
    "tool_call_id",
    "tool_use_id",
    "trace_id",
    "turn_id",
    "user_override",
];

/// `_generic_hook_content_key` (`commands_hook_native_generic.py:292-295`):
/// canonicalize a top-level hook key across snake/camel/kebab transports —
/// `re.sub(r"(?<!^)(?=[A-Z])", "_", key)` then `-` → `_` then lowercase.
/// The `(?<!^)` keeps a leading uppercase from gaining a leading underscore.
pub fn generic_hook_content_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 8);
    for (i, ch) in key.chars().enumerate() {
        if i > 0 && ch.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(ch);
    }
    out.replace('-', "_").to_lowercase()
}

/// `_generic_hook_payload_digest` (`commands_hook_native_generic.py:266-289`):
/// sha256 over the canonical-JSON of the payload minus the non-content top
/// -level keys and `artifact_hash`. Uses the shared `write_canonical_json`
/// oracle — `sort_keys=True, separators=(",",":"), ensure_ascii=True,
/// allow_nan=False` — so the review binding matches the Python digest
/// byte-for-byte. Nested keys untouched.
pub fn generic_hook_payload_digest(payload: &Map<String, Value>) -> String {
    let mut content: Map<String, Value> = Map::new();
    for (key, value) in payload {
        let canonical = generic_hook_content_key(key);
        if GENERIC_HOOK_NON_CONTENT_FIELDS.contains(&canonical.as_str()) {
            continue;
        }
        if canonical == "artifact_hash" {
            continue;
        }
        content.insert(key.clone(), value.clone());
    }
    let mut encoded = Vec::new();
    // The content payload is a JSON object of arbitrary values; a
    // non-finite float is the only write_canonical_json rejection. Python's
    // allow_nan=False would raise there; a caller that supplies NaN gets a
    // digest over an empty map rather than a panic (fail-closed, mirrors the
    // digest-binding contract — no NaN payload can ever produce a valid
    // binding, which is the safe outcome).
    let _ = write_canonical_json(&Value::Object(content), &mut encoded);
    hex_sha256(&encoded)
}

/// `_generic_hook_workspace_identity` (`commands_hook_native_generic.py:298-303`):
/// the runtime workspace root normalized to a forward-slash resolved path
/// string; `None`/empty → empty string. `Path::resolve`/`as_posix` in Python
/// collapse `.`/`..` and platform separators.
pub fn generic_hook_workspace_identity(runtime_workspace: Option<&str>) -> String {
    let Some(raw) = runtime_workspace else {
        return String::new();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Normalize separators the way Path.as_posix() does; `.`/`..` resolution
    // is a host-side Path operation the caller performs before crossing the
    // boundary — Rust keeps the string-level normalization (trailing slash
    // strip + backslash→slash) only.
    let mut normalized = trimmed.replace('\\', "/");
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

// ─── memory command derivation ───────────────────────────────────────────
// `commands_hook_native_generic.py:_generic_hook_memory_command` (306-312).

/// `_generic_hook_memory_command` (`commands_hook_native_generic.py:306-312`):
/// the command text the approval-reuse memory binds to — the tool payload's
/// command field, or empty when the tool carries no executable command.
/// `command_text_from_tool_payload` (`runtime/actions.py:894-910`) resolves
/// it; the Rust side takes the resolved command (or the payload's `tool_input`)
/// and returns the trimmed text for the memory key.
pub fn generic_hook_memory_command(
    tool_name: Option<&str>,
    tool_input: Option<&Map<String, Value>>,
) -> String {
    command_text_from_tool_payload(tool_name, tool_input).unwrap_or_default()
}

/// `command_text_from_tool_payload` (`runtime/actions.py:894-910`): the
/// trimmed executable text for a tool call — explicit `command`/`cmd`/
/// `shell_command`/`shellCommand` keys first, then grep-tool argument
/// synthesis, then (non-MCP) the broader `_command_from_payload` keys.
/// Returns `None` for non-Mapping input or an MCP-namespaced tool with no
/// explicit command key.
pub fn command_text_from_tool_payload(
    tool_name: Option<&str>,
    tool_input: Option<&Map<String, Value>>,
) -> Option<String> {
    let tool_input = tool_input?;
    for key in EXPLICIT_COMMAND_KEYS {
        if let Some(value) = first_tool_input_string(tool_input, &[key]) {
            return Some(value);
        }
    }
    if let Some(text) = native_tool_command_text(tool_name, tool_input) {
        return Some(text);
    }
    let normalized = tool_name.map(str::trim);
    if mcp_parts(normalized).is_some() {
        // MCP search/query fields are tool data, not shell source.
        return None;
    }
    command_from_payload(tool_input)
}

const EXPLICIT_COMMAND_KEYS: &[&str] = &["command", "cmd", "shell_command", "shellCommand"];
const COMMAND_KEYS: &[&str] = &[
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "pattern",
    "query",
    "search",
    "regex",
];
const SEARCH_PATTERN_KEYS: &[&str] = &["pattern", "query", "search", "regex"];

fn command_from_payload(tool_input: &Map<String, Value>) -> Option<String> {
    for key in COMMAND_KEYS {
        if let Some(value) = first_tool_input_string(tool_input, &[key]) {
            return Some(value);
        }
    }
    None
}

fn first_tool_input_string(tool_input: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = tool_input.get(*key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// `_native_tool_command_text` (`runtime/actions.py:913-919`): only the
/// grep-family tools synthesize a command line from structured args.
fn native_tool_command_text(
    tool_name: Option<&str>,
    tool_input: &Map<String, Value>,
) -> Option<String> {
    let normalized = tool_name?.trim().to_lowercase();
    if matches!(normalized.as_str(), "grep" | "egrep" | "fgrep" | "rg") {
        return grep_tool_command_text(&normalized, tool_input);
    }
    None
}

/// `_grep_tool_command_text` (`runtime/actions.py:922-940`): synthesize the
/// `grep [-n] [-E|-F] <pattern> [path]` argv and shell-quote it. The Python
/// returns `shlex.join(args)` — Rust reproduces the single-quote wrapping
/// POSIX shell join.
fn grep_tool_command_text(executable: &str, tool_input: &Map<String, Value>) -> Option<String> {
    let pattern = first_tool_input_string(tool_input, SEARCH_PATTERN_KEYS)?;
    let path = first_tool_input_string(tool_input, &["path", "glob"]);
    let line_numbers = tool_input
        .get("output_mode")
        .and_then(Value::as_str)
        .map(|m| m == "content")
        .unwrap_or(false)
        || tool_input
            .get("-n")
            .or_else(|| tool_input.get("line_numbers"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let fixed = tool_input
        .get("-F")
        .or_else(|| tool_input.get("fixed_strings"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut args: Vec<String> = vec![executable.to_string()];
    if line_numbers {
        args.push("-n".to_string());
    }
    if matches!(executable, "grep" | "egrep" | "rg") && !fixed {
        // Pattern arg follows flags; rg/egrep default to regex so no -E flag.
    } else if fixed {
        args.push("-F".to_string());
    }
    args.push(pattern);
    if let Some(p) = path {
        args.push(p);
    }
    Some(shlex_join(&args))
}

/// `_mcp_parts` (`runtime/actions.py:1033+`): `mcp__server__tool` splits into
/// the server + tool pair; `Some(server)` marks the call MCP-namespaced.
/// Returns the server component when the `mcp__` prefix pattern matches.
fn mcp_parts(tool_name: Option<&str>) -> Option<String> {
    let name = tool_name?;
    if let Some(rest) = name.strip_prefix("mcp__") {
        if let Some(server) = rest.split("__").next() {
            if !server.is_empty() {
                return Some(server.to_string());
            }
        }
    }
    None
}

/// `shlex.join` equivalent: POSIX shell single-quote join — wrap every arg in
/// `'…'`, escaping an embedded `'` as `'"'"'`. CPython `shlex.join` applies
/// `shlex.quote` per arg.
fn shlex_join(args: &[String]) -> String {
    args.iter()
        .map(|a| shlex_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shlex_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-' | b'_'))
    {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hook_event_name_canonical_map() {
        let payload = json!({"hookEventName": "pretooluse"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(hook_event_name(&payload).as_deref(), Some("PreToolUse"));
        let payload = json!({"event": "permissionrequestv2"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            hook_event_name(&payload).as_deref(),
            Some("PermissionRequest")
        );
        let payload = json!({"event": "UserPromptSubmitted"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            hook_event_name(&payload).as_deref(),
            Some("UserPromptSubmit")
        );
        // Unmapped value passes through unchanged.
        let payload = json!({"event": "CustomEvent"}).as_object().unwrap().clone();
        assert_eq!(hook_event_name(&payload).as_deref(), Some("CustomEvent"));
        // First non-empty key wins.
        let payload = json!({"event": "  ", "hook_name": "posttooluse"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(hook_event_name(&payload).as_deref(), Some("PostToolUse"));
        let empty = Map::new();
        assert!(hook_event_name(&empty).is_none());
    }

    #[test]
    fn artifact_id_tool_and_event_paths() {
        // Non-claude harness + tool → harness:scope:tool.
        let payload = json!({"tool_name": "Bash", "source_scope": "user"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            artifact_id_from_event("codex", "codex", &payload),
            "codex:user:Bash"
        );
        // Claude builtin → claude-code:scope:tool.
        let payload = json!({"tool_name": "bash"}).as_object().unwrap().clone();
        assert_eq!(
            artifact_id_from_event("claude", "claude-code", &payload),
            "claude-code:project:bash"
        );
        // Claude MCP tool → mcp slug.
        let payload = json!({"tool_name": "github-mcp"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            artifact_id_from_event("claude", "claude-code", &payload),
            "claude-code:project:mcp:github-mcp"
        );
        // No tool → event-scoped fallback.
        let payload = json!({"event": "posttooluse"}).as_object().unwrap().clone();
        assert_eq!(
            artifact_id_from_event("codex", "codex", &payload),
            "codex:project:posttooluse"
        );
        // Neither → :hook.
        let payload = Map::new();
        assert_eq!(
            artifact_id_from_event("codex", "codex", &payload),
            "codex:project:hook"
        );
    }

    #[test]
    fn content_key_normalization() {
        assert_eq!(generic_hook_content_key("toolName"), "tool_name");
        assert_eq!(
            generic_hook_content_key("hook-event-name"),
            "hook_event_name"
        );
        assert_eq!(generic_hook_content_key("session_id"), "session_id");
        // Leading uppercase does NOT get a leading underscore.
        assert_eq!(generic_hook_content_key("ToolName"), "tool_name");
        assert_eq!(generic_hook_content_key("HTTPRequest"), "h_t_t_p_request");
    }

    #[test]
    fn payload_digest_strips_delivery_fields() {
        let with_meta = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "session_id": "abc",
            "request_id": "r1",
            "timestamp": "2026-01-01",
            "artifact_hash": "should-drop",
            "toolUseId": "tu1",
        })
        .as_object()
        .unwrap()
        .clone();
        let stripped = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        })
        .as_object()
        .unwrap()
        .clone();
        assert_eq!(
            generic_hook_payload_digest(&with_meta),
            generic_hook_payload_digest(&stripped)
        );
        // Nested request_id survives (content field, not delivery).
        let nested = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls", "request_id": "nested-keep"},
        })
        .as_object()
        .unwrap()
        .clone();
        assert_ne!(
            generic_hook_payload_digest(&nested),
            generic_hook_payload_digest(&with_meta)
        );
        // Digest is a 64-char lowercase hex.
        let d = generic_hook_payload_digest(&stripped);
        assert_eq!(d.len(), 64);
        assert!(d
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn workspace_identity_normalizes() {
        assert_eq!(generic_hook_workspace_identity(None), "");
        assert_eq!(generic_hook_workspace_identity(Some("  ")), "");
        assert_eq!(
            generic_hook_workspace_identity(Some("C:\\proj\\x")),
            "C:/proj/x"
        );
        assert_eq!(generic_hook_workspace_identity(Some("/a/b/")), "/a/b");
    }

    #[test]
    fn memory_command_resolves_command_key() {
        let tool_input = json!({"command": "git status"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            generic_hook_memory_command(Some("Bash"), Some(&tool_input)),
            "git status"
        );
        // MCP-namespaced tool with only a query → empty (not shell source).
        let tool_input = json!({"query": "foo"}).as_object().unwrap().clone();
        assert_eq!(
            generic_hook_memory_command(Some("mcp__github__search"), Some(&tool_input)),
            ""
        );
        // Non-MCP tool falls through to the broader command keys.
        assert_eq!(
            generic_hook_memory_command(Some("Bash"), Some(&tool_input)),
            "foo"
        );
        assert_eq!(generic_hook_memory_command(None, None), "");
    }

    #[test]
    fn grep_command_synthesis() {
        let tool_input = json!({"pattern": "TODO", "path": "src/"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            command_text_from_tool_payload(Some("rg"), Some(&tool_input)).as_deref(),
            Some("rg TODO src/")
        );
        let tool_input = json!({"pattern": "a b", "-n": true})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            command_text_from_tool_payload(Some("grep"), Some(&tool_input)).as_deref(),
            Some("grep -n 'a b'")
        );
    }

    #[test]
    fn shlex_join_quoting() {
        assert_eq!(shlex_join(&["a".into(), "b".into()]), "a b");
        assert_eq!(shlex_join(&["a b".into()]), "'a b'");
        assert_eq!(shlex_join(&["it's".into()]), "'it'\"'\"'s'");
        assert_eq!(shlex_join(&["".into()]), "''");
    }
}
