//! Documented JSONL task/resume adapters. No shell, permission overrides,
//! profile replacement, credential reads, or implicit context grants.
use crate::model::valid_id;
use serde_json::Value;
use std::process::Command;

fn session_id(id: &str) -> bool {
    valid_id(id) && id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
}

pub(crate) fn configure(
    command: &mut Command,
    harness: &str,
    session: Option<&str>,
    model: Option<&str>,
) {
    if harness == "codex" {
        command.arg("exec");
        if let Some(session) = session {
            command.args(["resume", session]);
        }
        command.arg("--json");
        if let Some(model) = model {
            command.args(["--model", model]);
        }
        command.arg("-"); // Prompt travels over stdin, never argv.
    } else {
        command.args(["-p", "--output-format", "stream-json", "--verbose"]);
        if let Some(session) = session {
            command.args(["--resume", session]);
        }
        if let Some(model) = model {
            command.args(["--model", model]);
        }
    }
}

#[derive(Default, Debug)]
pub(crate) struct Update {
    pub session: Option<String>,
    pub events: Vec<(String, String)>,
    pub context_calls: u64,
    pub usage: Option<(u64, u64)>,
    pub completed: bool,
    pub failed: bool,
}

fn event(update: &mut Update, kind: &str, text: &str) {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .take(4096)
        .collect();
    if !clean.is_empty() {
        update.events.push((kind.into(), clean));
    }
}

// Exact known tool names; a mention of CIGAR in arbitrary output is not usage.
fn context_tool(server: &str, tool: &str) -> bool {
    matches!(server, "hol-guard" | "hol_guard" | "cigar" | "hol-context")
        && matches!(
            tool,
            "get_guard_context" | "explain_guard_context" | "explain_guard_action"
        )
}

fn context_result(value: &Value) -> bool {
    if value["isError"] == true || value["is_error"] == true {
        return false;
    }
    if value["ok"] == true && value["data_role"] == true {
        return true;
    }
    if let Some(text) = value.as_str() {
        return serde_json::from_str::<Value>(text)
            .is_ok_and(|v| v["ok"] == true && v["data_role"] == true);
    }
    value
        .as_array()
        .or_else(|| value["content"].as_array())
        .is_some_and(|blocks| {
            blocks
                .iter()
                .take(64)
                .any(|b| b["type"] == "text" && context_result(&b["text"]))
        })
}

#[derive(Default)]
pub(crate) struct Decoder {
    context_pending: std::collections::BTreeSet<String>,
    context_seen: std::collections::BTreeSet<String>,
}

impl Decoder {
    pub fn decode(&mut self, harness: &str, line: &[u8]) -> Option<Update> {
        let mut update = decode(harness, line)?;
        let value: Value = serde_json::from_slice(line).ok()?;
        if harness == "codex" && update.context_calls > 0 {
            let id = value["item"]["id"].as_str()?;
            if self.context_seen.len() >= 4096 || !self.context_seen.insert(id.to_owned()) {
                update.context_calls = 0;
                update.events.retain(|(kind, _)| kind != "context");
            }
        }
        if harness == "claude-code" {
            if let Some(blocks) = value["message"]["content"].as_array() {
                for block in blocks.iter().take(64) {
                    if block["type"] == "tool_use" && self.context_pending.len() < 256 {
                        if let (Some(name), Some(id)) =
                            (block["name"].as_str(), block["id"].as_str())
                        {
                            let parts: Vec<_> = name.split("__").collect();
                            if parts.len() == 3
                                && parts[0] == "mcp"
                                && context_tool(parts[1], parts[2])
                                && valid_id(id)
                            {
                                self.context_pending.insert(id.to_owned());
                            }
                        }
                    } else if block["type"] == "tool_result" {
                        if let Some(id) = block["tool_use_id"].as_str() {
                            if self.context_pending.remove(id)
                                && block["is_error"] != true
                                && context_result(&block["content"])
                                && self.context_seen.len() < 4096
                                && self.context_seen.insert(id.to_owned())
                            {
                                update.context_calls += 1;
                                event(
                                    &mut update,
                                    "context",
                                    "CIGAR returned a successful context response.",
                                );
                            }
                        }
                    }
                }
            }
        }
        Some(update)
    }
}

pub(crate) fn decode(harness: &str, line: &[u8]) -> Option<Update> {
    let value: Value = serde_json::from_slice(line).ok()?;
    let kind = value.get("type")?.as_str()?;
    let mut update = Update::default();
    if harness == "codex" {
        if kind == "thread.started" {
            update.session = value["thread_id"]
                .as_str()
                .filter(|id| session_id(id))
                .map(str::to_owned);
        } else if kind == "turn.completed" {
            update.completed = true;
            update.usage = Some((
                value["usage"]["input_tokens"].as_u64().unwrap_or(0),
                value["usage"]["output_tokens"].as_u64().unwrap_or(0),
            ));
        } else if matches!(kind, "error" | "turn.failed") {
            update.failed = true;
            event(
                &mut update,
                "error",
                value["message"]
                    .as_str()
                    .or(value["error"]["message"].as_str())
                    .unwrap_or("The CLI could not complete this turn."),
            );
        } else if matches!(kind, "item.started" | "item.completed") {
            let item = &value["item"];
            match item["type"].as_str().unwrap_or("") {
                "agent_message" if kind == "item.completed" => {
                    event(&mut update, "message", item["text"].as_str().unwrap_or(""))
                }
                "command_execution" if kind == "item.started" => event(
                    &mut update,
                    "command",
                    item["command"].as_str().unwrap_or("Running a command"),
                ),
                "file_change" if kind == "item.completed" => {
                    event(&mut update, "files", "Updated project files")
                }
                "mcp_tool_call" => {
                    let server = item["server"].as_str().unwrap_or("");
                    let tool = item["tool"].as_str().unwrap_or("tool");
                    if kind == "item.started" {
                        event(&mut update, "tool", &format!("{server} / {tool}"));
                    }
                    if kind == "item.completed"
                        && item["status"] == "completed"
                        && context_tool(server, tool)
                        && context_result(&item["result"])
                    {
                        update.context_calls = 1;
                        event(
                            &mut update,
                            "context",
                            &format!("CIGAR response reported: {tool}"),
                        );
                    }
                }
                _ => {} // Never expose internal reasoning or arbitrary protocol payloads.
            }
        }
    } else {
        if kind == "system" && value["subtype"] == "init" {
            update.session = value["session_id"]
                .as_str()
                .filter(|id| session_id(id))
                .map(str::to_owned);
        }
        if kind == "assistant" {
            if let Some(blocks) = value["message"]["content"].as_array() {
                for block in blocks.iter().take(64) {
                    match block["type"].as_str().unwrap_or("") {
                        "text" => {
                            event(&mut update, "message", block["text"].as_str().unwrap_or(""))
                        }
                        "tool_use" => event(
                            &mut update,
                            "tool",
                            block["name"].as_str().unwrap_or("Using a tool"),
                        ),
                        _ => {}
                    }
                }
            }
        } else if kind == "result" {
            update.session = value["session_id"]
                .as_str()
                .filter(|id| session_id(id))
                .map(str::to_owned);
            update.completed = true;
            update.failed = value["is_error"].as_bool().unwrap_or(false);
            update.usage = Some((
                value["usage"]["input_tokens"].as_u64().unwrap_or(0),
                value["usage"]["output_tokens"].as_u64().unwrap_or(0),
            ));
            if update.failed {
                event(
                    &mut update,
                    "error",
                    value["result"]
                        .as_str()
                        .unwrap_or("The CLI could not complete this turn."),
                );
            }
            if value["permission_denials"]
                .as_array()
                .is_some_and(|d| !d.is_empty())
            {
                event(&mut update, "permission", "The harness denied a tool. Check Guard Inbox and the harness's permission settings before continuing.");
            }
        } else if kind == "system" && value["subtype"] == "permission_denied" {
            event(
                &mut update,
                "permission",
                "A tool needs permission. Check Guard Inbox or continue in the harness.",
            );
        }
    }
    Some(update)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_use_exact_resume_ids_and_never_disable_protection() {
        let mut command = Command::new("codex");
        configure(&mut command, "codex", Some("session-1"), None);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["exec", "resume", "session-1", "--json", "-"]
        );
        let mut command = Command::new("claude");
        configure(&mut command, "claude-code", None, Some("sonnet"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                "-p",
                "--output-format",
                "stream-json",
                "--verbose",
                "--model",
                "sonnet"
            ]
        );
    }
    #[test]
    fn only_completed_context_tools_are_usage_and_thinking_is_private() {
        let started = br#"{"type":"item.started","item":{"type":"mcp_tool_call","server":"hol-guard","tool":"get_guard_context"}}"#;
        assert_eq!(decode("codex", started).unwrap().context_calls, 0);
        let done = br#"{"type":"item.completed","item":{"type":"mcp_tool_call","server":"hol-guard","tool":"get_guard_context","status":"completed","result":{"content":[{"type":"text","text":"{\"ok\":true,\"data_role\":true,\"data\":{}}"}]}}}"#;
        assert_eq!(decode("codex", done).unwrap().context_calls, 1);
        let reasoning =
            br#"{"type":"item.completed","item":{"type":"reasoning","text":"private"}}"#;
        assert!(decode("codex", reasoning).unwrap().events.is_empty());
        assert!(decode("codex", b"not json").is_none());
    }

    #[test]
    fn resume_ids_cannot_be_flags() {
        for harness in ["codex", "claude-code"] {
            let line = if harness == "codex" {
                br#"{"type":"thread.started","thread_id":"--dangerously-bypass-approvals-and-sandbox"}"#.as_slice()
            } else {
                br#"{"type":"system","subtype":"init","session_id":"--dangerously-skip-permissions"}"#.as_slice()
            };
            assert!(decode(harness, line).unwrap().session.is_none());
        }
    }

    #[test]
    fn context_counts_successful_correlated_responses_once() {
        let mut decoder = Decoder::default();
        let mut codex = serde_json::json!({"type":"item.completed", "item":{
            "id":"call-1", "type":"mcp_tool_call", "server":"hol-guard", "tool":"get_guard_context",
            "status":"completed", "result":{"ok":false, "data_role":true}}});
        assert_eq!(
            decoder
                .decode("codex", codex.to_string().as_bytes())
                .unwrap()
                .context_calls,
            0
        );
        codex["item"]["result"]["ok"] = true.into();
        assert_eq!(
            decoder
                .decode("codex", codex.to_string().as_bytes())
                .unwrap()
                .context_calls,
            1
        );
        assert_eq!(
            decoder
                .decode("codex", codex.to_string().as_bytes())
                .unwrap()
                .context_calls,
            0
        );

        let mut decoder = Decoder::default();
        let use_tool = br#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"tool-1","name":"mcp__hol-guard__get_guard_context"}]}}"#;
        let result = br#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"tool-1","content":"{\"ok\":true,\"data_role\":true}"}]}}"#;
        assert_eq!(
            decoder.decode("claude-code", result).unwrap().context_calls,
            0
        );
        assert_eq!(
            decoder
                .decode("claude-code", use_tool)
                .unwrap()
                .context_calls,
            0
        );
        assert_eq!(
            decoder.decode("claude-code", result).unwrap().context_calls,
            1
        );
        decoder.decode("claude-code", use_tool).unwrap();
        assert_eq!(
            decoder.decode("claude-code", result).unwrap().context_calls,
            0
        );
    }
}
