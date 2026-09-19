//! Exact command bytes are a separate selector from normalized command models.
//!
//! Only explicit, unambiguous shell input is eligible. Neither a display label,
//! a supplied digest nor a recursively discovered command creates this identity.

use serde_json::Value;
use sha2::{Digest, Sha256};

pub const EXACT_COMMAND_CONTRACT: &str = "guard.exact-command.v1";
pub const EXACT_COMMAND_MAX_BYTES: usize = 32_768;
const COMMAND_KEYS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];
const SHELL_TOOLS: [&str; 4] = ["bash", "shell", "terminal", "exec_command"];

fn is_blank(character: char) -> bool {
    matches!(character as u32,
        0x09..=0x0d | 0x1c..=0x20 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a
        | 0x2028..=0x2029 | 0x202f | 0x205f | 0x3000)
}

/// Validate complete UTF-8 without changing any accepted byte.
pub fn valid_exact_command_text(value: &str) -> bool {
    value.len() <= EXACT_COMMAND_MAX_BYTES
        && !value.contains('\0')
        && value.chars().any(|character| !is_blank(character))
}

/// Read one explicit argument from a recognized shell tool, before normalization.
pub fn exact_shell_command_text<'a>(tool_name: &Value, arguments: &'a Value) -> Option<&'a str> {
    let tool = tool_name.as_str()?;
    if !tool.is_ascii()
        || !SHELL_TOOLS
            .iter()
            .any(|known| tool.eq_ignore_ascii_case(known))
    {
        return None;
    }
    let arguments = arguments.as_object()?;
    let mut values = COMMAND_KEYS.iter().filter_map(|key| arguments.get(*key));
    let command = values.next()?.as_str()?;
    if values.next().is_some() || !valid_exact_command_text(command) {
        return None;
    }
    Some(command)
}

/// Select actual hook arguments only when tool and container aliases are unique.
pub fn exact_shell_command_from_hook(payload: &Value) -> Option<&str> {
    let object = payload.as_object()?;
    let mut tools = ["tool_name", "toolName"]
        .iter()
        .filter_map(|key| object.get(*key));
    let tool = tools.next()?;
    if tools.next().is_some() {
        return None;
    }
    let mut containers = ["tool_input", "arguments", "tool_args", "toolArgs"]
        .iter()
        .filter_map(|key| object.get(*key));
    let arguments = containers.next()?;
    if containers.next().is_some() {
        return None;
    }
    exact_shell_command_text(tool, arguments)
}

/// Hash an already selected complete command, never a normalized model or label.
pub fn exact_command_sha256(command: &str) -> Option<String> {
    valid_exact_command_text(command).then(|| hex::encode(Sha256::digest(command.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_shared_python_contract_without_changing_accepted_bytes() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/exact-command-contract-v1.json"
        ))
        .unwrap();
        assert_eq!(fixture["contractVersion"], EXACT_COMMAND_CONTRACT);
        assert_eq!(fixture["maxBytes"], EXACT_COMMAND_MAX_BYTES);
        for value in fixture["blankCodepoints"].as_array().unwrap() {
            let character = char::from_u32(value.as_u64().unwrap() as u32).unwrap();
            assert!(is_blank(character));
            assert!(!valid_exact_command_text(&character.to_string()));
        }
        for case in fixture["cases"].as_array().unwrap() {
            let actual = exact_shell_command_text(&case["toolName"], &case["arguments"])
                .and_then(exact_command_sha256);
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                case["expectedSha256"],
                "case {}",
                case["id"]
            );
        }
    }

    #[test]
    fn hook_selection_rejects_competing_tool_and_argument_containers() {
        let source = "  printf 'a  b'\n";
        let original = json!({"tool_name":"Bash", "tool_input":{"command":source}});
        assert_eq!(exact_shell_command_from_hook(&original), Some(source));
        for alias in ["arguments", "tool_args", "toolArgs"] {
            let mut competing = original.clone();
            competing[alias] = json!({"command":source});
            assert!(exact_shell_command_from_hook(&competing).is_none());
        }
        let mut competing = original;
        competing["toolName"] = json!("Bash");
        assert!(exact_shell_command_from_hook(&competing).is_none());
        for payload in [
            json!({"tool_name":"Bash", "tool_input":"{\"command\":\"printf synthetic\"}"}),
            json!({"tool_name":"Bash", "tool_input":{"nested":{"command":source}}}),
            json!({"tool_name":"Read", "tool_input":{"command":source}}),
            json!({"tool_name":"Bash", "tool_input":{"command":source,"cmd":null}}),
        ] {
            assert!(exact_shell_command_from_hook(&payload).is_none());
        }
    }

    #[test]
    fn whitespace_case_wrappers_and_unicode_remain_distinct_identities() {
        let commands = [
            "printf 'a b'",
            "printf 'a  b'",
            " printf 'a b'",
            "printf 'a b'\n",
            "printf\t'a b'",
            "PRINTF 'a b'",
            "sh -c \"printf 'a b'\"",
            "printf 'a\u{a0}b'",
        ];
        let hashes: std::collections::BTreeSet<_> = commands
            .into_iter()
            .map(|command| exact_command_sha256(command).unwrap())
            .collect();
        assert_eq!(hashes.len(), commands.len());
    }

    #[test]
    fn command_bounds_count_utf8_bytes_and_json_rejects_unpaired_surrogates() {
        assert!(exact_command_sha256(&"α".repeat(EXACT_COMMAND_MAX_BYTES / 2)).is_some());
        assert!(exact_command_sha256(&"α".repeat(EXACT_COMMAND_MAX_BYTES / 2 + 1)).is_none());
        assert!(serde_json::from_str::<Value>(r#"{"command":"\ud800"}"#).is_err());
        assert!(!valid_exact_command_text("\u{1c}\u{1f}"));
    }
}
