use super::*;

use serde_json::json;

fn texts(tool_name: Value, tool_input: Value) -> Vec<String> {
    post_tool_command_texts(&tool_name, &tool_input)
}

#[test]
fn the_command_and_every_candidate_list_count_in_payload_order() {
    assert_eq!(
        texts(
            json!("Bash"),
            json!({
                "command": "  ls -l  ",
                "argv": ["git", "status"],
                "commands": ["pwd", " ls -l "],
            }),
        ),
        ["ls -l", "git status", "pwd"]
    );
    // An argv-style list is one command; a `commands` list keeps its items.
    assert_eq!(
        texts(json!("Bash"), json!({"commandArgs": ["echo", "a b"]})),
        ["echo 'a b'"]
    );
}

#[test]
fn a_read_tool_path_stands_in_for_the_file_it_read() {
    assert_eq!(
        texts(
            json!(" Read_File "),
            json!({"file_path": " notes/a b.txt ", "path": "x"}),
        ),
        ["cat -- x", "cat -- 'notes/a b.txt'"]
    );
    // A command the payload names wins over the path it read.
    assert_eq!(
        texts(json!("read"), json!({"command": "head x", "path": "x"})),
        ["head x"]
    );
    // Only a read tool turns a path into a command.
    assert!(texts(json!("write"), json!({"path": "x"})).is_empty());
    assert!(texts(json!(7), json!({"path": "x"})).is_empty());
}

#[test]
fn a_tool_without_a_command_list_falls_back_to_its_own_command_text() {
    assert_eq!(
        texts(
            json!("grep"),
            json!({"pattern": "SupplyChainContextRow|context.*agent|context.*row", "path": "context"}),
        ),
        ["grep 'SupplyChainContextRow|context.*agent|context.*row' context"]
    );
    assert_eq!(
        texts(json!("Bash"), json!({"cmd": "make test"})),
        ["make test"]
    );
}

#[test]
fn a_payload_that_names_no_command_yields_none() {
    assert!(texts(json!("Bash"), json!("ls")).is_empty());
    assert!(texts(json!("Bash"), Value::Null).is_empty());
    assert!(texts(json!("Bash"), json!({})).is_empty());
    assert!(texts(json!("Bash"), json!({"command": "   ", "argv": ["", " "]})).is_empty());
}
