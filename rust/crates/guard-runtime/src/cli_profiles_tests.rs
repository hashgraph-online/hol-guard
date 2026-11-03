use serde_json::{json, Value};

use super::dispatch;

fn profiles() -> Vec<Value> {
    let answer = dispatch(&json!({})).expect("profiles");
    answer["profiles"].as_array().expect("profile list").clone()
}

fn lookup(name: &str) -> Value {
    dispatch(&json!({ "executable": name })).expect("lookup")["profile_id"].clone()
}

#[test]
fn every_profile_is_a_valid_command_tree() {
    for profile in profiles() {
        let commands = profile["commands"].as_array().expect("commands");
        let ids: Vec<&str> = commands
            .iter()
            .map(|command| command["command_id"].as_str().expect("command id"))
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
        assert!(!ids.contains(&"root") && !ids.contains(&"other"));
        for command in commands {
            if let Some(parent) = command["parent_id"].as_str() {
                assert!(ids.contains(&parent), "{parent} is listed");
            }
            assert!(matches!(
                command["suggested_state"].as_str(),
                Some("inherit" | "allow")
            ));
        }
    }
}

#[test]
fn wrangler_commands_carry_their_usage_and_parent() {
    let wrangler = profiles()
        .into_iter()
        .find(|profile| profile["profile_id"] == "wrangler")
        .expect("wrangler profile");
    let apply = wrangler["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .find(|command| command["command_id"] == "d1.migrations.apply")
        .expect("d1.migrations.apply")
        .clone();
    assert_eq!(
        apply,
        json!({"command_id": "d1.migrations.apply", "name": "apply",
               "usage": "wrangler d1 migrations apply",
               "description": "Apply pending D1 migrations.",
               "parent_id": "d1.migrations", "suggested_state": "inherit"})
    );
    assert_eq!(wrangler["executables"], json!(["wrangler"]));
}

#[test]
fn lookup_ignores_case_whitespace_and_windows_shims() {
    assert_eq!(lookup("wrangler"), json!("wrangler"));
    assert_eq!(lookup(" Wrangler.CMD "), json!("wrangler"));
    assert_eq!(lookup("wrangler.exe"), json!("wrangler"));
    assert_eq!(lookup("wrangle"), Value::Null);
    assert_eq!(lookup("npx"), Value::Null);
}

#[test]
fn an_unknown_shape_is_refused() {
    assert!(dispatch(&json!({"executable": 1})).is_err());
    assert!(dispatch(&json!({"executable": "wrangler", "x": 1})).is_err());
    assert!(dispatch(&json!({"x": 1})).is_err());
}
