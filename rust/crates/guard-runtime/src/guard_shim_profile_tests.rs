use serde_json::{json, Value};

use super::run_command;

fn content(existing: &str, shim_dir: &str, fish: bool) -> String {
    let request = json!({
        "schema": "guard-shim-profile.v1",
        "existing": existing,
        "shim_dir": shim_dir,
        "fish": fish,
    });
    let bytes = run_command(request.to_string().as_bytes()).expect("answer");
    let answer: Value = serde_json::from_slice(&bytes).expect("json answer");
    answer["content"].as_str().expect("content").to_owned()
}

#[test]
fn renders_one_block_and_is_idempotent() {
    let first = content("# user\n", "/Users/me/.hol-guard/bin", false);
    assert_eq!(
        first,
        "# user\n# HOL Guard harness launchers\nexport PATH=/Users/me/.hol-guard/bin:$PATH\n"
    );
    assert_eq!(content(&first, "/Users/me/.hol-guard/bin", false), first);
}

#[test]
fn renders_fish_syntax() {
    assert_eq!(
        content("", "/Users/me/.hol-guard/bin", true),
        "# HOL Guard harness launchers\nfish_add_path --prepend -- /Users/me/.hol-guard/bin\n"
    );
}

#[test]
fn refuses_malformed_requests() {
    for request in [
        "not json".to_owned(),
        json!({"schema": "other", "existing": "", "shim_dir": "/b", "fish": false}).to_string(),
        json!({"schema": "guard-shim-profile.v1", "existing": "", "shim_dir": "", "fish": false})
            .to_string(),
        json!({"schema": "guard-shim-profile.v1", "existing": "", "shim_dir": "/b"}).to_string(),
        json!({"schema": "guard-shim-profile.v1", "existing": "", "shim_dir": "/b", "fish": false, "extra": 1})
            .to_string(),
    ] {
        assert_eq!(
            run_command(request.as_bytes()),
            Err("guard_shim_profile_request_invalid".to_owned())
        );
    }
}
