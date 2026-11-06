//! Plain readers over a shell glob in a sibling repository. The pattern is
//! expanded before the reader runs, so every name it can produce must clear
//! the same proof a literal operand would.
#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::PathBuf;

/// Keep the fixture outside $TMPDIR: on macOS it canonicalizes under
/// /private/var, which the sensitive-root check rejects.
fn org_home() -> PathBuf {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-sibling-globs")
        .join(format!("home-{}", std::process::id()));
    for file in [
        "org/app-portal/README.md",
        "org/service-api/contracts/commands.json",
        "org/service-api/contracts/schema.json",
        "org/service-api/contracts/notes.md",
        "org/service-api/validation/schema.json",
        "org/service-api/mixed/config.json",
        "org/service-api/mixed/.env",
        "org/service-api/creds/config.json",
        "org/service-api/creds/credentials.json",
        "org/service-api/keys/notes.json",
        "org/service-api/keys/server.pem",
        "org/service-api/nested/top.json",
        "org/service-api/nested/inner.json/data.txt",
        ".ssh/id_rsa",
    ] {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "fixture\n").unwrap();
    }
    std::fs::canonicalize(&root).unwrap()
}

#[test]
fn sibling_glob_reads_prove_every_expanded_file() {
    let home = org_home();
    let app = home.join("org/app-portal");
    let sibling = home.join("org/service-api");
    let sibling = sibling.to_str().unwrap();
    let decide = |harness: &str, command: &str| {
        let tool = if harness == "codex" { "Bash" } else { "bash" };
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": tool, "tool_input": {"command": command}}),
            None,
            None,
            home.to_str(),
            app.to_str(),
        )
        .minimum_action
    };
    let allowed = [
        format!("wc -l {sibling}/contracts/*.json"),
        format!("wc -l {sibling}/contracts/*.json {sibling}/validation/*.json"),
        format!("cat {sibling}/contracts/*.json"),
        format!("head -n 20 {sibling}/contracts/*"),
        format!("base64 {sibling}/contracts/schema.js?n"),
        "wc -l ~/org/service-api/contracts/*.json".to_owned(),
        "cat ../service-api/contracts/*.md".to_owned(),
        "wc -l ../app-portal/*.md".to_owned(),
    ];
    for harness in ["codex", "zcode"] {
        for command in &allowed {
            assert_eq!(decide(harness, command), "allow", "{harness}: {command}");
        }
    }
    let reviewed = [
        // A hidden or credential-named match keeps the whole glob reviewed.
        format!("cat {sibling}/mixed/*"),
        format!("cat {sibling}/mixed/*.json {sibling}/mixed/.e*"),
        format!("cat {sibling}/creds/*.json"),
        format!("base64 {sibling}/keys/*"),
        // A directory match, no match, or an unmodelled pattern.
        format!("wc -l {sibling}/nested/*.json"),
        format!("cat {sibling}/contracts/*.yaml"),
        format!("cat {sibling}/contracts/[cs]*.json"),
        format!("cat {sibling}/*/*.json"),
        format!("cat {sibling}/**/*.json"),
        format!("cat {sibling}/contracts/*.json; rm -rf {sibling}"),
        "cat ~/.ssh/*".to_owned(),
        "cat ~/.ssh/id_*".to_owned(),
        "cat /etc/*.conf".to_owned(),
    ];
    for harness in ["codex", "zcode"] {
        for command in &reviewed {
            assert_ne!(decide(harness, command), "allow", "{harness}: {command}");
        }
    }
}
