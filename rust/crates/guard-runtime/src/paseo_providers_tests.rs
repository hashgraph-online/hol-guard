use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::*;

fn ask(config: &Path, home: &Path, environ: Value) -> Value {
    dispatch(&json!({
        "config_path": config.to_str().unwrap(),
        "xdg_default": home.join(".config").to_str().unwrap(),
        "environ": environ,
    }))
    .unwrap()
}

fn write(config: &Path, text: &str) {
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(config, text).unwrap();
}

fn by_id(answer: &Value, id: &str) -> Value {
    answer["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["provider"] == id)
        .cloned()
        .unwrap()
}

fn reason(answer: &Value, id: &str) -> Value {
    by_id(answer, id)["unsupported_reason"].clone()
}

#[test]
fn a_missing_configuration_lists_the_native_defaults() {
    let home = tempfile::tempdir().unwrap();
    let answer = ask(
        &home.path().join(".paseo/config.json"),
        home.path(),
        json!({}),
    );
    let ids: Vec<&str> = answer["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["provider"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["claude", "codex", "copilot", "omp", "opencode", "pi"]);
    assert_eq!(by_id(&answer, "omp")["enabled"], false);
    assert_eq!(by_id(&answer, "claude")["native_harness"], "claude-code");
    assert_eq!(by_id(&answer, "pi")["enabled"], true);
    assert_eq!(by_id(&answer, "pi")["unsupported_reason"], Value::Null);
}

#[test]
fn profiles_inherit_their_base_and_acp_profiles_are_uncovered() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join(".paseo/config.json");
    write(
        &config,
        r#"{"agents":{"providers":{
            "my-omp":{"extends":"omp","label":"My OMP"},
            "other":{"extends":"acp"},
            "pi":{"env":{"PI_PROFILE":"work"}},
            "work-pi":{"extends":"pi"},
            "nested":{"extends":"work-pi"},
            "deep":{"extends":"codex"},
            "codex":{"extends":"codex","command":["codex"]}
        }}}"#,
    );
    let answer = ask(&config, home.path(), json!({}));
    assert_eq!(by_id(&answer, "my-omp")["enabled"], true);
    assert_eq!(by_id(&answer, "my-omp")["native_harness"], "omp");
    assert_eq!(by_id(&answer, "other")["native_harness"], Value::Null);
    assert_eq!(reason(&answer, "other"), ACP_REASON);
    assert_eq!(reason(&answer, "nested"), ACP_REASON);
    assert_eq!(reason(&answer, "work-pi"), PROVIDER_ENV_REASON);
    assert_eq!(reason(&answer, "deep"), NESTED_REASON);
    assert_eq!(reason(&answer, "codex"), COMMAND_REASON);
}

#[test]
fn execution_overrides_are_explicitly_uncovered() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join(".paseo/config.json");
    for (env, expected) in [
        (
            json!({"PI_CODING_AGENT_DIR": "/another-home"}),
            PROVIDER_ENV_REASON,
        ),
        (json!({"path": "/custom-bin"}), PROVIDER_ENV_REASON),
        (json!({"HOL_GUARD_DISABLED": "1"}), PROVIDER_ENV_REASON),
        (json!({"guard_x": "1"}), PROVIDER_ENV_REASON),
        (json!({"LD_PRELOAD": "/untrusted.so"}), PROVIDER_ENV_REASON),
        (json!({"API_KEY": "sk-secret"}), ""),
    ] {
        let text = json!({"agents": {"providers": {"pi": {"env": env}}}}).to_string();
        write(&config, &text);
        let answer = ask(&config, home.path(), json!({}));
        let expected = if expected.is_empty() {
            Value::Null
        } else {
            json!(expected)
        };
        assert_eq!(reason(&answer, "pi"), expected, "{text}");
        assert!(!answer.to_string().contains("sk-secret"));
    }
}

#[cfg(unix)]
#[test]
fn only_the_default_xdg_directory_is_not_a_redirect() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join(".paseo/config.json");
    let default = home.path().join(".config");
    let default = default.to_str().unwrap();
    let cases = [
        (String::new(), Value::Null),
        (default.to_owned(), Value::Null),
        (format!("{default}/"), Value::Null),
        (format!("{default}/../.config/."), Value::Null),
        (format!("//{default}"), Value::Null),
        (format!("/{default}"), json!(PROVIDER_ENV_REASON)),
        ("/elsewhere".to_owned(), json!(PROVIDER_ENV_REASON)),
        (".config".to_owned(), json!(PROVIDER_ENV_REASON)),
    ];
    for (value, expected) in cases {
        let text =
            json!({"agents": {"providers": {"opencode": {"env": {"XDG_CONFIG_HOME": value}}}}})
                .to_string();
        write(&config, &text);
        let answer = ask(&config, home.path(), json!({}));
        assert_eq!(reason(&answer, "opencode"), expected, "{value:?}");
    }
}

#[test]
fn the_callers_environment_redirects_only_its_own_runtime() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join(".paseo/config.json");
    let answer = ask(&config, home.path(), json!({"CODEX_HOME": "/elsewhere"}));
    assert_eq!(reason(&answer, "codex"), CURRENT_ENV_REASON);
    assert_eq!(reason(&answer, "pi"), Value::Null);
    if cfg!(windows) {
        return;
    }
    let default = home.path().join(".config");
    let answer = ask(
        &config,
        home.path(),
        json!({"XDG_CONFIG_HOME": default.to_str().unwrap()}),
    );
    assert_eq!(reason(&answer, "copilot"), Value::Null);
}

#[test]
fn invalid_configuration_answers_the_message_python_raises() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join(".paseo/config.json");
    let unreadable = format!(
        "Cannot safely read configuration at {}; repair it before installing Paseo protection.",
        config.display()
    );
    let cases: [(&str, &str); 10] = [
        (r#"{"agents":"#, unreadable.as_str()),
        ("null", unreadable.as_str()),
        (r#"{"agents":{},"agents":{}}"#, unreadable.as_str()),
        (r#"{"agents":[]}"#, "Paseo agents must be a JSON object."),
        (
            r#"{"agents":{"providers":1}}"#,
            "Paseo providers must be a JSON object.",
        ),
        (
            r#"{"agents":{"providers":{"pi":{"enabled":"yes"}}}}"#,
            ERR_ENABLED,
        ),
        (r#"{"agents":{"providers":{"../escape":{}}}}"#, ERR_PROVIDER),
        (r#"{"agents":{"providers":{"pi":[]}}}"#, ERR_PROVIDER),
        (
            r#"{"agents":{"providers":{"pi":{"env":{"HOME":1}}}}}"#,
            ERR_ENV_VALUE,
        ),
        (
            r#"{"agents":{"providers":{"pi":{"env":[]}}}}"#,
            "Paseo env must be a JSON object.",
        ),
    ];
    for (text, message) in cases {
        write(&config, text);
        assert_eq!(
            ask(&config, home.path(), json!({})),
            json!({ "error": message }),
            "{text}"
        );
    }
    fs::write(&config, b"\xff").unwrap();
    assert_eq!(
        ask(&config, home.path(), json!({}))["error"],
        unreadable.as_str()
    );
    fs::write(&config, vec![b' '; MAX_CONFIG_BYTES + 1]).unwrap();
    assert_eq!(
        ask(&config, home.path(), json!({}))["error"],
        unreadable.as_str()
    );
    write(
        &config,
        r#"{"agents":{"providers":{"custom":{"extends":"pi"},"pi":5}}}"#,
    );
    assert_eq!(ask(&config, home.path(), json!({}))["error"], ERR_INHERITED);
}

#[test]
fn too_many_providers_are_refused_before_classification() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join(".paseo/config.json");
    let providers: serde_json::Map<String, Value> = (0..=MAX_PROVIDERS)
        .map(|index| (format!("p{index}"), json!({})))
        .collect();
    write(
        &config,
        &json!({"agents": {"providers": providers}}).to_string(),
    );
    assert_eq!(ask(&config, home.path(), json!({}))["error"], ERR_COUNT);
}

#[cfg(unix)]
#[test]
fn a_linked_configuration_is_unreadable() {
    let home = tempfile::tempdir().unwrap();
    let target = home.path().join("elsewhere.json");
    fs::write(&target, "{}").unwrap();
    let config = home.path().join(".paseo/config.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &config).unwrap();
    let error = ask(&config, home.path(), json!({}))["error"].clone();
    assert!(error
        .as_str()
        .unwrap()
        .starts_with("Cannot safely read configuration"));
    fs::remove_file(&target).unwrap();
    let error = ask(&config, home.path(), json!({}))["error"].clone();
    assert!(error
        .as_str()
        .unwrap()
        .starts_with("Cannot safely read configuration"));
}

#[test]
fn a_hard_linked_configuration_still_reads() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join(".paseo/config.json");
    write(
        &config,
        r#"{"agents":{"providers":{"pi":{"enabled":false}}}}"#,
    );
    fs::hard_link(&config, home.path().join("dotfiles-config.json")).unwrap();
    let answer = ask(&config, home.path(), json!({}));
    assert_eq!(by_id(&answer, "pi")["enabled"], false);
}

#[cfg(unix)]
#[test]
fn a_double_slash_home_keeps_its_default_xdg_directory() {
    let config = Path::new("/nonexistent-paseo/config.json");
    let answer = |value: &str| {
        let env = json!({"XDG_CONFIG_HOME": value});
        dispatch(&json!({
            "config_path": config.to_str().unwrap(),
            "xdg_default": "//home/alice/.config",
            "environ": env,
        }))
        .unwrap()
    };
    assert_eq!(
        reason(&answer("//home/alice/.config"), "opencode"),
        Value::Null
    );
    assert_eq!(
        reason(&answer("/home/alice/.config"), "opencode"),
        CURRENT_ENV_REASON
    );
}

#[test]
fn a_large_provider_environment_merges_in_order() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join(".paseo/config.json");
    let base: serde_json::Map<String, Value> = (0..20_000)
        .map(|index| (format!("K{index}"), json!("base")))
        .collect();
    let mut over = serde_json::Map::new();
    over.insert("K5".to_owned(), json!("child"));
    over.insert("PI_CODING_AGENT_DIR".to_owned(), json!("/elsewhere"));
    let text = json!({"agents": {"providers": {
        "pi": {"env": base},
        "work-pi": {"extends": "pi", "env": over},
    }}})
    .to_string();
    write(&config, &text);
    let answer = ask(&config, home.path(), json!({}));
    assert_eq!(reason(&answer, "pi"), Value::Null);
    assert_eq!(reason(&answer, "work-pi"), PROVIDER_ENV_REASON);
}

#[test]
fn malformed_requests_are_refused() {
    for args in [
        json!([]),
        json!({"config_path": "", "xdg_default": "/h/.config", "environ": {}}),
        json!({"config_path": "/c", "xdg_default": "/h/.config"}),
        json!({"config_path": "/c", "xdg_default": "/h/.config", "environ": {"A": 1}}),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID));
    }
}

#[test]
fn normpath_matches_posixpath() {
    assert_eq!(normpath("/a/./b/../c/"), "/a/c");
    assert_eq!(normpath("/.."), "/");
    assert_eq!(normpath("//a//b"), "//a/b");
    assert_eq!(normpath("///a"), "/a");
}

#[cfg(unix)]
#[test]
fn the_bounded_read_refuses_a_link_swapped_in_after_the_check() {
    let home = tempfile::tempdir().unwrap();
    let target = home.path().join("elsewhere.json");
    fs::write(&target, "{}").unwrap();
    let config = home.path().join("config.json");
    std::os::unix::fs::symlink(&target, &config).unwrap();
    assert_eq!(read_bounded(&config), None);
    assert_eq!(read_bounded(&target), Some(b"{}".to_vec()));
}

#[cfg(unix)]
#[test]
fn the_bounded_read_refuses_a_fifo_without_blocking() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("config.json");
    let made = std::process::Command::new("mkfifo")
        .arg(&config)
        .status()
        .unwrap();
    assert!(made.success());
    assert_eq!(read_bounded(&config), None);
}
