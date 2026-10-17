use std::path::PathBuf;

use super::*;

fn argv(tokens: &[&str]) -> Vec<String> {
    tokens.iter().map(|token| (*token).to_owned()).collect()
}

fn base(proxy: &str) -> Vec<String> {
    argv(&[
        "/usr/bin/python3",
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        proxy,
        "--guard-home",
        "/guard/home",
        "--server-name",
        "files",
        "--config-path",
        "/project/.codex/config.toml",
        "--command",
        "npx",
    ])
}

#[test]
fn parses_the_installed_codex_proxy_argv() {
    let mut tokens = base("codex-mcp-proxy");
    tokens.extend(argv(&[
        "--arg=-y",
        "--arg",
        "server-files",
        "--arg=--root=/data",
        "--server-env-key",
        "API_TOKEN",
        "--server-env-key=REGION",
        "--server-env-key= API_TOKEN ",
        "--server-env-key=  ",
        "--server-id=abc",
        "--source-scope",
        "global",
    ]));
    let parsed = parse(&tokens).unwrap();
    assert_eq!(parsed.harness, "codex");
    assert!(parsed.elicitation_capable);
    assert_eq!(parsed.guard_home, PathBuf::from("/guard/home"));
    assert_eq!(parsed.server_name, "files");
    assert_eq!(parsed.config_path, "/project/.codex/config.toml");
    assert_eq!(parsed.command, "npx");
    assert_eq!(parsed.args, vec!["-y", "server-files", "--root=/data"]);
    assert_eq!(parsed.server_env_keys, vec!["API_TOKEN", "REGION"]);
    assert_eq!(parsed.server_id.as_deref(), Some("abc"));
    assert_eq!(parsed.source_scope, "global");
    assert_eq!(parsed.transport, "stdio");
    assert_eq!(parsed.home, None);
    assert_eq!(parsed.workspace, None);
}

#[test]
fn harness_defaults_follow_the_proxy_command() {
    for (proxy, harness, transport, elicitation) in [
        ("codex-mcp-proxy", "codex", "stdio", true),
        ("copilot-mcp-proxy", "copilot", "stdio", true),
        ("cursor-mcp-proxy", "cursor", "stdio", true),
        ("opencode-mcp-proxy", "opencode", "local", false),
    ] {
        let parsed = parse(&base(proxy)).unwrap();
        assert_eq!(parsed.harness, harness);
        assert_eq!(parsed.transport, transport);
        assert_eq!(parsed.elicitation_capable, elicitation);
        assert_eq!(parsed.source_scope, "project");
        assert!(parsed.args.is_empty());
        assert!(parsed.server_env_keys.is_empty());
    }
}

#[test]
fn a_repeated_scalar_flag_keeps_the_last_value() {
    let mut tokens = base("cursor-mcp-proxy");
    tokens.extend(argv(&["--command=uvx", "--transport", "sse"]));
    let parsed = parse(&tokens).unwrap();
    assert_eq!(parsed.command, "uvx");
    assert_eq!(parsed.transport, "sse");
}

#[test]
fn an_empty_inline_value_is_kept_for_repeated_flags() {
    let mut tokens = base("codex-mcp-proxy");
    tokens.push("--arg=".to_owned());
    assert_eq!(parse(&tokens).unwrap().args, vec![String::new()]);
}

#[test]
fn rejects_a_missing_proxy_command() {
    let error = parse(&argv(&["guard", "codex-mcp-server", "--command", "npx"])).unwrap_err();
    assert_eq!(error, "mcp_relay_proxy_command_missing");
    assert_eq!(
        parse(&argv(&["codex-mcp-proxy"])).unwrap_err(),
        "mcp_relay_proxy_command_missing"
    );
    assert_eq!(parse(&[]).unwrap_err(), "mcp_relay_proxy_command_missing");
}

#[test]
fn rejects_unknown_unexpected_and_valueless_flags() {
    let mut unknown = base("codex-mcp-proxy");
    unknown.push("--surprise=1".to_owned());
    assert_eq!(parse(&unknown).unwrap_err(), "mcp_relay_argument_unknown");

    let mut positional = base("codex-mcp-proxy");
    positional.push("stray".to_owned());
    assert_eq!(
        parse(&positional).unwrap_err(),
        "mcp_relay_argument_unexpected"
    );

    let mut valueless = base("codex-mcp-proxy");
    valueless.push("--arg".to_owned());
    assert_eq!(
        parse(&valueless).unwrap_err(),
        "mcp_relay_argument_value_missing"
    );
}

#[test]
fn rejects_missing_or_empty_required_flags() {
    for flag in [
        "--guard-home",
        "--server-name",
        "--config-path",
        "--command",
    ] {
        let tokens = base("codex-mcp-proxy");
        let position = tokens.iter().position(|token| token == flag).unwrap();
        let mut missing = tokens.clone();
        missing.drain(position..position + 2);
        assert_eq!(parse(&missing).unwrap_err(), "mcp_relay_argument_required");

        let mut empty = tokens;
        empty[position + 1] = String::new();
        assert_eq!(parse(&empty).unwrap_err(), "mcp_relay_argument_required");
    }
}

#[test]
fn keeps_an_explicit_home() {
    let mut tokens = base("codex-mcp-proxy");
    tokens.extend(argv(&["--home", "/users/dev"]));
    assert_eq!(
        parse(&tokens).unwrap().home,
        Some(PathBuf::from("/users/dev"))
    );
    let mut empty = base("codex-mcp-proxy");
    empty.push("--home=".to_owned());
    assert_eq!(parse(&empty).unwrap().home, None);
}

#[test]
fn normalizes_the_workspace() {
    let root = std::env::temp_dir().canonicalize().unwrap();
    let mut tokens = base("codex-mcp-proxy");
    tokens.push(format!("--workspace={}", root.display()));
    assert_eq!(parse(&tokens).unwrap().workspace, Some(root.clone()));

    assert_eq!(normalize_workspace(""), None);
    assert_eq!(normalize_workspace("   "), None);
    assert_eq!(normalize_workspace("None"), None);
    assert_eq!(normalize_workspace("null"), None);
    assert_eq!(normalize_workspace("NULL"), None);
    assert_eq!(
        normalize_workspace(&format!("  {}  ", root.display())),
        Some(root.clone())
    );
    // `join` uses the native separator: a canonical Windows root is a
    // verbatim `\\?\` path, where `/` is not a separator.
    assert_eq!(
        normalize_workspace(&root.join("None").display().to_string()),
        Some(root.clone())
    );
    let missing = normalize_workspace("/guard-relay-missing/workspace").unwrap();
    assert!(missing.is_absolute());
    assert!(missing.ends_with("guard-relay-missing/workspace"));
    #[cfg(unix)]
    assert_eq!(missing, PathBuf::from("/guard-relay-missing/workspace"));
    let relative = normalize_workspace("guard-relay-missing-relative").unwrap();
    assert!(relative.is_absolute());
    assert!(relative.ends_with("guard-relay-missing-relative"));
}

#[test]
fn expands_the_home_prefix() {
    let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) else {
        return;
    };
    let home = PathBuf::from(home);
    assert_eq!(expand_user("~"), home);
    assert_eq!(expand_user("~/projects/app"), home.join("projects/app"));
    assert_eq!(expand_user("~other/app"), PathBuf::from("~other/app"));
    assert_eq!(expand_user("/abs/~"), PathBuf::from("/abs/~"));
}
