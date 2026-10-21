use guard_command::mcp_decision::{build_mcp_server_identity, package_source_token};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn configuration_and_source_operands_do_not_become_the_package() {
    for (launcher, flag, operand) in [
        ("npx", "--userconfig", "evil.npmrc"),
        ("npx", "--globalconfig", "evil.npmrc"),
        ("npx", "--userconf", "evil.npmrc"),
        ("npx", "--reg", "https://alternate.example.invalid"),
        (
            "npx",
            "--@scope:registry",
            "https://alternate.example.invalid",
        ),
        ("bunx", "--config", "evil.bunfig.toml"),
        ("yarn", "--use-yarnrc", "evil.yarnrc"),
        ("uvx", "--config-file", "evil.toml"),
        (
            "uvx",
            "--default-index",
            "https://alternate.example.invalid",
        ),
        ("uvx", "--find-links", "./unreviewed-wheels"),
        ("uvx", "--env-file", "evil.env"),
        (
            "pipx",
            "--pip-args",
            "--index-url https://alternate.example.invalid",
        ),
    ] {
        let separated = args(&[flag, operand, "mcp-mail-server"]);
        let inline = args(&[&format!("{flag}={operand}"), "mcp-mail-server"]);
        for argv in [&separated, &inline] {
            let identity = build_mcp_server_identity("", launcher, argv, "stdio", None, &[]);
            assert_eq!(identity.package_name.as_deref(), Some("mcp-mail-server"));
            assert_ne!(identity.package_source, "default", "{launcher} {argv:?}");
        }
        assert_eq!(
            package_source_token(launcher, &separated),
            package_source_token(launcher, &inline)
        );
    }
}

#[test]
fn neutral_launcher_options_and_server_arguments_keep_default_source() {
    for argv in [
        args(&["-y", "mcp-mail-server"]),
        args(&["--quiet", "-y", "mcp-mail-server@2.1.0"]),
        args(&["-y", "mcp-mail-server", "--port", "3000"]),
        args(&["--", "mcp-mail-server", "--port", "3000"]),
    ] {
        assert_eq!(package_source_token("npx", &argv), "default");
    }
    assert_eq!(
        package_source_token(
            "npm",
            &args(&["exec", "--", "mcp-mail-server", "--port", "3000"])
        ),
        "default"
    );
}

#[test]
fn unfamiliar_launcher_options_fail_closed_and_bind_their_operands() {
    let first = args(&["--future-config", "secret-one", "mcp-mail-server"]);
    let second = args(&["--future-config", "secret-two", "mcp-mail-server"]);
    let source = package_source_token("npx", &first);
    assert_ne!(source, "default");
    assert_ne!(source, package_source_token("npx", &second));
    assert!(!source.contains("secret-one"));
    assert_ne!(
        package_source_token(
            "npx",
            &args(&["--", "--future-config=evil", "mcp-mail-server"])
        ),
        "default"
    );
    assert_ne!(
        package_source_token("npx", &args(&["--registry"])),
        "default"
    );
    assert_ne!(
        package_source_token(
            "npm",
            &args(&["exec", "mcp-mail-server", "--future-config=evil"])
        ),
        "default"
    );
}

#[test]
fn new_configuration_tokens_do_not_expose_paths_or_forwarded_credentials() {
    for (launcher, flag) in [
        ("npx", "--userconfig"),
        ("pipx", "--pip-args"),
        ("npx", "--reg"),
        ("uvx", "-i"),
    ] {
        let source = package_source_token(
            launcher,
            &args(&[flag, "secret-credential", "mcp-mail-server"]),
        );
        assert_ne!(source, "default");
        assert!(!source.contains("secret-credential"));
    }
}

#[test]
fn existing_explicit_registry_tokens_remain_compatible() {
    let registry = "https://alternate.example.invalid";
    assert_eq!(
        package_source_token(
            "npx",
            &args(&["--registry", registry, "-y", "mcp-mail-server"])
        ),
        format!("--registry={registry}")
    );
}

#[test]
fn short_index_and_find_links_options_are_launcher_specific() {
    for (launcher, flag) in [("uvx", "-i"), ("uvx", "-f"), ("pipx", "-i")] {
        let argv = args(&[flag, "alternate", "mcp-mail-server"]);
        let identity = build_mcp_server_identity("", launcher, &argv, "stdio", None, &[]);
        assert_eq!(identity.package_name.as_deref(), Some("mcp-mail-server"));
        assert_ne!(identity.package_source, "default");
    }
    let identity = build_mcp_server_identity(
        "",
        "npx",
        &args(&["-f", "mcp-mail-server"]),
        "stdio",
        None,
        &[],
    );
    assert_eq!(identity.package_name.as_deref(), Some("mcp-mail-server"));
    assert_ne!(identity.package_source, "default");
}
