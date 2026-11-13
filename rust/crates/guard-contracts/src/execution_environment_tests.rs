use super::*;

#[test]
fn heap_and_diagnostic_flags_are_inert() {
    for value in [
        "--max-old-space-size=8192",
        " --max_old_space_size=4096  --no-warnings ",
        "--enable-source-maps --stack-trace-limit=50",
        "--max-semi-space-size=64 --trace-deprecation",
        // The spelling an ESM Jest run needs, alone and beside a heap size.
        "--experimental-vm-modules",
        "--experimental_vm_modules",
        "--experimental-vm-modules --max-old-space-size=4096",
    ] {
        assert!(node_options_inert(value), "{value:?}");
    }
}

#[test]
fn loaders_files_and_odd_spellings_are_not_inert() {
    for value in [
        "",
        "   ",
        "--require ./hook.js",
        "--require=./hook.js",
        "-r ./hook.js",
        "--import=data:text/javascript,0",
        "--loader ./loader.mjs",
        "--experimental-loader=./loader.mjs",
        // Only the exact flag is inert: it takes no value, and no other
        // `--experimental-` option inherits the reading.
        "--experimental-vm-modules=1",
        "--experimental-vm-modules --require=./hook.js",
        "--experimental-network-imports",
        "--experimental-policy=./policy.json",
        "--inspect=0.0.0.0:9229",
        "--max-old-space-size=8192 --require=./hook.js",
        "--max-old-space-size=",
        "--max-old-space-size=8g",
        "--max-old-space-size 8192",
        "--env-file=.env",
        "--max-old-space-size=8192\t--require=x",
        "\"--max-old-space-size=8192\"",
        "--no-warnings=1",
    ] {
        assert!(!node_options_inert(value), "{value:?}");
    }
}

#[test]
fn the_flag_is_omitted_when_false() {
    let stamp = GuardExecutionEnvironmentV1::unavailable();
    let text = serde_json::to_string(&stamp).unwrap();
    assert!(!text.contains("node_options_inert"), "{text}");
    let stamp = GuardExecutionEnvironmentV1 {
        node_options_inert: true,
        ..stamp
    };
    let text = serde_json::to_string(&stamp).unwrap();
    let read: GuardExecutionEnvironmentV1 = serde_json::from_str(&text).unwrap();
    assert!(read.node_options_inert, "{text}");
}

#[test]
fn only_the_default_cargo_home_moves_nothing() {
    assert!(cargo_home_default(
        Some("/Users/dev"),
        Some("/Users/dev/.cargo")
    ));
    assert!(cargo_home_default(
        Some("/Users/dev/"),
        Some("/Users/dev/.cargo/")
    ));
    for (home, cargo_home) in [
        (Some("/Users/dev"), Some("/opt/cargo")),
        (Some("/Users/dev"), Some("/Users/dev/.cargo/vendor")),
        (Some("/Users/dev"), Some(".cargo")),
        (Some("/Users/dev"), Some("")),
        (Some("/Users/dev"), None),
        (None, Some("/Users/dev/.cargo")),
        (Some("/"), Some("/.cargo")),
    ] {
        assert!(
            !cargo_home_default(home, cargo_home),
            "{home:?} {cargo_home:?}"
        );
    }
}

#[test]
fn the_cargo_home_flag_is_omitted_when_false() {
    let stamp = GuardExecutionEnvironmentV1::unavailable();
    let text = serde_json::to_string(&stamp).unwrap();
    assert!(!text.contains("cargo_home_default"), "{text}");
    let stamp = GuardExecutionEnvironmentV1 {
        cargo_home_default: true,
        ..stamp
    };
    let text = serde_json::to_string(&stamp).unwrap();
    let read: GuardExecutionEnvironmentV1 = serde_json::from_str(&text).unwrap();
    assert!(read.cargo_home_default, "{text}");
}

fn git_config_inert(entries: &[(&str, &str)]) -> bool {
    let map: BTreeMap<String, String> = entries
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    git_config_environment_inert(|name| map.get(name).map(String::as_str))
}

#[test]
fn an_editor_quote_path_entry_is_inert() {
    // The exact entry Cursor and VS Code export in their terminals.
    assert!(git_config_inert(&[
        ("GIT_CONFIG_COUNT", "1"),
        ("GIT_CONFIG_KEY_0", "core.quotePath"),
        ("GIT_CONFIG_VALUE_0", "false"),
    ]));
    assert!(git_config_inert(&[
        ("GIT_CONFIG_COUNT", "2"),
        ("GIT_CONFIG_KEY_0", "core.quotepath"),
        ("GIT_CONFIG_VALUE_0", "off"),
        ("GIT_CONFIG_KEY_1", "CORE.QUOTEPATH"),
        ("GIT_CONFIG_VALUE_1", "true"),
    ]));
    // Entries past the count are never read by Git.
    assert!(git_config_inert(&[
        ("GIT_CONFIG_COUNT", "1"),
        ("GIT_CONFIG_KEY_0", "core.quotePath"),
        ("GIT_CONFIG_VALUE_0", "false"),
        ("GIT_CONFIG_KEY_1", "core.pager"),
        ("GIT_CONFIG_VALUE_1", "sh -c id"),
    ]));
}

#[test]
fn other_git_config_entries_are_not_inert() {
    for entries in [
        &[][..],
        &[("GIT_CONFIG_COUNT", "1")][..],
        &[
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.quotePath"),
        ][..],
        &[
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.pager"),
            ("GIT_CONFIG_VALUE_0", "less"),
        ][..],
        &[
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.fsmonitor"),
            ("GIT_CONFIG_VALUE_0", "./x"),
        ][..],
        &[
            ("GIT_CONFIG_COUNT", "2"),
            ("GIT_CONFIG_KEY_0", "core.quotePath"),
            ("GIT_CONFIG_VALUE_0", "false"),
            ("GIT_CONFIG_KEY_1", "include.path"),
            ("GIT_CONFIG_VALUE_1", "/tmp/x"),
        ][..],
        &[
            ("GIT_CONFIG_COUNT", " core.quotePath"),
            ("GIT_CONFIG_KEY_0", "core.quotePath"),
            ("GIT_CONFIG_VALUE_0", "false"),
        ][..],
        // Git reads `1k` as 1024 entries.
        &[
            ("GIT_CONFIG_COUNT", "1k"),
            ("GIT_CONFIG_KEY_0", "core.quotePath"),
            ("GIT_CONFIG_VALUE_0", "false"),
        ][..],
        &[("GIT_CONFIG_COUNT", "9")][..],
        &[("GIT_CONFIG_COUNT", "")][..],
        &[("GIT_CONFIG_COUNT", "+1")][..],
    ] {
        assert!(!git_config_inert(entries), "{entries:?}");
    }
}

#[test]
fn git_config_count_entries_are_recognized() {
    for name in [
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_12",
        "git_config_key_3",
    ] {
        assert!(git_config_count_entry(name), "{name}");
    }
    for name in [
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG",
        "GIT_CONFIG_KEY_",
        "GIT_CONFIG_KEY_x",
        "GIT_CONFIG_VALUE_0x",
    ] {
        assert!(!git_config_count_entry(name), "{name}");
    }
}

#[test]
fn the_git_config_flag_is_omitted_when_false() {
    let stamp = GuardExecutionEnvironmentV1::unavailable();
    let text = serde_json::to_string(&stamp).unwrap();
    assert!(!text.contains("git_config_environment_inert"), "{text}");
    let stamp = GuardExecutionEnvironmentV1 {
        git_config_environment_inert: true,
        ..stamp
    };
    let text = serde_json::to_string(&stamp).unwrap();
    let read: GuardExecutionEnvironmentV1 = serde_json::from_str(&text).unwrap();
    assert!(read.git_config_environment_inert, "{text}");
}
