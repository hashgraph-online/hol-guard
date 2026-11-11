use super::{
    cargo_config_inert, inert_toolchain, registry_query, rustup_settings,
    rustup_settings_only_official, safe_cargo_probe, RustupSettings,
};
use std::path::Path;

fn words(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn reads_a_bounded_search_query_only() {
    for arguments in [
        "search serde",
        "search serde json",
        "search --limit 5 serde",
        "search --limit=100 serde",
        "search",
    ] {
        assert!(registry_query(&words(arguments)), "{arguments}");
    }
    for arguments in [
        "search --limit 0 serde",
        "search --limit 101 serde",
        "search --limit all serde",
        "search --limit",
        "search --registry mirror serde",
        "search --index https://example.invalid serde",
        "search -Z unstable-options serde",
        "search +nightly serde",
        // The shell turns each of these into words Cargo reads as
        // options, so neither is the query this proof read.
        "search {--config,evil.toml} serde",
        "search *",
        "search ?erde",
        "search [a-z]erde",
        "search ~/serde",
        "install serde",
        "test",
    ] {
        assert!(!registry_query(&words(arguments)), "{arguments}");
    }
}

#[test]
fn admits_plain_channels_only() {
    for contents in [
        "stable",
        "1.85.0\n",
        "nightly-2025-01-01",
        "1.85",
        "stable-aarch64-apple-darwin",
        "nightly-2025-01-01-x86_64-unknown-linux-gnu",
        "stable-x86_64-pc-windows-msvc",
        "1.85.0-aarch64-unknown-linux-musl",
        "[toolchain]\nchannel = \"1.85.0\"\n",
        "[toolchain]\nchannel = \"stable\"\ncomponents = [\"clippy\", \"rustfmt\"]\nprofile = \"minimal\"\n",
    ] {
        assert!(inert_toolchain(contents), "{contents}");
    }
    for contents in [
        "",
        "../toolchain",
        "/opt/toolchain",
        "C:\\toolchain",
        "[toolchain]\npath = \"/opt/toolchain\"\n",
        "[toolchain]\nchannel = \"stable\"\npath = \"tools\"\n",
        "[toolchain]\nchannel = \"../tools\"\n",
        "my-toolchain",
        "custom",
        "stable-",
        "1",
        "1.85.0.1",
        "nightly-2025-01-01-Evil",
        // Lowercase tails that are not known triples are valid custom
        // names that rustup can link to a local directory.
        "stable-evil-thing",
        "nightly-2025-01-01-my-build",
        "stable-x86_64-evil",
        "stable-x86_64-unknown-linux-evil",
        "stable-x86_64-unknown-linux-gnu-extra",
        "[toolchain]\nchannel = \"workspace-linked\"\n",
        "[toolchain]\ncomponents = [\"clippy\"]\n",
        "[toolchain]\nchannel = \"stable\"\n[other]\nkey = 1\n",
        "path = \"/opt/toolchain\"\n",
        "[toolchain\n",
    ] {
        assert!(!inert_toolchain(contents), "{contents}");
    }
}

#[test]
fn refuses_a_cargo_configuration_that_can_move_the_registry() {
    let root = std::env::temp_dir().join(format!(
        "guard-cargo-config-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos(),
    ));
    let directory = root.join(".cargo");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config.toml");
    // A directory with no Cargo configuration at all leaves the query
    // pointed at crates.io.
    assert!(cargo_config_inert(Path::new(&root)));
    for contents in [
        "[profile.dev]\nopt-level = 1\n",
        "[build]\ntarget-dir = \"out\"\nrustc-wrapper = \"sccache\"\n",
        "[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\n",
        "[alias]\nb = \"build\"\n",
        "[term]\nquiet = true\n",
    ] {
        std::fs::write(&path, contents).unwrap();
        assert!(cargo_config_inert(Path::new(&root)), "{contents}");
    }
    for contents in [
        "[registry]\ndefault = \"mirror\"\n",
        "[registry]\nglobal-credential-providers = [\"./evil\"]\n",
        "[registries.mirror]\nindex = \"sparse+https://example.invalid/\"\n",
        "[source.crates-io]\nreplace-with = \"mirror\"\n",
        "[http]\nproxy = \"http://example.invalid\"\n",
        "[net]\noffline = false\n",
        "[credential-alias]\nevil = [\"./evil\"]\n",
        "[env]\nCARGO_REGISTRY_DEFAULT = \"mirror\"\n",
        "[unstable]\ncredential-process = true\n",
        // Unreadable configuration is not proof of anything.
        "[registry\n",
    ] {
        std::fs::write(&path, contents).unwrap();
        assert!(!cargo_config_inert(Path::new(&root)), "{contents}");
    }
    std::fs::remove_file(&path).unwrap();
    // Cargo reads the extensionless spelling too.
    std::fs::write(
        directory.join("config"),
        "[registry]\ndefault = \"mirror\"\n",
    )
    .unwrap();
    assert!(!cargo_config_inert(Path::new(&root)));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn formatter_requires_official_default_and_official_directory_overrides() {
    let root = std::env::temp_dir().join(format!(
        "guard-rustfmt-settings-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos(),
    ));
    let directory = root.join(".rustup");
    std::fs::create_dir_all(&directory).unwrap();
    let settings = directory.join("settings.toml");
    std::fs::write(
        &settings,
        "version = \"12\"\ndefault_toolchain = \"stable-x86_64-unknown-linux-gnu\"\n[overrides]\n",
    )
    .unwrap();
    assert!(rustup_settings_only_official(Path::new(&root)));
    std::fs::write(
        &settings,
        "default_toolchain = \"custom-formatter\"\n[overrides]\n",
    )
    .unwrap();
    assert!(!rustup_settings_only_official(Path::new(&root)));
    std::fs::write(
        &settings,
        "default_toolchain = \"stable\"\n[overrides]\n\"/tmp/project\" = \"custom-formatter\"\n",
    )
    .unwrap();
    assert!(!rustup_settings_only_official(Path::new(&root)));
    std::fs::write(&settings, "default_toolchain = \"stable\"\n").unwrap();
    assert!(rustup_settings_only_official(Path::new(&root)));

    // `rustup override set nightly` in another checkout stores an
    // official channel, which can only select a toolchain rustup verified.
    std::fs::write(
        &settings,
        "default_toolchain = \"stable\"\n[overrides]\n\"/tmp/a\" = \"nightly-aarch64-apple-darwin\"\n\"/tmp/b\" = \"1.88.0\"\n",
    )
    .unwrap();
    assert!(rustup_settings_only_official(Path::new(&root)));
    // One custom entry among official ones, or a value that is not a
    // name, keeps the review.
    std::fs::write(
        &settings,
        "default_toolchain = \"stable\"\n[overrides]\n\"/tmp/a\" = \"nightly\"\n\"/tmp/b\" = \"nightly-custom\"\n",
    )
    .unwrap();
    assert!(!rustup_settings_only_official(Path::new(&root)));
    std::fs::write(
        &settings,
        "default_toolchain = \"stable\"\n[overrides]\n\"/tmp/a\" = { path = \"/tmp/cargo\" }\n",
    )
    .unwrap();
    assert!(!rustup_settings_only_official(Path::new(&root)));
    // A numeric name outside rustup's release grammar is a linkable custom
    // toolchain, not a release.
    std::fs::write(
        &settings,
        "default_toolchain = \"stable\"\n[overrides]\n\"/tmp/a\" = \"10.0\"\n",
    )
    .unwrap();
    assert!(!rustup_settings_only_official(Path::new(&root)));
    std::fs::write(
        &settings,
        "default_toolchain = \"stable\"\noverrides = \"nightly\"\n",
    )
    .unwrap();
    assert!(!rustup_settings_only_official(Path::new(&root)));

    // A settings file that names no default selects no toolchain at all.
    // A query reads that as nothing stored, because rustup stops with its
    // own error rather than running something unproven. The formatter
    // writes files, so it asks for the positive answer instead.
    std::fs::write(&settings, "version = \"12\"\n").unwrap();
    assert!(matches!(
        rustup_settings(Path::new(&root)),
        RustupSettings::Official {
            default_named: false
        }
    ));
    assert!(!rustup_settings_only_official(Path::new(&root)));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_stored_rustup_default_decides_whether_the_search_is_read() {
    let root = std::env::temp_dir().join(format!(
        "guard-cargo-settings-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos(),
    ));
    let cwd = root.join("workspace");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = root.to_str().unwrap().to_owned();
    let cwd = cwd.to_str().unwrap().to_owned();
    let query = words("search serde");
    let context = || super::super::PathContext {
        home_dir: Some(&home),
        cwd: Some(&cwd),
        rustup_override_absent: true,
        cargo_config_inert: true,
        ..Default::default()
    };

    // No rustup home at all: nothing stored selects a toolchain, so the
    // query is read on whichever `cargo` the session already found.
    assert!(safe_cargo_probe(&query, context()));

    let directory = root.join(".rustup");
    std::fs::create_dir_all(&directory).unwrap();
    let settings = directory.join("settings.toml");
    assert!(safe_cargo_probe(&query, context()));

    // A linked toolchain runs a Cargo from a directory rustup never
    // downloaded or verified, and a directory override can name one for
    // this workspace alone. Both keep the review.
    std::fs::write(&settings, "default_toolchain = \"vendor-cargo\"\n").unwrap();
    assert!(!safe_cargo_probe(&query, context()));
    std::fs::write(
        &settings,
        "default_toolchain = \"stable\"\n[overrides]\n\"/tmp/project\" = \"vendor-cargo\"\n",
    )
    .unwrap();
    assert!(!safe_cargo_probe(&query, context()));

    // A directory override that names an official channel selects a
    // toolchain rustup downloaded and verified, wherever it applies.
    std::fs::write(
        &settings,
        "default_toolchain = \"stable\"\n[overrides]\n\"/tmp/project\" = \"nightly\"\n",
    )
    .unwrap();
    assert!(safe_cargo_probe(&query, context()));
    assert!(super::safe_version_probe(&words("--version"), context()));

    std::fs::write(&settings, "default_toolchain = \"stable\"\n").unwrap();
    assert!(safe_cargo_probe(&query, context()));
    std::fs::remove_dir_all(root).unwrap();
}
