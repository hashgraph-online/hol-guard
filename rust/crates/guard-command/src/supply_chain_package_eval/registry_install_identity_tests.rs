use super::*;

fn tokens(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn last_ignore_scripts_spelling_wins() {
    assert!(lifecycle_scripts_disabled(&tokens(
        "npm install zod --ignore-scripts"
    )));
    assert!(lifecycle_scripts_disabled(&tokens(
        "npm i --ignore-scripts true zod"
    )));
    assert!(lifecycle_scripts_disabled(&tokens(
        "npm i --ignore-scripts=true zod"
    )));
    assert!(!lifecycle_scripts_disabled(&tokens("npm install zod")));
    assert!(!lifecycle_scripts_disabled(&tokens(
        "npm i --ignore-scripts false zod"
    )));
    assert!(!lifecycle_scripts_disabled(&tokens(
        "npm i --ignore-scripts=false zod"
    )));
    assert!(!lifecycle_scripts_disabled(&tokens(
        "npm i --ignore-scripts=1 zod"
    )));
    assert!(!lifecycle_scripts_disabled(&tokens(
        "npm i --ignore-scripts --no-ignore-scripts zod"
    )));
    assert!(!lifecycle_scripts_disabled(&tokens(
        "npm i zod -- --ignore-scripts"
    )));
}

#[test]
fn last_allow_git_spelling_wins() {
    assert!(git_dependencies_refused(&tokens(
        "npm i zod --allow-git=none"
    )));
    assert!(git_dependencies_refused(&tokens(
        "npm i zod --allow-git none"
    )));
    assert!(git_dependencies_refused(&tokens(
        "npm i --allow-git=all zod --allow-git=none"
    )));
    assert!(!git_dependencies_refused(&tokens("npm i zod")));
    assert!(!git_dependencies_refused(&tokens(
        "npm i zod --allow-git=root"
    )));
    assert!(!git_dependencies_refused(&tokens(
        "npm i --allow-git=none zod --allow-git=all"
    )));
    assert!(!git_dependencies_refused(&tokens(
        "npm i zod -- --allow-git=none"
    )));
}

#[test]
fn only_recording_options_and_exact_safety_flags_qualify() {
    assert!(only_recording_options(&tokens(
        "npm i -D zod vitest --ignore-scripts --allow-git=none --no-audit"
    )));
    assert!(only_recording_options(&tokens(
        "npm --ignore-scripts true install zod --allow-git none"
    )));
    for extra in [
        "--allow-g=all",
        "--ignore-s=false",
        "--no-allow-git",
        "--reg=https://example.test/",
        "-reg",
        "--strict-ssl=false",
        "--ignore-scripts=false",
        "-g",
        "--",
        "[REDACTED_URL]",
        "user/zod",
        "../local",
    ] {
        assert!(
            !only_recording_options(&tokens(&format!(
                "npm i zod --ignore-scripts --allow-git=none {extra}"
            ))),
            "{extra}"
        );
    }
    // A redacted option before the subcommand cannot pass as the subcommand.
    assert!(!only_recording_options(&tokens(
        "npm [REDACTED_URL] install zod --ignore-scripts --allow-git=none"
    )));
}

#[test]
fn only_npm_releases_with_allow_git_qualify() {
    assert_eq!(release_triple("11.9.0"), Some((11, 9, 0)));
    assert_eq!(release_triple("12.0.0-pre.1"), Some((12, 0, 0)));
    assert_eq!(release_triple("11.10"), None);
    assert_eq!(release_triple("v11.9.0"), None);
    assert!(release_triple("11.8.9").is_some_and(|v| v < MIN_ALLOW_GIT_NPM));
    assert!(release_triple("11.10.0").is_some_and(|v| v >= MIN_ALLOW_GIT_NPM));
}

#[test]
fn npmrc_settings_that_move_the_fetch_are_overrides() {
    assert!(npmrc_redirects_fetch("registry=https://example.test/"));
    assert!(npmrc_redirects_fetch(
        "@acme:registry = https://example.test/"
    ));
    assert!(npmrc_redirects_fetch("strict-ssl=false"));
    assert!(npmrc_redirects_fetch("\"https-proxy\"=http://example.test"));
    assert!(npmrc_redirects_fetch("Prefix=/tmp/x"));
    assert!(npmrc_redirects_fetch("noproxy=registry.npmjs.org"));
    assert!(!npmrc_redirects_fetch("# registry=https://example.test/"));
    assert!(!npmrc_redirects_fetch("save-exact=true"));
    assert!(!npmrc_redirects_fetch("engine-strict=true"));
}

#[test]
fn registry_flags_are_overrides() {
    assert!(command_overrides_registry(&tokens(
        "npm i zod --registry https://example.test"
    )));
    assert!(command_overrides_registry(&tokens(
        "npm i zod --registry=https://example.test"
    )));
    assert!(command_overrides_registry(&tokens(
        "npm i @a/b --@a:registry=https://example.test"
    )));
    assert!(!command_overrides_registry(&tokens(
        "npm i zod --ignore-scripts"
    )));
}

#[test]
fn global_and_prefixed_installs_are_relocated() {
    assert!(command_relocates_install(&tokens(
        "npm i -g zod --ignore-scripts"
    )));
    assert!(command_relocates_install(&tokens("npm i --global zod")));
    assert!(command_relocates_install(&tokens(
        "npm i --location=global zod"
    )));
    assert!(command_relocates_install(&tokens(
        "npm i --prefix /tmp/x zod"
    )));
    assert!(command_relocates_install(&tokens(
        "pnpm add -C ../other zod"
    )));
    assert!(command_relocates_install(&tokens("npm i -gD zod")));
    assert!(!command_relocates_install(&tokens(
        "npm i -D zod --ignore-scripts"
    )));
}

#[test]
fn only_plain_registry_specs_qualify() {
    for plain in [
        "zod",
        "zod@3",
        "@scope/pkg@^1.2.0",
        "lodash.merge@>=4 <5",
        "react@next",
    ] {
        assert!(plain_registry_spec(plain), "{plain}");
    }
    for source in [
        "foo@npm:bar",
        "./local",
        "../x",
        "/abs/path",
        "user/repo",
        "github:user/repo",
        "foo@git+https://github.com/a/b",
        "https://example.com/a.tgz",
        "file:../x",
        "foo@file:../x",
        "@scope",
        "Zod",
        "foo@",
        "foo@1#sha",
    ] {
        assert!(!plain_registry_spec(source), "{source}");
    }
}

#[test]
fn bare_names_resolve_the_latest_release() {
    let target = |raw_spec: &str, range: Value, version: Value| {
        let mut target = Map::new();
        target.insert("raw_spec".to_owned(), Value::String(raw_spec.to_owned()));
        target.insert("range".to_owned(), range);
        target.insert("version".to_owned(), version);
        target
    };
    assert_eq!(
        registry_selector(&target("zod", Value::Null, Value::Null)).as_deref(),
        Some("latest")
    );
    assert_eq!(
        registry_selector(&target("zod@^3", Value::String("^3".into()), Value::Null)).as_deref(),
        Some("^3")
    );
    assert_eq!(
        registry_selector(&target(
            "zod@3.23.8",
            Value::Null,
            Value::String("3.23.8".into())
        ))
        .as_deref(),
        Some("3.23.8")
    );
    assert_eq!(
        registry_selector(&target("user/repo", Value::Null, Value::Null)),
        None
    );
}

/// Regression for #4809 (Path 2): when a frozen `npm ci` lockfile pins two
/// scoped packages that share an unscoped name (`@oh-my-pi/pi-coding-agent`
/// and `@earendil-works/pi-coding-agent`), the package map handed to
/// `finalize_evaluation` must carry each entry's `namespace` with the
/// leading `@` (the npm canonical form produced by
/// `split_namespace_name` / `parse_package_identity` and used by the
/// sibling test in `package_policy_override_tests.rs`). With the canonical
/// map, `package_display_name` (the very last step before the user copy is
/// written) must produce two distinct scoped labels so the review message
/// can say which scope is under review.
///
/// The end-to-end coverage (frozen-lockfile install -> user copy) is part
/// of the fix commit because it requires a full `SupplyChainEvalDeps`.
#[test]
fn package_display_name_round_trips_scope_for_two_scoped_packages_same_unscoped_name() {
    let mut first = Map::new();
    first.insert("name".into(), json!("pi-coding-agent"));
    first.insert("namespace".into(), json!("@oh-my-pi"));
    first.insert("requestedVersion".into(), json!("0.1.0"));
    let mut second = Map::new();
    second.insert("name".into(), json!("pi-coding-agent"));
    second.insert("namespace".into(), json!("@earendil-works"));
    second.insert("requestedVersion".into(), json!("0.1.0"));
    assert_eq!(package_display_name(&first), "@oh-my-pi/pi-coding-agent");
    assert_eq!(
        package_display_name(&second),
        "@earendil-works/pi-coding-agent"
    );
    assert_ne!(
        package_display_name(&first),
        package_display_name(&second),
        "two scopes must produce distinct display names; otherwise the user \
         cannot tell which scoped package is under review"
    );
}
