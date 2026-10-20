use super::{
    cache_list_arguments, global_configuration_inert, inert_line, list_arguments, npmrc_inert,
    plain_registry_spec, view_arguments,
};

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn view_takes_one_registry_spec_and_field_paths() {
    for text in [
        "zod",
        "zod version",
        "zod@latest dist-tags.latest",
        "zod@^3 versions --json",
        "--json @types/node versions",
        "react peerDependencies dependencies[scheduler]",
    ] {
        assert!(view_arguments(&arguments(text)), "{text}");
    }
    for text in [
        "",
        "--json",
        "zod --registry=https://registry.example.test",
        "zod --userconfig=/tmp/npmrc",
        "zod -g",
        "user/repo",
        "zod@npm:other",
        "file:../local",
        "./local",
        "https://example.test/pkg.tgz",
        "git+ssh://example.test/repo.git",
        "Zod",
    ] {
        assert!(!view_arguments(&arguments(text)), "{text}");
    }
}

#[test]
fn list_takes_display_flags_and_package_names() {
    for text in [
        "",
        "zod",
        "--depth=0",
        "--all --json",
        "-p -l",
        "--omit=dev zod",
        "-g",
        "--global",
        "--location=global",
        "-g --depth=0",
    ] {
        assert!(list_arguments(&arguments(text)), "{text}");
    }
    for text in [
        "--prefix=/tmp",
        "--location=/tmp/elsewhere",
        "--depth=999",
        "--omit=everything",
        "../outside",
    ] {
        assert!(!list_arguments(&arguments(text)), "{text}");
    }
}

#[test]
fn cache_takes_only_ls_with_package_names() {
    for text in ["ls", "ls zod", "ls zod@3.23.8 @types/node"] {
        assert!(cache_list_arguments(&arguments(text)), "{text}");
    }
    for text in [
        "",
        "add zod",
        "clean --force",
        "clean",
        "verify",
        "npx ls",
        "ls --cache /tmp/x",
        "ls --cache=/tmp/x",
        "ls --registry=https://registry.example.test/",
        "ls --prefix=/tmp",
        "ls --userconfig=/tmp/npmrc",
        "ls --globalconfig=/tmp/npmrc",
        "ls -C /tmp",
        "ls ./local",
    ] {
        assert!(!cache_list_arguments(&arguments(text)), "{text}");
    }
}

#[test]
fn scoped_specs_need_both_parts() {
    assert!(plain_registry_spec("@scope/pkg@1.2.3"));
    assert!(!plain_registry_spec("@scope"));
    assert!(!plain_registry_spec("@scope/"));
    assert!(!plain_registry_spec("pkg@"));
}

#[test]
fn npmrc_lines_that_move_the_fetch_or_send_credentials_are_unsafe() {
    for line in [
        "",
        "; comment",
        "# registry=https://registry.example.test/",
        "save-exact=true",
        "engine-strict = true",
        "legacy-peer-deps=true",
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN}",
        "\u{feff}save-exact=true",
        "' \"save-exact\" '=true",
    ] {
        assert!(inert_line(line), "{line}");
    }
    for line in [
        "registry=https://registry.example.test/",
        " Registry = https://registry.example.test/",
        "\"registry\"=https://registry.example.test/",
        "@evil:registry=https://registry.example.test/",
        "https-proxy=http://proxy.example.test",
        "https_proxy=http://proxy.example.test",
        "strict-ssl=false",
        "cafile=/tmp/ca.pem",
        "userconfig=/tmp/other",
        "globalconfig=/tmp/other",
        "cache=/tmp/cache",
        "logs-dir=/tmp/logs",
        "_authToken=${GITHUB_TOKEN}",
        "_auth=${GITHUB_TOKEN}",
        "always-auth=true",
        "ca[]=-----BEGIN CERTIFICATE-----",
        "[section]",
        "${X?}registry=https://registry.example.test/",
        "user${X?}config=/tmp/other",
        "\u{feff}registry=https://registry.example.test/",
        "\u{feff}\"registry\"=https://registry.example.test/",
        "' \"registry\" '=https://registry.example.test/",
        "' [\"registry\"] '=https://registry.example.test/",
    ] {
        assert!(!inert_line(line), "{line}");
    }
}

#[test]
fn npmrc_lines_are_screened_as_npm_decodes_them() {
    for line in [
        "\"save-exact\"=true",
        "'save-exact'=true",
        "save-exact=true ; registry=https://registry.example.test/",
        "\"registry=https://registry.example.test/",
    ] {
        assert!(inert_line(line), "{line}");
    }
    for line in [
        "\"\\u0072egistry\"=https://registry.example.test/",
        "\"regist\\u0072y\"=https://registry.example.test/",
        "'registry'=https://registry.example.test/",
        "registry;ignored=https://registry.example.test/",
        "registry#ignored=https://registry.example.test/",
        "\"\\u0063afile\"=/tmp/ca.pem",
    ] {
        assert!(!inert_line(line), "{line}");
    }
}

#[test]
fn npmrc_files_are_inert_only_when_absent_or_regular_and_clean() {
    let root = std::env::temp_dir().join(format!("guard-npmrc-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let clean = root.join("clean");
    std::fs::write(&clean, "save-exact=true\n").unwrap();
    let moved = root.join("moved");
    std::fs::write(&moved, "registry=https://registry.example.test/\n").unwrap();
    let directory = root.join("directory");
    std::fs::create_dir_all(&directory).unwrap();
    let carriage_return = root.join("carriage-return");
    std::fs::write(
        &carriage_return,
        "save-exact=true\rregistry=https://registry.example.test/\n",
    )
    .unwrap();
    let oversized = root.join("oversized");
    std::fs::write(&oversized, "a=b\n".repeat(20_000)).unwrap();

    let stray = root.join("stray");
    std::fs::write(&stray, "not a directory\n").unwrap();

    assert!(npmrc_inert(&root.join("absent")));
    assert!(npmrc_inert(&stray.join("etc/npmrc")));
    assert!(npmrc_inert(&clean));
    assert!(!npmrc_inert(&moved));
    assert!(!npmrc_inert(&carriage_return));
    assert!(!npmrc_inert(&directory));
    assert!(!npmrc_inert(&oversized));
    #[cfg(unix)]
    {
        let linked = root.join("linked");
        std::os::unix::fs::symlink(&clean, &linked).unwrap();
        assert!(!npmrc_inert(&linked));
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// macOS leaves a `.DS_Store` file beside the version directories a Node
/// version manager keeps. Reading a configuration path below that file fails
/// with `ENOTDIR`, which is as absent as a missing file, so the stray entry
/// must not send an ordinary `npm ls` to review.
#[test]
fn a_version_root_with_a_stray_file_reads_like_one_without_it() {
    let root = std::env::temp_dir().join(format!("guard-npm-versions-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let bare = root.join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    let stray = root.join("stray");
    let versions = stray.join(".nvm/versions/node");
    std::fs::create_dir_all(versions.join("v22.1.0/etc")).unwrap();
    std::fs::write(versions.join("v22.1.0/etc/npmrc"), "save-exact=true\n").unwrap();
    std::fs::write(versions.join(".DS_Store"), "\x00\x01").unwrap();

    // The stray entry has to read as an absent configuration on its own.
    // Comparing the two homes alone proves nothing on a host that keeps a
    // live `<prefix>/etc/npmrc`, since both homes are then not inert whether
    // or not `ENOTDIR` is handled.
    assert!(npmrc_inert(&versions.join(".DS_Store").join("etc/npmrc")));
    assert_eq!(
        global_configuration_inert(&stray),
        global_configuration_inert(&bare)
    );
    let _ = std::fs::remove_dir_all(&root);
}
