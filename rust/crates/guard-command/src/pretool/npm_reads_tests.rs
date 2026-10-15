use super::{
    cache_list_arguments, inert_line, list_arguments, npmrc_inert, plain_registry_spec,
    view_arguments,
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
    ] {
        assert!(list_arguments(&arguments(text)), "{text}");
    }
    for text in [
        "-g",
        "--global",
        "--prefix=/tmp",
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
    let oversized = root.join("oversized");
    std::fs::write(&oversized, "a=b\n".repeat(20_000)).unwrap();

    assert!(npmrc_inert(&root.join("absent")));
    assert!(npmrc_inert(&clean));
    assert!(!npmrc_inert(&moved));
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
