//! Vectors captured from the retired `runtime/git_execution_safety.py`.

use crate::git_execution_safety_config::*;

fn config(entries: &[(&str, &[&str])]) -> GitConfig {
    entries
        .iter()
        .map(|(key, values)| {
            (
                (*key).to_owned(),
                values.iter().map(|value| (*value).to_owned()).collect(),
            )
        })
        .collect()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn remote_urls_match_the_retired_python_vectors() {
    for (url, expected) in [
        ("https://github.com/example/project.git", true),
        ("https://github.com/example/project", true),
        ("HTTPS://GitHub.com/example/project.git", true),
        ("https://github.com:443/example/project", true),
        ("https://github.com:8443/example/project", false),
        ("http://github.com/example/project", false),
        ("https://github.com/example/project?x=1", false),
        ("https://github.com/example/project#f", false),
        ("https://github.com/example/../project", false),
        ("https://github.com/example/.git", false),
        ("https://github.com/example/project/extra", false),
        ("https://example.com/example/project", false),
        ("https://github.com.evil.com/example/project", false),
        ("git@github.com:example/project.git", false),
        ("https://github.com/a b/project", false),
        ("https://github.com/example/pro$ject", false),
        ("https://github.com//project", false),
        ("ext::sh -c payload", false),
        (
            "https://account:credential@github.com/example/project.git",
            true,
        ),
        ("https://github.com@evil.com/example/project", false),
        ("https://evil.com@github.com:8443/example/project", false),
    ] {
        assert_eq!(safe_github_https_remote_url(url), expected, "{url}");
    }
}

#[test]
fn status_arguments_match_the_retired_python_vectors() {
    for (arguments, expected) in [
        (&["status"][..], true),
        (&["status", "--short", "--branch"], true),
        (&["status", "-sb"], true),
        (&["status", "-uno"], false),
        (&["status", "--untracked-files=no"], true),
        (&["status", "--porcelain=v2"], true),
        (&["status", "--ignored=matching"], true),
        (&["status", "--ext-diff"], false),
        (&["status", "--", "--anything"], true),
        (&["status", "-c", "x"], false),
        (&["STATUS", "-S"], true),
        (&["diff"], false),
        (&[], false),
        (&["status", "--column=always"], true),
        (&["status", "--find-renames=50"], true),
        (&["status", "--no-renames", "-z"], true),
        (&["status", "-sbz"], true),
        (&["status", "-s=1"], false),
        (&["status", "-ss"], true),
        (&["status", "--branch=x"], false),
    ] {
        assert_eq!(
            status_arguments_are_read_only(&strings(arguments)),
            expected,
            "{arguments:?}"
        );
    }
}

#[test]
fn fetch_configuration_matches_the_retired_python_vectors() {
    for (entries, routes) in [
        (config(&[("remote.origin.uploadpack", &["x"])]), true),
        (config(&[("core.sshcommand", &["ssh -i k"])]), true),
        (config(&[("core.sshcommand", &[" "])]), false),
        (
            config(&[("url.https://github.com/.insteadof", &["git@github.com:"])]),
            false,
        ),
        (
            config(&[("url.https://github.com/.insteadof", &["git@gitlab.com:"])]),
            true,
        ),
        (
            config(&[("url.ext::payload.insteadof", &["https://github.com/"])]),
            true,
        ),
        (
            config(&[(
                "remote.origin.fetch",
                &["+refs/heads/*:refs/remotes/origin/*"],
            )]),
            false,
        ),
        (
            config(&[(
                "remote.origin.fetch",
                &["+refs/heads/main:refs/remotes/origin/main"],
            )]),
            true,
        ),
        (config(&[("fetch.prune", &["true"])]), true),
        (config(&[("fetch.prune", &["false"])]), false),
        (config(&[("submodule.recurse", &["on-demand"])]), true),
        (config(&[("remote.origin.tagopt", &["--no-tags"])]), false),
        (config(&[("remote.origin.tagopt", &["--tags"])]), true),
        (config(&[("remote.origin.mirror", &["0"])]), false),
        (config(&[]), false),
    ] {
        assert_eq!(
            fetch_config_routes_execution(&entries),
            routes,
            "{entries:?}"
        );
    }
}

#[test]
fn push_and_checkout_configuration_match_the_retired_python_vectors() {
    for (entries, branch, routes) in [
        (config(&[("core.gitproxy", &["x"])]), "main", true),
        (config(&[("url.x.pushinsteadof", &["y"])]), "main", true),
        (config(&[("hook.a.command", &["x"])]), "main", true),
        (config(&[("remote.origin.push", &["x"])]), "main", true),
        (
            config(&[("branch.main.pushremote", &["fork"])]),
            "main",
            true,
        ),
        (
            config(&[("branch.main.pushremote", &["fork"])]),
            "Main",
            true,
        ),
        (config(&[("push.followtags", &["true"])]), "main", true),
        (
            config(&[("push.recursesubmodules", &["check"])]),
            "main",
            false,
        ),
        (
            config(&[("push.recursesubmodules", &["on-demand"])]),
            "main",
            true,
        ),
        (config(&[("push.gpgsign", &["if-asked"])]), "main", true),
        (config(&[("push.gpgsign", &["false"])]), "main", false),
        (config(&[]), "main", false),
    ] {
        assert_eq!(
            push_config_routes_execution(&entries, branch),
            routes,
            "{entries:?}"
        );
    }
    for (key, scoped, weakens) in [
        ("http.proxy", true, true),
        ("credential.helper", true, false),
        ("core.askpass", true, false),
        ("core.sshcommand", false, false),
        ("user.name", false, false),
        ("remote.origin.proxy", true, false),
        ("http.sslverify", true, true),
        ("http.https://github.com/.extraheader", true, true),
        ("http.postbuffer", true, false),
        ("core.x.proxy", false, false),
    ] {
        let entries = config(&[(key, &["x"])]);
        assert_eq!(
            push_scoped_config_routes_transport(&entries),
            scoped,
            "{key}"
        );
        assert_eq!(
            push_effective_config_weakens_transport(&entries),
            weakens,
            "{key}"
        );
    }
    for (key, value, fetches) in [
        ("extensions.partialclone", "origin", true),
        ("extensions.partialclone", "", false),
        ("remote.origin.promisor", "true", true),
        ("remote.origin.promisor", "false", false),
        ("remote.origin.partialclonefilter", "blob:none", true),
        ("remote.origin.partialclonefilter", "", false),
        ("core.x", "1", false),
    ] {
        assert_eq!(
            checkout_config_can_fetch(&config(&[(key, &[value])])),
            fetches,
            "{key}"
        );
    }
}

#[test]
fn null_config_parsing_matches_the_retired_python_vectors() {
    assert_eq!(
        parse_null_config("a\nb\0c\nd\0"),
        Some(config(&[("a", &["b"]), ("c", &["d"])]))
    );
    assert_eq!(parse_null_config("\0"), Some(config(&[])));
    assert_eq!(parse_null_config("a\n\0"), Some(config(&[("a", &[""])])));
    assert_eq!(parse_null_config("\nb\0"), None);
    assert_eq!(parse_null_config("a\0"), None);
    assert_eq!(
        parse_null_config("Remote.Origin.URL\nhttps://x\0remote.origin.url\nhttps://y\0"),
        Some(config(&[(
            "remote.origin.url",
            &["https://x", "https://y"]
        )]))
    );
}

#[test]
fn credential_helper_shapes_are_narrow() {
    for (value, safe) in [
        ("!gh auth git-credential", true),
        ("!/usr/bin/gh auth git-credential", true),
        ("!gh auth git-credential --x", false),
        ("!sh auth git-credential", false),
        ("osxkeychain", true),
        ("store", true),
        ("cache --timeout=1", false),
        ("-bad", false),
        ("!gh auth git-credential; id", false),
        ("!\"gh\" auth git-credential", false),
    ] {
        assert_eq!(credential_helper_shape(value).is_some(), safe, "{value}");
    }
}

#[test]
fn environment_gates_match_the_retired_python_vectors() {
    let environment = |pairs: &[(&str, &str)]| -> Environment {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    };
    assert!(routing_environment_is_clean(&environment(&[(
        "HOME", "/h"
    )])));
    // Whitespace-only routing values still name a path for Git, so they are
    // not clean; only an empty value is treated as unset.
    assert!(!routing_environment_is_clean(&environment(&[(
        "GIT_DIR", "  "
    )])));
    assert!(routing_environment_is_clean(&environment(&[(
        "GIT_DIR", ""
    )])));
    assert!(!routing_environment_is_clean(&environment(&[(
        "GIT_DIR", "."
    )])));
    assert!(!fetch_environment_is_set(&environment(&[("GIT_SSH", " ")])));
    assert!(fetch_environment_is_set(&environment(&[(
        "GIT_SSH_COMMAND",
        "x"
    )])));
    // Checkout variables are compared without stripping.
    assert!(checkout_environment_is_set(&environment(&[(
        "GIT_OBJECT_DIRECTORY",
        " "
    )])));
    assert!(!checkout_environment_is_set(&environment(&[(
        "GIT_OBJECT_DIRECTORY",
        ""
    )])));
    assert!(checkout_environment_is_set(&environment(&[(
        "GIT_EXEC_PATH",
        "helpers"
    )])));
}
