use super::*;

fn config(entries: &[(&str, &str)]) -> GitConfig {
    let mut output = Vec::new();
    for (key, value) in entries {
        output.extend_from_slice(format!("global\0{key}\n{value}\0").as_bytes());
    }
    parse_scoped(&output).expect("parsed").0
}

#[test]
fn scoped_parse_separates_repository_settings() {
    let (effective, repository) = parse_scoped(
        b"system\0credential.helper\nosxkeychain\0local\0Remote.Origin.URL\nhttps://github.com/example-org/app-portal.git\0worktree\0core.hooksPath\n/tmp/h\0",
    )
    .expect("parsed");
    assert_eq!(effective.len(), 3);
    assert!(repository.contains_key("remote.origin.url"));
    assert!(repository.contains_key("core.hookspath"));
    assert!(!repository.contains_key("credential.helper"));
    assert!(parse_scoped(b"local\0no-newline\0").is_none());
}

#[test]
fn only_plain_github_https_urls_are_safe() {
    for url in [
        "https://github.com/example-org/app-portal.git",
        "https://github.com/example-org/app-portal",
        "HTTPS://GitHub.com:443/example-org/app.portal",
    ] {
        assert!(safe_github_https_remote_url(url), "{url}");
    }
    for url in [
        "git@github.com:example-org/app-portal.git",
        "ssh://git@github.com/example-org/app-portal.git",
        "http://github.com/example-org/app-portal.git",
        "https://token@github.com/example-org/app-portal.git",
        "https://user:pw@github.com/example-org/app-portal.git",
        "https://github.com.evil.example/example-org/app-portal.git",
        "https://evil.example/github.com/app-portal.git",
        "https://github.com:8443/example-org/app-portal.git",
        "https://github.com/example-org/app-portal.git?x=1",
        "https://github.com/example-org/../app-portal.git",
        "https://github.com/example-org/app-portal/extra",
        "https://github.com/example-org",
        "ext::sh -c id",
        "https://github.com/example-org/app portal",
        "file:///tmp/repo",
    ] {
        assert!(!safe_github_https_remote_url(url), "{url}");
    }
}

#[test]
fn fetch_routes_reject_programs_rewrites_and_refspecs() {
    let base = [
        (
            "remote.origin.url",
            "https://github.com/example-org/app-portal.git",
        ),
        ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
    ];
    assert!(!fetch_config_routes_execution(&config(&base)));
    assert!(!fetch_config_routes_execution(&config(&[
        base[0],
        ("url.https://github.com/.insteadof", "git@github.com:"),
    ])));
    for extra in [
        ("remote.origin.uploadpack", "sh -c id"),
        ("core.sshcommand", "ssh -o ProxyCommand=id"),
        ("core.askpass", "/tmp/askpass"),
        ("url.git@github.com:.insteadof", "https://github.com/"),
        ("url.ssh://evil.example/.insteadof", "https://github.com/"),
        ("url.https://github.com/.insteadof", "https://evil.example/"),
        ("remote.origin.fetch", "+refs/*:refs/*"),
        ("remote.origin.fetch", "refs/heads/main:refs/heads/main"),
        ("remote.origin.mirror", "true"),
        ("fetch.recursesubmodules", "yes"),
        ("remote.origin.tagopt", "--tags"),
        ("remote.origin.vcs", "evil"),
        ("fetch.bundleuri", "https://evil.example/b.bundle"),
        ("transfer.bundleuri", "true"),
        ("core.alternaterefscommand", "sh -c id"),
    ] {
        assert!(
            fetch_config_routes_execution(&config(&[base[0], extra])),
            "{extra:?}"
        );
    }
}

#[test]
fn transport_weakening_settings_are_detected() {
    assert!(config_weakens_transport(&config(&[(
        "http.sslverify",
        "false"
    )])));
    assert!(config_weakens_transport(&config(&[(
        "http.https://github.com/.extraheader",
        "Authorization: x"
    )])));
    assert!(repository_config_routes_transport(&config(&[(
        "credential.helper",
        "!sh -c id"
    )])));
    assert!(repository_config_routes_transport(&config(&[(
        "core.hookspath",
        "/tmp/hooks"
    )])));
}

#[test]
fn credential_helper_shapes_are_narrow() {
    assert!(matches!(
        credential_helper_shape("osxkeychain"),
        Some(HelperShape::Named("osxkeychain"))
    ));
    assert!(matches!(
        credential_helper_shape("!gh auth git-credential"),
        Some(HelperShape::GithubCli("gh"))
    ));
    assert!(matches!(
        credential_helper_shape("!/opt/homebrew/bin/gh auth git-credential"),
        Some(HelperShape::GithubCli(_))
    ));
    for helper in [
        "!sh -c id",
        "!gh auth git-credential; id",
        "!/tmp/evil auth git-credential",
        "!gh auth token",
        "/tmp/helper",
        "store --file=/tmp/x",
        "-evil",
        "",
    ] {
        assert!(credential_helper_shape(helper).is_none(), "{helper}");
    }
    assert_eq!(
        credential_helpers(&config(&[
            ("credential.helper", ""),
            ("credential.helper", "osxkeychain"),
            (
                "credential.https://github.com.helper",
                "!gh auth git-credential"
            ),
        ])),
        vec!["osxkeychain", "!gh auth git-credential"]
    );
}
