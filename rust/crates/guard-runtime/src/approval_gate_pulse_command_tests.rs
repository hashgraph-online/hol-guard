use super::*;

/// A fake GitHub token, built at run time so secret scanners do not flag
/// the source, as in the other Guard tests.
fn fake_token() -> String {
    format!("ghp_{}", "0123456789abcdefghijABCDEFGHIJ012345")
}

fn shown(command: &str) -> String {
    command_preview(command, Some("/Users/omar")).unwrap_or_default()
}

#[test]
fn secrets_are_hidden_and_the_home_folder_becomes_a_tilde() {
    let out = shown(&format!(
        "rm -rf /Users/omar/client-acme/build --token={}",
        fake_token()
    ));
    assert!(out.starts_with("rm -rf ~/client-acme/build"), "{out}");
    assert!(!out.contains("omar"), "{out}");
    assert!(!out.contains("ghp_0123456789"), "{out}");
}

#[test]
fn common_secret_shapes_never_reach_the_phone() {
    let bearer = format!("Bearer {}", "abcdefghijklmnop0123456789");
    let curl = format!("curl -H 'Authorization: {bearer}' https://x.test");
    for (command, secret) in [
        (curl.as_str(), "abcdefghijklmnop0123456789"),
        (
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "wJalrXUtnFEMI",
        ),
        ("mysql --password=hunter2hunter2 -u root", "hunter2hunter2"),
        (
            "git clone https://user:s3cr3tpass@github.com/acme/app.git",
            "s3cr3tpass",
        ),
    ] {
        let out = shown(command);
        assert!(!out.contains(secret), "{command} -> {out}");
    }
    assert_eq!(
        shown("git clone https://user:s3cr3tpass@github.com/acme/app.git"),
        "git clone https://[redacted]@github.com/acme/app.git"
    );
    assert_eq!(
        shown("curl https://example.com/a@b"),
        "curl https://example.com/a@b",
        "an @ after the host is not a credential"
    );
}

#[test]
fn any_user_folder_hides_its_account_name() {
    for (command, expected) in [
        ("cat /home/alice/.ssh/config", "cat ~/.ssh/config"),
        ("ls /Users/bob", "ls ~"),
        (r"dir C:\Users\carol\Documents", r"dir ~\Documents"),
        ("cp a /home/dave/x b /Users/erin/y", "cp a ~/x b ~/y"),
        ("cd '/Users/frank/My Project'", "cd '~/My Project'"),
    ] {
        assert_eq!(
            command_preview(command, None).as_deref(),
            Some(expected),
            "{command}"
        );
    }
}

#[test]
fn only_whole_home_paths_are_replaced() {
    let home = Some("/srv/omar");
    assert_eq!(
        command_preview("ls /srv/omar /srv/omar/a /srv/omar2", home).as_deref(),
        Some("ls ~ ~/a /srv/omar2")
    );
    // A folder that merely contains a user folder's name is not a user folder.
    assert_eq!(
        command_preview("ls /data/home/x", None).as_deref(),
        Some("ls /data/home/x")
    );
    // A home of "/" would replace every path; it is ignored.
    assert_eq!(
        command_preview("ls /etc", Some("/")).as_deref(),
        Some("ls /etc")
    );
}

#[test]
fn the_command_is_one_line_and_cut_after_the_filter() {
    let out = shown("echo one\necho two\t\u{202E}three");
    assert_eq!(out, "echo one echo two three");
    let long = format!("echo {} --token={}", "x".repeat(290), fake_token());
    let out = shown(&long);
    assert!(out.ends_with('…'), "{out}");
    assert!(!out.contains("ghp_"), "{out}");
}

#[test]
fn an_empty_command_shows_nothing() {
    assert_eq!(command_preview("", Some("/Users/omar")), None);
    assert_eq!(command_preview(" \n\t", Some("/Users/omar")), None);
}
