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

// Review of #7541 (Gitar, Qodo): forms the first version let through.

#[test]
fn a_user_folder_after_a_redirect_at_sign_or_separator_is_hidden() {
    for (command, expected) in [
        ("echo x >/Users/bob/log", "echo x >~/log"),
        ("cmd 2>/home/alice/err", "cmd 2>~/err"),
        ("cat </Users/bob/in", "cat <~/in"),
        (
            "curl -d @/Users/bob/body.json x.test",
            "curl -d @~/body.json x.test",
        ),
        ("tool --paths=/a,/home/carol/b", "tool --paths=/a,~/b"),
        ("a|/home/dave/bin/x", "a|~/bin/x"),
        ("a;/home/dave/x&&/Users/erin/y", "a;~/x&&~/y"),
        (
            "cat file:///Users/alice/.ssh/id_rsa",
            "cat file://~/.ssh/id_rsa",
        ),
        (
            "cc -I/home/omar/include -L/Users/omar/lib",
            "cc -I~/include -L~/lib",
        ),
    ] {
        assert_eq!(
            command_preview(command, None).as_deref(),
            Some(expected),
            "{command}"
        );
    }
    assert_eq!(
        command_preview("cat >/srv/omar/log -I/srv/omar/inc", Some("/srv/omar")).as_deref(),
        Some("cat >~/log -I~/inc")
    );
}

#[test]
fn passwords_in_common_command_line_forms_are_hidden() {
    // Built at run time so secret scanners do not flag the source.
    let user_pass = format!("admin:{}", "hunter2pw");
    let curl_u = format!("curl -u {user_pass} https://x.test");
    let curl_user = format!("curl --user={user_pass} https://x.test");
    for (command, secret) in [
        (curl_u.as_str(), "hunter2pw"),
        (curl_user.as_str(), "hunter2pw"),
        (
            "curl --proxy-user admin:hunter2pw https://x.test",
            "hunter2pw",
        ),
        ("mysql -u root -phunter2pw shop", "hunter2pw"),
        ("mysqldump -h db -phunter2pw shop", "hunter2pw"),
        ("sshpass -p hunter2pw ssh host", "hunter2pw"),
        ("sshpass -phunter2pw ssh host", "hunter2pw"),
        (
            "docker login -u bob -p hunter2pw registry.test",
            "hunter2pw",
        ),
        ("podman login registry.test -p=hunter2pw", "hunter2pw"),
        ("redis-cli -h cache -a hunter2pw ping", "hunter2pw"),
        ("lftp --pass hunter2pw host", "hunter2pw"),
        ("tool --pwd='hunter2 pw' run", "hunter2 pw"),
        ("MYSQL_PWD=hunter2pw mysql shop", "hunter2pw"),
        ("export REDIS_AUTH=\"hunter2pw\"", "hunter2pw"),
        ("curl -H 'X-Session: hunter2pw' https://x.test", "hunter2pw"),
        (
            "curl --header \"Cookie2: sid=hunter2pw\" https://x.test",
            "hunter2pw",
        ),
    ] {
        let out = shown(command);
        assert!(!out.contains(secret), "{command} -> {out}");
        assert!(out.contains("[redacted]"), "{command} -> {out}");
    }
    assert_eq!(
        shown("mysql -u root -phunter2pw shop"),
        "mysql -u root -p[redacted] shop"
    );
    assert_eq!(
        shown("curl -H 'X-Session: hunter2pw' https://x.test"),
        "curl -H 'X-Session: [redacted]' https://x.test"
    );
}

#[test]
fn ordinary_flags_and_headers_are_left_alone() {
    for command in [
        "mkdir -p build/out",
        "git push -u origin main",
        "mysql -u root -p shop",
        "ssh -p 2222 host",
        "curl -H 'Content-Type: application/json' -H 'Accept: */*' https://x.test",
        "ls /data/home/x",
    ] {
        assert_eq!(shown(command), command, "{command}");
    }
}

#[test]
fn a_password_split_by_a_line_continuation_is_still_hidden() {
    let out = shown("curl https://alice:pa\\\nss@example.com/x");
    assert_eq!(out, "curl https://[redacted]@example.com/x");
    let out = shown("curl -u admin:hun\\\r\nter2pw \\\n  https://x.test");
    assert!(!out.contains("hun") && !out.contains("ter2pw"), "{out}");
}
