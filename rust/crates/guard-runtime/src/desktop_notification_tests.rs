use super::*;

#[derive(Default)]
struct FakeHost {
    files: Vec<&'static str>,
    succeed: bool,
    system_root: Option<String>,
    runs: Vec<(String, Vec<String>, Duration)>,
}

impl Host for FakeHost {
    fn run(&mut self, program: &str, args: &[&str], timeout: Duration) -> bool {
        self.runs.push((
            program.to_owned(),
            args.iter().map(|arg| (*arg).to_owned()).collect(),
            timeout,
        ));
        self.succeed
    }

    fn is_file(&self, path: &str) -> bool {
        self.files.contains(&path)
    }

    fn token(&mut self) -> String {
        "feed".to_owned()
    }

    fn system_root(&self) -> Option<String> {
        self.system_root.clone()
    }
}

fn notification() -> Notification {
    Notification {
        request_id: "req-1".to_owned(),
        title: "Approve \"rm\"".to_owned(),
        message: r"Path C:\tmp".to_owned(),
        approval_url: "http://127.0.0.1:4781/approvals/req-1".to_owned(),
    }
}

fn send_request(notification: &Notification) -> Request {
    Request::Send {
        schema: SCHEMA.to_owned(),
        notification: Notification {
            request_id: notification.request_id.clone(),
            title: notification.title.clone(),
            message: notification.message.clone(),
            approval_url: notification.approval_url.clone(),
        },
    }
}

fn setup_request(guard_home: &Path, force: bool) -> Request {
    Request::Setup {
        schema: SCHEMA.to_owned(),
        guard_home: guard_home.to_string_lossy().into_owned(),
        approval_url: "http://127.0.0.1:4781/approvals".to_owned(),
        force,
    }
}

#[test]
fn requests_are_validated() {
    for request in [
        json!({ "op": "send", "schema": "desktop-notification.v0", "notification": {
            "request_id": "r", "title": "t", "message": "m", "approval_url": "u" } }),
        json!({ "op": "send", "schema": SCHEMA, "notification": {
            "request_id": "r", "title": "t", "message": "m", "approval_url": "u", "extra": 1 } }),
        json!({ "op": "setup", "schema": SCHEMA, "guard_home": "relative",
            "approval_url": "u", "force": false }),
        json!({ "op": "unknown", "schema": SCHEMA }),
    ] {
        assert_eq!(
            run_command(request.to_string().as_bytes()).expect_err("refused"),
            "desktop_notification_request_invalid",
            "{request}"
        );
    }
    let oversized = vec![b' '; usize::try_from(MAX_REQUEST_BYTES).expect("fits") + 1];
    assert_eq!(
        run_command(oversized.as_slice()).expect_err("refused"),
        "desktop_notification_request_too_large"
    );
}

#[test]
fn macos_prefers_a_trusted_terminal_notifier() {
    let mut host = FakeHost {
        files: vec!["/usr/local/bin/terminal-notifier"],
        succeed: true,
        ..FakeHost::default()
    };
    let answer =
        answer(&send_request(&notification()), Platform::MacOs, &mut host).expect("answer");
    assert_eq!(answer, json!({ "sent": true }));
    let (program, args, timeout) = &host.runs[0];
    assert_eq!(program, "/usr/local/bin/terminal-notifier");
    assert_eq!(
        args,
        &[
            "-title",
            "Approve \"rm\"",
            "-subtitle",
            "Action needs approval",
            "-message",
            r"Path C:\tmp",
            "-open",
            "http://127.0.0.1:4781/approvals/req-1",
            "-group",
            "hol-guard-req-1-feed",
            "-sound",
            "default",
            "-ignoreDnD",
        ]
    );
    assert_eq!(*timeout, MACOS_TIMEOUT);
}

#[test]
fn macos_falls_back_to_osascript_with_escaped_text() {
    let mut host = FakeHost::default();
    let answer =
        answer(&send_request(&notification()), Platform::MacOs, &mut host).expect("answer");
    assert_eq!(answer, json!({ "sent": false }), "a failed run is not sent");
    let (program, args, _) = &host.runs[0];
    assert_eq!(program, OSASCRIPT);
    assert_eq!(
        args,
        &[
            "-e",
            r#"display notification "Path C:\\tmp Open: http://127.0.0.1:4781/approvals/req-1" with title "Approve \"rm\"" subtitle "Action needs approval" sound name "default""#,
        ]
    );
}

#[test]
fn windows_shows_a_toast_through_the_system_powershell() {
    let mut host = FakeHost {
        succeed: true,
        system_root: Some(r"D:\Windows".to_owned()),
        ..FakeHost::default()
    };
    let mut toast = notification();
    toast.title = "Bob&#39;s \u{2019}tool\u{2019} &amp; more".to_owned();
    let answer = answer(&send_request(&toast), Platform::Windows, &mut host).expect("answer");
    assert_eq!(answer, json!({ "sent": true }));
    let (program, args, timeout) = &host.runs[0];
    assert_eq!(
        program,
        r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    );
    assert_eq!(
        &args[..4],
        ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
    );
    assert!(args[4].starts_with("$Title = 'Bob''s ''tool'' & more'\n$Message = 'Path C:\\tmp'\n"));
    assert!(args[4].ends_with("$Notifier.Show($Toast)"));
    assert_eq!(*timeout, WINDOWS_TIMEOUT);
}

#[test]
fn only_a_drive_windows_root_is_trusted() {
    for (root, expected) in [
        (None, r"C:\Windows"),
        (Some(r"D:\Windows"), r"D:\Windows"),
        (Some("e:/WINDOWS/"), r"e:\WINDOWS"),
        (Some(r"C:\Users\alice\Windows"), r"C:\Windows"),
        (Some(r"C:\Windows\.."), r"C:\Windows"),
        (Some(r"\\server\Windows"), r"C:\Windows"),
        (Some("C:Windows"), r"C:\Windows"),
        (Some(r"\C:\Windows"), r"C:\Windows"),
    ] {
        assert_eq!(trusted_windows_root(root), expected, "{root:?}");
    }
}

#[test]
fn other_platforms_show_nothing() {
    let mut host = FakeHost::default();
    let sent = answer(&send_request(&notification()), Platform::Other, &mut host).expect("answer");
    assert_eq!(sent, json!({ "sent": false }));
    assert!(host.runs.is_empty());
    let directory = tempfile::tempdir().expect("tempdir");
    let setup = answer(
        &setup_request(directory.path(), false),
        Platform::Windows,
        &mut host,
    )
    .expect("answer");
    assert_eq!(setup["supported"], false);
    assert!(host.runs.is_empty());
}

#[test]
fn setup_prompts_once_and_records_it() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path().join("guard");
    let mut host = FakeHost {
        files: vec!["/opt/homebrew/bin/terminal-notifier"],
        succeed: true,
        ..FakeHost::default()
    };
    let first = answer(&setup_request(&home, false), Platform::MacOs, &mut host).expect("answer");
    assert_eq!(
        first,
        json!({
            "supported": true,
            "preview_sent": true,
            "settings_opened": true,
            "settings_url": SETTINGS_URL,
            "already_prompted": false,
            "notifier_path": "/opt/homebrew/bin/terminal-notifier",
        })
    );
    assert_eq!(host.runs.len(), 2);
    assert!(host.runs[0]
        .1
        .contains(&"hol-guard-notification-setup-feed-feed".to_owned()));
    assert_eq!(host.runs[1].0, OPEN);
    assert_eq!(host.runs[1].1, [SETTINGS_URL]);
    let state: Value = serde_json::from_str(
        &fs::read_to_string(home.join(SETUP_STATE_FILE)).expect("state written"),
    )
    .expect("state is JSON");
    assert_eq!(state["settings_opened"], true);
    assert!(state["opened_at"]
        .as_str()
        .is_some_and(|at| at.ends_with("+00:00")));

    let second = answer(&setup_request(&home, false), Platform::MacOs, &mut host).expect("answer");
    assert_eq!(second["already_prompted"], true);
    assert_eq!(second["preview_sent"], false);
    assert_eq!(host.runs.len(), 2, "a recorded prompt is not repeated");

    let forced = answer(&setup_request(&home, true), Platform::MacOs, &mut host).expect("answer");
    assert_eq!(forced["already_prompted"], true);
    assert_eq!(forced["settings_opened"], true);
    assert_eq!(host.runs.len(), 4);
}

#[test]
fn setup_that_could_not_open_settings_records_nothing() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut host = FakeHost::default();
    let answer = answer(
        &setup_request(directory.path(), false),
        Platform::MacOs,
        &mut host,
    )
    .expect("answer");
    assert_eq!(answer["settings_opened"], false);
    assert_eq!(answer["notifier_path"], Value::Null);
    assert!(!directory.path().join(SETUP_STATE_FILE).exists());
}
