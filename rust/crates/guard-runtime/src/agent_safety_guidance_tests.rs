use std::fs;
use std::path::PathBuf;

use super::*;

struct Home {
    _root: tempfile::TempDir,
    path: PathBuf,
}

impl Home {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("home");
        Self { _root: root, path }
    }

    fn agents(&self) -> PathBuf {
        self.path.join(AGENTS_DIRECTORY).join(AGENTS_NAME)
    }

    fn safety(&self) -> PathBuf {
        self.path.join(SAFETY_DIRECTORY).join(SAFETY_NAME)
    }

    fn write_agents(&self, text: &str) {
        let path = self.agents();
        fs::create_dir_all(path.parent().expect("parent")).expect("agents directory");
        fs::write(path, text).expect("agents written");
    }

    fn read_agents(&self) -> String {
        fs::read_to_string(self.agents()).expect("agents read")
    }

    fn ask(&self, op: &str) -> Value {
        let request = json!({
            "schema": SCHEMA,
            "op": op,
            "home_dir": self.path.to_string_lossy(),
        });
        let bytes = run_command(request.to_string().as_bytes()).expect("answered");
        serde_json::from_slice(&bytes).expect("answer is JSON")
    }

    fn failure(&self, op: &str) -> String {
        self.ask(op)["failure"].as_str().expect("failed").to_owned()
    }
}

fn installed(changed: bool) -> Value {
    json!({
        "status": "installed",
        "changed": changed,
        "agents_path": "~/.codex/AGENTS.md",
        "safety_path": "~/.hol-support/SAFETY.md",
    })
}

#[test]
fn install_keeps_user_content_and_is_idempotent() {
    let home = Home::new();
    home.write_agents("# My instructions\n\n- Preserve this rule.\n");

    assert_eq!(home.ask("install"), installed(true));
    let agents = home.read_agents();
    assert_eq!(
        agents,
        format!("# My instructions\n\n- Preserve this rule.\n\n{MANAGED_BLOCK}")
    );
    let safety = fs::read_to_string(home.safety()).expect("safety read");
    assert_eq!(safety, SAFETY_GUIDANCE);
    assert!(safety.contains("Use one semantic action per tool call."));
    assert!(safety.contains("Never approve, deny, or resolve your own Guard approval requests."));
    assert!(!safety.contains("unless the user explicitly authorizes"));

    assert_eq!(home.ask("install"), installed(false));
    assert_eq!(home.read_agents(), agents);
}

#[cfg(unix)]
#[test]
fn install_keeps_the_mode_of_a_file_it_replaces() {
    use std::os::unix::fs::PermissionsExt;

    let home = Home::new();
    home.write_agents("# Mine\n");
    fs::set_permissions(home.agents(), fs::Permissions::from_mode(0o600)).expect("chmod");

    assert_eq!(home.ask("install"), installed(true));
    let agents_mode = fs::metadata(home.agents())
        .expect("agents")
        .permissions()
        .mode();
    let safety_mode = fs::metadata(home.safety())
        .expect("safety")
        .permissions()
        .mode();
    assert_eq!(agents_mode & 0o777, 0o600);
    assert_eq!(safety_mode & 0o777, DEFAULT_MODE);
}

#[test]
fn install_replaces_only_the_managed_block() {
    let home = Home::new();
    home.write_agents(&format!(
        "User rule.\n\n{MANAGED_BEGIN}\nstale pointer\n{MANAGED_END}\n\nFinal user rule.\n"
    ));

    assert_eq!(home.ask("install"), installed(true));
    assert_eq!(
        home.read_agents(),
        format!("User rule.\n\n{MANAGED_BLOCK}\nFinal user rule.\n")
    );
}

#[test]
fn install_refuses_an_unmanaged_safety_document() {
    let home = Home::new();
    let safety = home.safety();
    fs::create_dir_all(safety.parent().expect("parent")).expect("safety directory");
    fs::write(&safety, "# Team safety\n\nKeep this rule.\n").expect("safety written");

    assert_eq!(
        home.failure("install"),
        "Guard could not install agent safety guidance (agents_changed=false, safety_changed=false): Guard refused to trust an unmanaged SAFETY.md file"
    );
    assert_eq!(
        fs::read_to_string(safety).expect("safety read"),
        "# Team safety\n\nKeep this rule.\n"
    );
    assert!(!home.agents().exists());
}

#[test]
fn install_refuses_incomplete_and_malformed_markers() {
    for original in [
        format!("{MANAGED_BEGIN}\nuser-edited text\n"),
        format!("{MANAGED_END}\nuser\n{MANAGED_BEGIN}\n"),
        format!("  {MANAGED_BEGIN}\nuser\n  {MANAGED_END}\n"),
        format!("{MANAGED_BLOCK}{MANAGED_BLOCK}"),
    ] {
        let home = Home::new();
        home.write_agents(&original);
        assert!(
            home.failure("install")
                .ends_with("Guard found an incomplete managed safety guidance block"),
            "{original}"
        );
        assert_eq!(home.read_agents(), original);
        assert!(!home.safety().exists());
    }
}

#[test]
fn install_refuses_a_support_file_that_is_not_utf8() {
    let home = Home::new();
    home.write_agents("");
    fs::write(home.agents(), b"\xff\xfe").expect("agents written");

    assert!(home
        .failure("install")
        .ends_with("Guard refused a support file that is not UTF-8: AGENTS.md"));
}

#[cfg(unix)]
#[test]
fn install_refuses_a_linked_agents_file() {
    let home = Home::new();
    let target = home.path.with_file_name("protected.md");
    fs::write(&target, "do not change\n").expect("target written");
    fs::create_dir_all(home.agents().parent().expect("parent")).expect("agents directory");
    std::os::unix::fs::symlink(&target, home.agents()).expect("link");

    assert!(home
        .failure("install")
        .ends_with("Guard refused to replace a non-regular support file: AGENTS.md"));
    assert_eq!(
        fs::read_to_string(target).expect("target read"),
        "do not change\n"
    );
    assert!(!home.safety().exists());
}

#[cfg(unix)]
#[test]
fn install_refuses_a_linked_support_directory() {
    let home = Home::new();
    let protected = home.path.with_file_name("protected");
    fs::create_dir_all(&protected).expect("protected directory");
    fs::create_dir_all(&home.path).expect("home");
    std::os::unix::fs::symlink(&protected, home.path.join(SAFETY_DIRECTORY)).expect("link");

    assert!(home
        .failure("install")
        .ends_with("Guard refused to use a non-directory support path: .hol-support"));
    assert!(!protected.join(SAFETY_NAME).exists());
}

#[test]
fn install_leaves_an_agents_file_edited_while_it_was_written() {
    let home = Home::new();
    home.write_agents("original\n");
    let agents = home.agents();
    let mut progress = Progress::default();

    let error = install(&home.path, &mut progress, &mut |name| {
        if name == AGENTS_NAME {
            fs::write(&agents, "concurrent\n").expect("concurrent edit");
        }
    })
    .expect_err("refused");

    assert_eq!(error, "Guard support file changed during update: AGENTS.md");
    assert!(!progress.agents_changed);
    assert!(progress.safety_changed);
    assert_eq!(
        answer("install", "installed", &progress, Err(error))["failure"],
        "Guard could not install agent safety guidance (agents_changed=false, safety_changed=true): Guard support file changed during update: AGENTS.md"
    );
    assert_eq!(home.read_agents(), "concurrent\n");
    assert_eq!(
        fs::read_to_string(home.safety()).expect("safety read"),
        SAFETY_GUIDANCE
    );
    let leftovers = fs::read_dir(agents.parent().expect("parent"))
        .expect("listing")
        .count();
    assert_eq!(leftovers, 1, "the temporary file is removed");
}

#[test]
fn install_migrates_each_known_earlier_safety_document() {
    let previous = include_str!("../../../../tests/fixtures/agent-safety-guidance-previous.md");
    let prefix = "<!-- HOL GUARD MANAGED SAFETY DOCUMENT v2 -->\n";
    let legacy = [
        previous.to_owned(),
        format!("{prefix}{previous}"),
        format!(
            "{prefix}{}",
            include_str!("../../../../tests/fixtures/agent-safety-guidance-secret-carveout.md")
        ),
        format!(
            "{prefix}{}",
            include_str!(
                "../../../../tests/fixtures/agent-safety-guidance-before-script-free-installs.md"
            )
        ),
        format!(
            "{prefix}{}",
            include_str!(
                "../../../../tests/fixtures/agent-safety-guidance-before-connector-setup.md"
            )
        ),
    ];
    for text in legacy {
        let home = Home::new();
        assert_eq!(home.ask("install"), installed(true));
        fs::write(home.safety(), text).expect("legacy written");

        assert_eq!(home.ask("install"), installed(true));
        assert_eq!(
            fs::read_to_string(home.safety()).expect("safety read"),
            SAFETY_GUIDANCE
        );
    }
    assert!(!is_known_safety_guidance(&format!("{SAFETY_GUIDANCE}\n")));
}

#[test]
fn uninstall_keeps_user_bytes_around_the_managed_block() {
    for original in [
        "# User agents\n",
        "Before  \n\nAfter\t\n\n",
        "alpha\r\nbeta\r\n",
    ] {
        let home = Home::new();
        home.write_agents(original);
        assert_eq!(home.ask("install"), installed(true));

        let answer = home.ask("uninstall");

        assert_eq!(answer["status"], "removed");
        assert_eq!(answer["changed"], true);
        assert_eq!(
            fs::read(home.agents()).expect("agents read"),
            original.as_bytes()
        );
        assert!(!home.safety().exists());
    }
}

#[test]
fn uninstall_removes_files_only_guard_wrote() {
    let home = Home::new();
    assert_eq!(home.ask("install"), installed(true));

    assert_eq!(home.ask("uninstall")["changed"], true);
    assert!(!home.agents().exists());
    assert!(!home.safety().exists());
    assert!(home.agents().parent().expect("parent").is_dir());

    assert_eq!(home.ask("uninstall")["changed"], false);
}

#[test]
fn uninstall_without_support_directories_changes_nothing() {
    let home = Home::new();

    assert_eq!(home.ask("uninstall")["changed"], false);
    assert!(!home.path.exists());
}

#[test]
fn uninstall_refuses_an_unmanaged_safety_document() {
    let home = Home::new();
    let safety = home.safety();
    fs::create_dir_all(safety.parent().expect("parent")).expect("safety directory");
    fs::write(&safety, "unmanaged\n").expect("safety written");

    assert_eq!(
        home.failure("uninstall"),
        "Guard could not remove agent safety guidance (agents_changed=false, safety_changed=false): Guard refused to remove an unmanaged SAFETY.md file"
    );
    assert!(safety.is_file());
}

#[cfg(unix)]
#[test]
fn uninstall_names_the_files_it_changed_before_a_failure() {
    use std::os::unix::fs::PermissionsExt;

    if nix::unistd::geteuid().is_root() {
        return;
    }
    let home = Home::new();
    assert_eq!(home.ask("install"), installed(true));
    let safety_directory = home.path.join(SAFETY_DIRECTORY);
    fs::set_permissions(&safety_directory, fs::Permissions::from_mode(0o500)).expect("chmod");

    let failure = home.failure("uninstall");

    fs::set_permissions(safety_directory, fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(
        failure.starts_with(
            "Guard could not remove agent safety guidance (agents_changed=true, safety_changed=false): "
        ),
        "{failure}"
    );
    assert!(failure.ends_with(": SAFETY.md"), "{failure}");
    assert!(!home.agents().exists());
    assert!(home.safety().is_file());
}

#[test]
fn managed_blocks_match_whole_lines_only() {
    let text = format!("x{MANAGED_BEGIN}\nuser\n{MANAGED_END}\n");
    assert!(managed_blocks(&text).is_empty());

    let text = format!("{MANAGED_BEGIN}\nuser {MANAGED_END}\n{MANAGED_END}");
    assert_eq!(managed_blocks(&text), [(0, text.len())]);
}

#[test]
fn requests_are_validated() {
    for request in [
        json!({ "schema": "agent-safety-guidance.v0", "op": "install", "home_dir": "/home" }),
        json!({ "schema": SCHEMA, "op": "reinstall", "home_dir": "/home" }),
        json!({ "schema": SCHEMA, "op": "install", "home_dir": "relative" }),
        json!({ "schema": SCHEMA, "op": "install", "home_dir": "/home", "extra": true }),
        json!({ "schema": SCHEMA, "op": "install" }),
    ] {
        assert_eq!(
            run_command(request.to_string().as_bytes()).expect_err("refused"),
            "agent_safety_guidance_request_invalid"
        );
    }
    let oversized = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(oversized.as_slice()).expect_err("refused"),
        "agent_safety_guidance_request_too_large"
    );
}
