use super::super::safe_reads::bounded_omp_directory_read_target;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture_root() -> std::path::PathBuf {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "guard-directory-read-{}-{nonce}",
            std::process::id()
        ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn read_directory(
    harness: &str,
    target: &str,
    home: &std::path::Path,
    cwd: &std::path::Path,
) -> guard_contracts::PreToolResultV1 {
    super::super::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": target},
        }),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

#[test]
fn omp_directory_reads_allow_verified_ordinary_directories() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let sibling = home.join("sibling-project");
    let nested_sibling = sibling.join("src");
    let ordinary_home = home.join("other-ordinary-project");
    let ordinary_outside_workspace = root.join("ordinary-outside-workspace");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&nested_sibling).unwrap();
    std::fs::create_dir_all(&ordinary_home).unwrap();
    std::fs::create_dir_all(&ordinary_outside_workspace).unwrap();

    for target in [
        &project,
        &sibling,
        &nested_sibling,
        &ordinary_home,
        &home,
        &ordinary_outside_workspace,
    ] {
        let target = target.to_string_lossy().into_owned();
        let decision = read_directory("omp", &target, &home, &project);
        assert_eq!(decision.minimum_action, "allow", "{target}");
        assert_eq!(
            decision.reason_code, "native_exact_safe_directory_read",
            "{target}"
        );
        assert!(decision.explicitly_benign, "{target}");
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn directory_allow_does_not_allow_dotenv_or_credential_file_reads() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let ssh = home.join(".ssh");
    let aws = home.join(".aws");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::create_dir_all(&aws).unwrap();
    std::fs::create_dir_all(home.join(".env")).unwrap();
    std::fs::write(project.join(".env"), "directory-listing-secret-canary").unwrap();
    std::fs::write(project.join("credentials.json"), "credential-canary").unwrap();

    let project_target = project.to_string_lossy().into_owned();
    let listing = read_directory("omp", &project_target, &home, &project);
    assert!(bounded_omp_directory_read_target(
        &project_target,
        home.to_str(),
        project.to_str(),
    ));
    assert_eq!(
        listing.minimum_action, "allow",
        "{}: {}",
        listing.reason_code, listing.reason
    );
    assert!(!serde_json::to_string(&listing)
        .unwrap()
        .contains("directory-listing-secret-canary"));

    for target in [
        project.join(".env"),
        project.join("credentials.json"),
        home.join(".ssh"),
        home.join(".aws"),
        home.join(".env"),
        std::path::PathBuf::from("/etc"),
        std::path::PathBuf::from("/var"),
    ] {
        let target = target.to_string_lossy().into_owned();
        let decision = read_directory("omp", &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{target}");
        assert!(!decision.explicitly_benign, "{target}");
    }
    #[cfg(unix)]
    {
        let foreign_user_home = std::path::Path::new(std::path::MAIN_SEPARATOR_STR)
            .join("Users")
            .join("Shared");
        if foreign_user_home.is_dir() {
            let target = foreign_user_home.to_string_lossy().into_owned();
            let decision = read_directory("omp", &target, &home, &project);
            assert_ne!(decision.minimum_action, "allow", "foreign user home");
            assert!(!decision.explicitly_benign, "foreign user home");
        }
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pi_unknown_and_recursive_harnesses_do_not_get_directory_allow() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let target = project.to_string_lossy().into_owned();
    for harness in ["pi", "unknown", "omp-recursive"] {
        let decision = read_directory(harness, &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{harness}");
        assert!(!decision.explicitly_benign, "{harness}");
    }
    let post_tool = super::super::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PostToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": target},
        }),
        None,
        None,
        home.to_str(),
        project.to_str(),
    );
    assert_ne!(post_tool.minimum_action, "allow");
    let missing_context = super::super::evaluate_pre_tool_envelope(
        "omp",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": target},
        }),
    );
    assert_ne!(missing_context.minimum_action, "allow");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn omp_directory_post_tool_rechecks_resolved_sensitive_target() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let ordinary = home.join("ordinary");
    let credentials = home.join(".ssh");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&ordinary).unwrap();
    std::fs::create_dir_all(&credentials).unwrap();

    let ordinary_target = ordinary.to_string_lossy().into_owned();
    let ordinary_result = super::super::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PostToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": ordinary_target},
            "tool_response": [{"type": "text", "text": "ordinary/"}],
        }),
        None,
        None,
        home.to_str(),
        project.to_str(),
    );
    assert_ne!(ordinary_result.minimum_action, "allow");
    assert!(!ordinary_result.explicitly_benign);

    let credentials_target = credentials.to_string_lossy().into_owned();
    let redirected_result = super::super::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PostToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": credentials_target},
            "tool_response": [{"type": "text", "text": "id_ed25519"}],
        }),
        None,
        None,
        home.to_str(),
        project.to_str(),
    );
    assert_ne!(redirected_result.minimum_action, "allow");
    assert!(!redirected_result.explicitly_benign);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn omp_directory_parent_components_remain_reviewable() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();

    for target in [
        format!("{}/../project", project.display()),
        format!("{}/../../", project.display()),
    ] {
        let decision = read_directory("omp", &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{target}");
        assert!(!decision.explicitly_benign, "{target}");
    }

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn directory_symlink_escape_stays_reviewable() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let external = root.join("external");
    let ordinary_sibling = home.join("ordinary-sibling");
    let link = project.join("linked-directory");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&external).unwrap();
    std::fs::create_dir_all(&ordinary_sibling).unwrap();
    std::os::unix::fs::symlink(&external, &link).unwrap();

    for target in [
        link,
        project.join("../project/linked-directory"),
        project.join("../ordinary-sibling"),
    ] {
        let target = target.to_string_lossy().into_owned();
        let decision = read_directory("omp", &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{target}");
        assert!(!decision.explicitly_benign, "{target}");
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn omp_bounded_line_selectors_cover_files_and_directories() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let source = project.join("main.rs");
    let selected_directory = project.join("src");
    let literal_colon_file = project.join("literal:1-5");
    std::fs::create_dir_all(&selected_directory).unwrap();
    std::fs::write(&source, "fn main() {}\n").unwrap();
    std::fs::write(&literal_colon_file, "literal path\n").unwrap();

    let source = std::fs::canonicalize(source).unwrap();
    let selected_directory = std::fs::canonicalize(selected_directory).unwrap();
    let literal_colon_file = std::fs::canonicalize(literal_colon_file).unwrap();

    for target in [
        format!("{}:1-5", source.display()),
        format!("{}:1-5", selected_directory.display()),
        "main.rs:1-5".to_owned(),
        literal_colon_file.to_string_lossy().into_owned(),
    ] {
        let decision = read_directory("omp", &target, &home, &project);
        assert_eq!(
            decision.minimum_action, "allow",
            "{target}: {} ({})",
            decision.reason_code, decision.reason
        );
        assert!(decision.explicitly_benign, "{target}");
    }

    for harness in ["pi", "unknown"] {
        let target = format!("{}:1-5", source.display());
        let decision = read_directory(harness, &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{harness}: {target}");
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn omp_bounded_line_selectors_keep_sensitive_and_unsupported_targets_denied() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let ssh = home.join(".ssh");
    let symlink_target = root.join("outside.txt");
    let _symlink = project.join("linked.txt");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(project.join(".env"), "selector-secret\n").unwrap();
    std::fs::write(ssh.join("id_ed25519"), "private-key\n").unwrap();
    std::fs::write(&symlink_target, "outside\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&symlink_target, &_symlink).unwrap();

    for target in [
        format!("{}:1-5", project.join(".env").display()),
        format!("{}:1-5", ssh.join("id_ed25519").display()),
        "src:1-".to_owned(),
        "src:-5".to_owned(),
        "src:1+5".to_owned(),
        "src:1,5".to_owned(),
        format!("{}:1-", project.display()),
        format!("{}:-5", project.display()),
        format!("{}:1+5", project.display()),
        format!("{}:1,5", project.display()),
    ] {
        let decision = read_directory("omp", &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{target}");
        assert!(!decision.explicitly_benign, "{target}");
    }

    #[cfg(unix)]
    {
        let target = format!("{}:1-5", _symlink.display());
        let decision = read_directory("omp", &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{target}");
        assert!(!decision.explicitly_benign, "{target}");
    }

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn omp_selectors_accept_verified_tmp_alias_but_reject_child_symlinks() {
    let tmp = std::path::Path::new("/tmp");
    if std::fs::canonicalize(tmp).ok().as_deref() == Some(tmp) {
        return;
    }
    let root = tmp.join(format!("guard-selector-tmp-alias-{}", std::process::id()));
    let home = root.join("home");
    let project = home.join("project");
    let source = project.join("src").join("main.rs");
    let selected_directory = project.join("src");
    let external = root.join("outside.rs");
    let link = project.join("linked.rs");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, "fn main() {}\n").unwrap();
    std::fs::write(&external, "outside\n").unwrap();
    std::os::unix::fs::symlink(&external, &link).unwrap();

    for (target, reason_code) in [
        (
            format!("{}:1-5", source.display()),
            "native_exact_safe_file_read",
        ),
        (
            format!("{}:1-5", selected_directory.display()),
            "native_exact_safe_directory_read",
        ),
    ] {
        let decision = read_directory("omp", &target, &home, &project);
        assert_eq!(decision.minimum_action, "allow", "{target}");
        assert_eq!(decision.reason_code, reason_code, "{target}");
    }
    let canonical_home = std::fs::canonicalize(&home).unwrap();
    let canonical_project = std::fs::canonicalize(&project).unwrap();
    for (target, reason_code) in [
        (
            format!("{}:1-5", source.display()),
            "native_exact_safe_file_read",
        ),
        (
            format!("{}:1-5", selected_directory.display()),
            "native_exact_safe_directory_read",
        ),
    ] {
        let decision = read_directory("omp", &target, &canonical_home, &canonical_project);
        assert_eq!(decision.minimum_action, "allow", "{target}");
        assert_eq!(decision.reason_code, reason_code, "{target}");
    }
    let symlink_target = format!("{}:1-5", link.display());
    let decision = read_directory("omp", &symlink_target, &canonical_home, &canonical_project);
    assert_ne!(decision.minimum_action, "allow", "{symlink_target}");
    assert!(!decision.explicitly_benign, "{symlink_target}");

    let _ = std::fs::remove_dir_all(root);
}
