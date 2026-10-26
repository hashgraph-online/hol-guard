use super::apply_patch_targets;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    home: PathBuf,
    workspace: PathBuf,
}

fn fixture() -> Fixture {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("guard-apply-patch-{}-{nonce}", std::process::id()));
    // The target directory survives between CI runs through the build cache,
    // and process ids repeat, so an earlier run's fixture (including its
    // symlinks) can already sit at this path.
    match std::fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("failed to clear stale fixture {}: {error}", root.display()),
    }
    let workspace = root.join("home/project");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join("src/settings.ts"), "retryLimit: 3,\n").unwrap();
    std::fs::write(workspace.join(".env"), "TOKEN=synthetic\n").unwrap();
    std::fs::write(workspace.join("AGENTS.md"), "rules\n").unwrap();
    std::fs::write(workspace.join(".git/config"), "[core]\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    // Windows canonicalize yields `\\?\D:\...`; hosts hand Guard plain drive paths.
    let root = PathBuf::from(root.to_str().unwrap().trim_start_matches(r"\\?\"));
    Fixture {
        home: root.join("home"),
        workspace: root.join("home/project"),
    }
}

fn patch(headers: &[&str]) -> String {
    let mut body = vec!["*** Begin Patch".to_owned()];
    for header in headers {
        body.push((*header).to_owned());
        if header.trim_start().starts_with("*** Add File: ") {
            body.push("+export const added = true;".to_owned());
        } else {
            body.push("@@".to_owned());
            body.push("-  retryLimit: 3,".to_owned());
            body.push("+  retryLimit: 5,".to_owned());
        }
    }
    body.push("*** End Patch".to_owned());
    body.join("\n")
}

fn review(harness: &str, command: &str, fixture: &Fixture) -> guard_contracts::PreToolResultV1 {
    super::super::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": command},
        }),
        None,
        None,
        fixture.home.to_str(),
        fixture.workspace.to_str(),
    )
}

fn proven(result: &guard_contracts::PreToolResultV1) -> bool {
    result.reason_code == "native_exact_safe_file_write" && result.minimum_action == "allow"
}

#[test]
fn routine_workspace_update_is_proven() {
    let fixture = fixture();
    let absolute = format!(
        "*** Update File: {}",
        fixture.workspace.join("src/settings.ts").display()
    );
    for command in [
        patch(&["*** Update File: src/settings.ts"]),
        patch(&[absolute.as_str()]),
        patch(&[
            "*** Add File: src/new.ts",
            "*** Update File: src/settings.ts",
        ]),
    ] {
        let result = review("codex", &command, &fixture);
        assert!(proven(&result), "{command}: {result:?}");
        assert!(!result.action.sensitive_target);
    }
}

#[test]
fn protected_or_unbounded_targets_stay_unproven() {
    let fixture = fixture();
    let outside = format!(
        "*** Update File: {}",
        fixture
            .home
            .parent()
            .unwrap()
            .join("elsewhere.ts")
            .display()
    );
    for header in [
        "*** Update File: .env",
        "*** Update File: AGENTS.md",
        "*** Update File: .git/config",
        "*** Add File: .codex/config.toml",
        "*** Add File: .opencode/plugins/x.ts",
        "*** Add File: .zcode/settings.json",
        "*** Add File: .gemini/settings.json",
        "*** Update File: .mcp.json",
        "*** Add File: .github/copilot-instructions.md",
        "*** Add File: .husky/pre-commit",
        "*** Update File: ../outside.ts",
        "*** Delete File: src/settings.ts",
        outside.as_str(),
    ] {
        let command = patch(&["*** Update File: src/settings.ts", header]);
        assert!(!proven(&review("codex", &command, &fixture)), "{header}");
    }
}

#[test]
fn sibling_project_in_verified_home_matches_host_write_tools() {
    // Claude Code's Write and Oh My Pi's write already reach a sibling
    // project in the verified home; Codex's edit tool gets the same scope.
    let fixture = fixture();
    let sibling = fixture.home.join("other-project");
    std::fs::create_dir_all(sibling.join(".git")).unwrap();
    std::fs::create_dir_all(fixture.home.join("bin")).unwrap();
    std::fs::write(sibling.join("notes.md"), "Reviewed\n").unwrap();
    for path in ["notes.md", "added.md"] {
        let header = if path == "notes.md" { "Update" } else { "Add" };
        let command = patch(&[&format!(
            "*** {header} File: {}",
            sibling.join(path).display()
        )]);
        let result = review("codex", &command, &fixture);
        assert!(proven(&result), "{command}: {result:?}");
    }
    for target in [
        sibling.join("AGENTS.md"),
        sibling.join(".git/config"),
        sibling.join(".codex/config.toml"),
        fixture.home.join(".zshrc"),
        fixture.home.join(".ssh/config"),
        fixture.home.join("bin/tool"),
    ] {
        let command = patch(&[&format!("*** Add File: {}", target.display())]);
        assert!(!proven(&review("codex", &command, &fixture)), "{command}");
    }
    // Codex writes `~/notes.md` under cwd, not the home directory.
    for header in [
        "*** Add File: ~/notes.md",
        "*** Update File: ~/other-project/notes.md",
    ] {
        let command = patch(&[header]);
        assert!(!proven(&review("codex", &command, &fixture)), "{command}");
    }
}

#[test]
fn moves_malformed_and_foreign_harness_patches_stay_unproven() {
    let fixture = fixture();
    let moved = "*** Begin Patch\n*** Update File: src/settings.ts\n*** Move to: src/other.ts\n@@\n-a\n+b\n*** End Patch";
    let unterminated = "*** Begin Patch\n*** Update File: src/settings.ts\n@@\n-a\n+b";
    let empty = "*** Begin Patch\n*** End Patch";
    let shell = "cat src/settings.ts";
    for command in [moved, unterminated, empty, shell] {
        assert!(!proven(&review("codex", command, &fixture)), "{command}");
    }
    let routine = patch(&["*** Update File: src/settings.ts"]);
    assert!(!proven(&review("claude-code", &routine, &fixture)));
}

#[test]
fn targets_parse_only_add_and_update_headers() {
    let crlf = "*** Begin Patch\r\n*** Add File: a.ts\r\n+x\r\n*** Update File: b.ts\r\n@@\r\n-a\r\n+b\r\n*** End of File\r\n*** End Patch\r\n";
    assert_eq!(
        apply_patch_targets(crlf),
        Some(vec!["a.ts".to_owned(), "b.ts".to_owned()])
    );
    assert_eq!(
        apply_patch_targets("*** Begin Patch\n*** Frobnicate: a\n*** End Patch"),
        None
    );
    assert_eq!(apply_patch_targets(&"x".repeat(600 * 1024)), None);
}

#[test]
fn padded_headers_cannot_hide_targets_from_the_proof() {
    // Codex trims lines before matching headers outside update hunks, so a
    // padded header after added content is a real hunk and must be seen.
    let fixture = fixture();
    for (hidden, surfaced) in [
        ("  *** Delete File: AGENTS.md", None),
        (" *** Environment ID: remote", None),
        (
            "\t*** Update File: ../../.ssh/authorized_keys",
            Some("../../.ssh/authorized_keys"),
        ),
        (
            "  *** Add File: .codex/config.toml",
            Some(".codex/config.toml"),
        ),
    ] {
        let body =
            format!("*** Begin Patch\n*** Add File: src/new.ts\n+x\n{hidden}\n+y\n*** End Patch");
        let expected = surfaced.map(|path| vec!["src/new.ts".to_owned(), path.to_owned()]);
        assert_eq!(apply_patch_targets(&body), expected, "{hidden}");
        assert!(!proven(&review("codex", &body, &fixture)), "{hidden}");
    }
    let padded = "*** Begin Patch\n*** Add File: a.ts\n+x\n   *** Update File: b.ts\n@@\n-a\n+b\n*** End Patch";
    assert_eq!(
        apply_patch_targets(padded),
        Some(vec!["a.ts".to_owned(), "b.ts".to_owned()])
    );
}

#[test]
fn only_codex_hunk_content_is_accepted_between_headers() {
    for body in [
        // Added files accept only `+` lines.
        "*** Begin Patch\n*** Add File: a.ts\nplain\n*** End Patch",
        // Update hunks accept context, `+`, `-`, `@@` and end-of-file lines.
        "*** Begin Patch\n*** Update File: a.ts\n*** Move to: b.ts\n@@\n-a\n+b\n*** End Patch",
        "*** Begin Patch\n*** Update File: a.ts\n@@\n-a\n+b\n*** Frobnicate\n*** End Patch",
        // Nothing but blank lines may follow the end marker.
        "*** Begin Patch\n*** Add File: a.ts\n+x\n*** End Patch\n*** Delete File: b.ts",
        "<<EOF\n*** Begin Patch\n*** Add File: a.ts\n+x\n*** End Patch\nEOF",
    ] {
        assert_eq!(apply_patch_targets(body), None, "{body}");
    }
    // Inside an update hunk Codex keeps leading space, so this is a context line.
    let context =
        "*** Begin Patch\n*** Update File: a.ts\n@@\n *** Delete File: b.ts\n-a\n+b\n*** End Patch";
    assert_eq!(apply_patch_targets(context), Some(vec!["a.ts".to_owned()]));
}

#[test]
fn patches_over_the_payload_string_bound_stay_unproven() {
    let filler = format!("+{}\n", "x".repeat(1024)).repeat(40);
    let body = format!("*** Begin Patch\n*** Add File: src/big.ts\n{filler}*** End Patch");
    assert!(body.len() > crate::MAX_COMMAND_BYTES);
    assert_eq!(apply_patch_targets(&body), None);
}

#[cfg(unix)]
#[test]
fn links_named_as_agent_instructions_stay_unproven() {
    let fixture = fixture();
    std::fs::create_dir_all(fixture.workspace.join("docs")).unwrap();
    std::fs::write(fixture.workspace.join("docs/rules.md"), "rules\n").unwrap();
    std::fs::create_dir_all(fixture.workspace.join("nested")).unwrap();
    std::os::unix::fs::symlink(
        "../docs/rules.md",
        fixture.workspace.join("nested/CLAUDE.md"),
    )
    .unwrap();
    std::os::unix::fs::symlink("docs", fixture.workspace.join(".cursor")).unwrap();
    let absolute = format!(
        "*** Update File: {}",
        fixture.workspace.join("nested/CLAUDE.md").display()
    );
    for header in [
        "*** Update File: nested/CLAUDE.md",
        absolute.as_str(),
        "*** Update File: .cursor/rules.md",
    ] {
        let command = patch(&[header]);
        assert!(!proven(&review("codex", &command, &fixture)), "{header}");
    }
    let routine = patch(&["*** Update File: docs/rules.md"]);
    assert!(proven(&review("codex", &routine, &fixture)));
}
