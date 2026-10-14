//! `cd <sibling repository root> && …` runs contained in that root.
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;
use guard_contracts::NativeCommandControlBindingV1;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn controls() -> CompiledNativeCommandControls {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

fn host() -> bool {
    cfg!(target_os = "macos") || crate::restricted_pytest::linux_workspace_sandbox_available()
}

fn reason(harness: &str, home: &Path, cwd: &Path, command: &str) -> String {
    let controls = controls();
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .reason_code
}

/// A main checkout, a linked worktree beside it, an unrelated clone and a
/// plain directory, all below a private home.
fn fixture() -> (PathBuf, PathBuf, PathBuf) {
    // `/tmp`, not `$TMPDIR`: macOS puts the latter below `/private/var`,
    // which no path proof admits outside the working directory.
    let root = Path::new("/tmp").join(format!(
        "guard-sibling-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    let projects = root.join("home/projects");
    let (main, tree) = (projects.join("app"), projects.join("app-report"));
    let admin = main.join(".git/worktrees/app-report");
    for directory in [
        &admin,
        &tree.join("scripts"),
        &projects.join("other/.git"),
        &projects.join("plain"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = root.join("home").canonicalize().unwrap();
    let (main, tree) = (main.canonicalize().unwrap(), tree.canonicalize().unwrap());
    let admin = admin.canonicalize().unwrap();
    for config in [main.join(".git/config"), projects.join("other/.git/config")] {
        std::fs::write(config, "[core]\n\tbare = false\n").unwrap();
    }
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", tree.join(".git").display()),
    )
    .unwrap();
    std::fs::write(tree.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
    for project in [
        &main,
        &tree,
        &projects.join("other"),
        &projects.join("plain"),
    ] {
        std::fs::write(project.join("package.json"), "{}").unwrap();
    }
    (home, main, tree)
}

fn contained(reason: &str) -> bool {
    reason.ends_with("_containment_required")
}

#[test]
fn a_list_after_cd_into_a_sibling_root_runs_contained_there() {
    let (home, main, tree) = fixture();
    let other = tree.parent().unwrap().join("other");
    for command in [
        format!(
            "cd {} && node scripts/report.mjs && cat reports/weekly.md",
            tree.display()
        ),
        format!("cd {} && npm run build && ls dist", tree.display()),
        // A removal is contained there exactly as it is in the session's own root.
        format!("cd {} && ls && rm notes.txt", tree.display()),
        format!(
            "cd {} && npm run build && cat package.json",
            other.display()
        ),
        // The sink resolves the root itself, so a failed `cd` never leaves
        // the rest running in the session directory; `;` peels like `&&`.
        format!("cd {}; node scripts/report.mjs", tree.display()),
        format!("cd {} ; npm run build && ls dist", tree.display()),
    ] {
        assert_eq!(
            contained(&reason("omp", &home, &main, &command)),
            host(),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

#[test]
fn a_sibling_cd_the_sink_would_not_rebase_keeps_its_review() {
    let (home, main, _tree) = fixture();
    let projects = main.parent().unwrap();
    for command in [
        // The shell resolves `..` against its logical `$PWD`, which the
        // reported cwd may not show, so a relative parent is never proved.
        "cd ../app-report && node scripts/report.mjs && cat reports/weekly.md".to_owned(),
        // Not a repository root, or no repository at all.
        format!(
            "cd {}/app-report/scripts && node report.mjs && cat out.md",
            projects.display()
        ),
        format!(
            "cd {}/plain && npm run build && ls dist",
            projects.display()
        ),
        format!("cd {} && npm run build && ls dist", projects.display()),
        // A pipe, or `;` anywhere but right after the `cd`, is not the list
        // the sink peels.
        format!(
            "cd {}/app-report && npm run build && ls | wc -l",
            projects.display()
        ),
        format!(
            "cd {}/app-report; npm run build; ls dist",
            projects.display()
        ),
        format!(
            "cd {}/app-report && npm run build; ls dist",
            projects.display()
        ),
        // `;` after a cd into a plain directory still has no root to rebase.
        format!("cd {}/plain; npm run build", projects.display()),
        // An absolute operand does not move the workspace, so the compile
        // would have to write `__pycache__` into the sibling from this one.
        format!(
            "python3 -m py_compile {}/app-report/scripts/report.py",
            projects.display()
        ),
        // The rest still faces every check it would from that root.
        format!(
            "cd {}/app-report && git add -A && git status",
            projects.display()
        ),
        format!(
            "cd {}/app-report && npm run build && curl https://example.com",
            projects.display()
        ),
        format!(
            "cd {}/app-report && npm run build && cat ../app/.git/config",
            projects.display()
        ),
        format!(
            "cd {}/app-report && npm run build && rm -rf .",
            projects.display()
        ),
    ] {
        assert!(
            !contained(&reason("omp", &home, &main, &command)),
            "{command}"
        );
    }
    assert!(!contained(&reason(
        "cursor",
        &home,
        &main,
        &format!(
            "cd {}/app-report && npm run build && ls dist",
            projects.display()
        )
    )));
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}
