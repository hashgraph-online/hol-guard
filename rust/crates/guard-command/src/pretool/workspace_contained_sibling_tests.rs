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
    crate::pretool::workspace_contained::sandbox_available()
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
        // `..` into a linked worktree of the session's repository is that
        // worktree's root, as the checkout a chain creates beside it is.
        "cd ../app-report && node scripts/report.mjs && cat reports/weekly.md".to_owned(),
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
        // A relative parent is proved only into a linked worktree of the
        // session's repository.
        "cd ../other && npm run build && ls dist".to_owned(),
        "cd ../plain && npm run build && ls dist".to_owned(),
        "cd .. && npm run build && ls dist".to_owned(),
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
        format!("cd {}/plain 2>/dev/null; npm run build", projects.display()),
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

/// Scripts in the linked worktree: a package whose `node_modules` links into
/// the main checkout, as a worktree shares its installs, and a package whose
/// link leaves both trees. Returns the directory outside home holding the
/// link target and a config file.
#[cfg(unix)]
fn worktree_packages(main: &Path, tree: &Path) -> PathBuf {
    let outside = tree
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("elsewhere");
    for directory in [
        main.join("web/node_modules/.bin"),
        outside.join("node_modules/.bin"),
        tree.join("web"),
        tree.join("stray"),
        tree.join("tools"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    for file in [
        main.join("web/node_modules/.bin/report"),
        main.join("web/node_modules/.bin/vite"),
        outside.join("node_modules/.bin/report"),
        outside.join("report.config.js"),
        tree.join("scripts/report.sh"),
        tree.join("tools/report"),
    ] {
        std::fs::write(file, "#!/bin/sh\n").unwrap();
    }
    std::os::unix::fs::symlink(main.join("web/node_modules"), tree.join("web/node_modules"))
        .unwrap();
    std::os::unix::fs::symlink(
        outside.join("node_modules"),
        tree.join("stray/node_modules"),
    )
    .unwrap();
    outside
}

#[cfg(unix)]
#[test]
fn one_command_below_a_sibling_root_runs_contained_from_that_root() {
    let (home, main, tree) = fixture();
    worktree_packages(&main, &tree);
    for command in [
        format!("cd {}/scripts && ./report.sh", tree.display()),
        format!(
            "cd {}/scripts && ./report.sh 2>&1 | tail -15",
            tree.display()
        ),
        // The root itself with an output filter is not the `&&` list above.
        format!("cd {} && ./tools/report 2>&1 | tail -15", tree.display()),
        // A worktree package reads its installs from the main checkout,
        // which the sandbox mounts read-only for a linked worktree.
        format!(
            "cd {}/web && ./node_modules/.bin/report build",
            tree.display()
        ),
        // The sink resolves the directory first, so `;` and a silenced `cd`
        // never run the command from the session directory.
        format!("cd {}/scripts; ./report.sh", tree.display()),
        format!("cd {}/scripts 2>/dev/null; ./report.sh", tree.display()),
        format!(
            "cd {0}/web 2>/dev/null; {0}/web/node_modules/.bin/vite build",
            tree.display()
        ),
    ] {
        assert_eq!(
            contained(&reason("omp", &home, &main, &command)),
            host(),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

#[cfg(unix)]
#[test]
fn a_command_below_a_sibling_root_reaching_outside_it_keeps_its_review() {
    let (home, main, tree) = fixture();
    let outside = worktree_packages(&main, &tree);
    let config = outside.join("report.config.js");
    for command in [
        // The link resolves outside the repository and its main checkout.
        format!(
            "cd {}/stray && ./node_modules/.bin/report build",
            tree.display()
        ),
        format!(
            "cd {}/web && ./node_modules/.bin/report build --config {}",
            tree.display(),
            config.display()
        ),
        format!(
            "cd {}/web && ./node_modules/.bin/report build --config={}",
            tree.display(),
            config.display()
        ),
        // Unproved, or more than one command.
        "cd ../app-report/scripts && ./report.sh".to_owned(),
        format!("cd {}/scripts && ./report.sh && ls", tree.display()),
        format!("cd {}/scripts; ./report.sh; ls", tree.display()),
        format!("cd {}/scripts && ./report.sh | wc -l", tree.display()),
        format!(
            "cd {}/scripts 2>/dev/null; ./report.sh | wc -l",
            tree.display()
        ),
        // After `;` the command must also stay readable from the root, where
        // `../other` is the unrelated clone.
        format!(
            "cd {}/web; ./node_modules/.bin/report build ../other/package.json",
            tree.display()
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
        &format!("cd {}/scripts && ./report.sh", tree.display())
    )));
    // macOS holds a Vite build to its own read-only output profile instead.
    if !cfg!(target_os = "macos") {
        let command = format!(
            "cd {}/web && ./node_modules/.bin/vite build --config {}",
            tree.display(),
            config.display()
        );
        assert!(
            !contained(&reason("omp", &home, &main, &command)),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// A script in the linked worktree, a tool installed in the unrelated clone,
/// and a script in a private temporary directory outside home.
fn sibling_scripts(home: &Path, tree: &Path) -> PathBuf {
    let other = tree.parent().unwrap().join("other");
    let loose = home.parent().unwrap().join("loose");
    for directory in [other.join("node_modules/vite/bin"), loose.clone()] {
        std::fs::create_dir_all(directory).unwrap();
    }
    for file in [
        tree.join("scripts/report.py"),
        tree.join("scripts/report.ts"),
        other.join("node_modules/vite/bin/vite.js"),
        tree.parent().unwrap().join("plain/probe.py"),
        loose.join("probe.py"),
    ] {
        std::fs::write(file, "").unwrap();
    }
    loose
}

#[test]
fn a_script_in_a_sibling_repository_runs_contained_from_its_root() {
    let (home, main, tree) = fixture();
    sibling_scripts(&home, &tree);
    let other = tree.parent().unwrap().join("other");
    for command in [
        format!("python3 {}/scripts/report.py --top 40", tree.display()),
        // The compile writes `__pycache__` beside the module, in that root.
        format!("python3 -m py_compile {}/scripts/report.py", tree.display()),
        format!("bun {}/scripts/report.ts --help", tree.display()),
        format!(
            "bun {0}/node_modules/vite/bin/vite.js build --root {0}",
            other.display()
        ),
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
fn a_script_outside_a_sibling_repository_keeps_its_review() {
    let (home, main, tree) = fixture();
    let loose = sibling_scripts(&home, &tree);
    let script = tree.join("scripts/report.py");
    for command in [
        format!("bun {}/probe.py", loose.display()),
        // An operand outside the trees the rooted sandbox can read.
        format!("python3 {} {}/probe.py", script.display(), loose.display()),
        // A sibling path that is only an operand runs nothing from there.
        format!("rm {}", script.display()),
        format!("cat {}", script.display()),
        format!("jq . {}/package.json", tree.display()),
        format!("rg -n report {}/scripts", tree.display()),
        format!("python3 -c 1 {}", script.display()),
    ] {
        assert!(
            !contained(&reason("omp", &home, &main, &command)),
            "{command}"
        );
    }
    // A relative operand names a file in the session's own checkout, which
    // the workspace sandbox already reads, so the clean script runs contained.
    // A setting, a pipe or a list around the clean script stays in the same
    // read-only sandbox, so it runs contained as well.
    for command in [
        format!("python3 {} package.json", script.display()),
        format!("REPORT=1 python3 {}", script.display()),
        format!("python3 {} | wc -l", script.display()),
        format!("python3 {} && ls", script.display()),
    ] {
        assert_eq!(
            contained(&reason("omp", &home, &main, &command)),
            host(),
            "{command}"
        );
    }
    // A plain home directory or a private temporary one has no root, but a
    // clean single script there still runs as a read-only grant of that file.
    for command in [
        format!(
            "python3 {}/plain/probe.py",
            tree.parent().unwrap().display()
        ),
        format!("python3 {}/probe.py", loose.display()),
    ] {
        assert_eq!(
            contained(&reason("omp", &home, &main, &command)),
            host(),
            "{command}"
        );
    }
    let command = format!("python3 {}", script.display());
    assert!(!contained(&reason("cursor", &home, &main, &command)));
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

#[cfg(unix)]
#[test]
fn a_setting_after_a_sibling_cd_runs_contained_from_that_root() {
    let (home, main, tree) = fixture();
    worktree_packages(&main, &tree);
    // The sandbox runs the text as issued from the sibling root, where the
    // command without its setting is contained too.
    let command = format!(
        "cd {}/web && REPORT_DIR=/tmp/report ./node_modules/.bin/report build",
        tree.display()
    );
    assert_eq!(
        contained(&reason("omp", &home, &main, &command)),
        host(),
        "{command}"
    );
    for command in [
        format!(
            "cd {}/web && NODE_OPTIONS=--require=./x.js ./node_modules/.bin/report build",
            tree.display()
        ),
        format!(
            "cd {}/stray && REPORT_DIR=/tmp/report ./node_modules/.bin/report build",
            tree.display()
        ),
    ] {
        assert!(
            !contained(&reason("omp", &home, &main, &command)),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

#[test]
fn a_temporary_or_enclosing_repository_is_no_sibling_root() {
    let (home, main, tree) = fixture();
    sibling_scripts(&home, &tree);
    let root = home.parent().unwrap().to_path_buf();
    // A fresh `git init` below `/tmp`, outside home.
    std::fs::create_dir_all(root.join("scratch/.git")).unwrap();
    std::fs::write(root.join("scratch/run.py"), "").unwrap();
    // A linked worktree below `/tmp` of the checkout in home.
    let (linked, admin) = (root.join("linked"), main.join(".git/worktrees/linked"));
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::create_dir_all(linked.join("scripts")).unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(admin.join("gitdir"), format!("{}/.git\n", linked.display())).unwrap();
    std::fs::write(
        linked.join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .unwrap();
    std::fs::write(linked.join("scripts/run.py"), "").unwrap();
    std::fs::create_dir_all(tree.join("web")).unwrap();
    let run = |cwd: &Path, script: PathBuf| {
        contained(&reason(
            "omp",
            &home,
            cwd,
            &format!("python3 {}", script.display()),
        ))
    };
    // Neither is a sibling root; a clean script still runs as a one-file read grant.
    assert_eq!(run(&main, root.join("scratch/run.py")), host());
    assert_eq!(run(&main, linked.join("scripts/run.py")), host());
    assert_eq!(
        run(&tree.join("web"), tree.join("scripts/report.py")),
        host()
    );
    let _ = std::fs::remove_dir_all(root);
}
