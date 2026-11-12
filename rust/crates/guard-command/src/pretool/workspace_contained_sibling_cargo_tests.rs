//! `cargo --manifest-path <sibling worktree>/Cargo.toml` from the main
//! checkout runs contained from the worktree that holds the manifest, as
//! after `cd <worktree> &&`.
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;
use guard_contracts::NativeCommandControlBindingV1;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

const MANIFEST: &str =
    "[package]\nname = \"app-portal\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";

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

fn reason(home: &Path, cwd: &Path, command: &str) -> String {
    let controls = controls();
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .reason_code
}

struct Layout {
    home: PathBuf,
    main: PathBuf,
    beside: PathBuf,
    temporary: PathBuf,
    stranger: PathBuf,
    roots: [PathBuf; 2],
}

impl Drop for Layout {
    fn drop(&mut self) {
        for root in &self.roots {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

/// Register `tree` as a linked worktree of `main`, the way Git does.
fn link(main: &Path, tree: &Path) {
    let name = tree.file_name().unwrap();
    let admin = main.join(".git/worktrees").join(name);
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::create_dir_all(tree.join("rust")).unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", tree.join(".git").display()),
    )
    .unwrap();
    std::fs::write(tree.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
}

/// A main checkout below home, a linked worktree beside it, another in
/// `/tmp` outside home, and an unrelated clone in `/tmp`. Each of the last
/// three holds a crate at its root and one in `rust/`.
fn layout() -> Layout {
    let label = format!(
        "guard-sibling-cargo-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    );
    let roots = [
        Path::new("/tmp").join(&label),
        Path::new("/tmp").join(format!("{label}-tmp")),
    ];
    for root in &roots {
        let _ = std::fs::remove_dir_all(root);
    }
    std::fs::create_dir_all(roots[0].join("home/projects/app/.git")).unwrap();
    std::fs::create_dir_all(roots[1].join("other/.git")).unwrap();
    let home = roots[0].join("home").canonicalize().unwrap();
    let main = home.join("projects/app");
    let temporary_root = roots[1].canonicalize().unwrap();
    let (beside, temporary) = (
        home.join("projects/app-fix"),
        temporary_root.join("app-brand"),
    );
    let stranger = temporary_root.join("other");
    for config in [main.join(".git/config"), stranger.join(".git/config")] {
        std::fs::write(config, "[core]\n\tbare = false\n").unwrap();
    }
    link(&main, &beside);
    link(&main, &temporary);
    std::fs::create_dir_all(stranger.join("rust")).unwrap();
    for tree in [&beside, &temporary, &stranger] {
        std::fs::write(tree.join("Cargo.toml"), MANIFEST).unwrap();
        std::fs::write(tree.join("rust/Cargo.toml"), MANIFEST).unwrap();
    }
    Layout {
        home,
        main,
        beside,
        temporary,
        stranger,
        roots,
    }
}

fn contained(reason: &str) -> bool {
    reason.ends_with("_containment_required")
}

#[test]
fn a_manifest_in_a_linked_worktree_runs_contained_from_that_worktree() {
    let layout = layout();
    let host = crate::pretool::workspace_contained::sandbox_available();
    for tree in [&layout.beside, &layout.temporary] {
        for command in [
            format!(
                "cargo test --manifest-path {}/Cargo.toml -p app-portal -- --exact",
                tree.display()
            ),
            format!(
                "cargo check --manifest-path={}/rust/Cargo.toml",
                tree.display()
            ),
        ] {
            let reason = reason(&layout.home, &layout.main, &command);
            assert_eq!(contained(&reason), host, "{reason}: {command}");
        }
    }
}

#[test]
fn a_manifest_the_sibling_rule_does_not_trust_keeps_its_review() {
    let layout = layout();
    for command in [
        // A clone in a shared temporary directory, not a worktree of this one.
        format!(
            "cargo test --manifest-path {}/Cargo.toml",
            layout.stranger.display()
        ),
        // A verb that reaches a registry.
        format!(
            "cargo install --manifest-path {}/Cargo.toml",
            layout.beside.display()
        ),
        // A manifest the worktree does not hold.
        format!(
            "cargo test --manifest-path {}/missing/Cargo.toml",
            layout.beside.display()
        ),
        // Another file in the worktree is no manifest.
        format!(
            "cargo test --manifest-path {}/.git",
            layout.beside.display()
        ),
    ] {
        let reason = reason(&layout.home, &layout.main, &command);
        assert!(!contained(&reason), "{reason}: {command}");
    }
}
