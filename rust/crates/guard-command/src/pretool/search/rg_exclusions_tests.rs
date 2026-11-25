use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;
use guard_contracts::NativeCommandControlBindingV1;
use std::path::{Path, PathBuf};

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

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A home with the agent's repository and a sibling one whose tests hold a
/// TLS key fixture next to ordinary test files.
fn fixture(name: &str) -> (PathBuf, PathBuf, String) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/rg-exclusions")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let repo = home.join("work/app");
    let sibling = home.join("work/site");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(sibling.join(".git")).unwrap();
    write(repo.join("src/index.ts"), "export const x = 1;\n");
    write(sibling.join("__tests__/scroll.test.ts"), "scrollTo();\n");
    write(sibling.join("app/page.tsx"), "scrollTo;\n");
    write(
        sibling.join("__tests__/fixtures/tls/loopback-server.key"),
        "synthetic\n",
    );
    let home = crate::runtime_read_paths::canonicalize_text(&home).unwrap();
    let repo = crate::runtime_read_paths::canonicalize_text(&repo).unwrap();
    let tests = home.join("work/site/__tests__").display().to_string();
    (home, repo, tests)
}

fn evaluate(command: &str, home: &Path, cwd: &Path) -> (String, String) {
    let controls = controls();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    );
    (result.decision, result.reason)
}

#[test]
fn the_reason_names_the_key_and_the_exclusion_that_releases_the_search() {
    let (home, repo, tests) = fixture("reason");
    for command in [
        format!("rg -l scrollTo {tests}"),
        format!("rg -l scrollTo {tests}/"),
        format!("rg -n -e scrollTo {tests}"),
        format!("rg -l scrollTo {tests} | head -5"),
    ] {
        let (decision, reason) = evaluate(&command, &home, &repo);
        assert_ne!(decision, "allow", "{command}");
        assert!(
            reason.contains("/fixtures/tls/loopback-server.key`, which Guard treats as sensitive"),
            "{command}: {reason}"
        );
        assert!(reason.contains("`-g '!tls'`"), "{command}: {reason}");
    }
    std::fs::remove_dir_all(home.parent().unwrap()).unwrap();
}

#[test]
fn an_exclusion_that_leaves_out_the_key_releases_the_search() {
    let (home, repo, tests) = fixture("released");
    for command in [
        format!("rg -l scrollTo -g '!tls' {tests}"),
        format!("rg -l scrollTo {tests} -g '!fixtures'"),
        format!("rg -l scrollTo --glob '!fixtures' {tests}"),
        format!("rg -l scrollTo --glob='!fixtures' {tests}"),
        format!("rg -l scrollTo '-g!loopback-server.key' {tests}"),
        format!("rg -l scrollTo -g '!tls' -g '!node_modules' {tests} | head -5"),
    ] {
        let (decision, reason) = evaluate(&command, &home, &repo);
        assert_eq!(decision, "allow", "{command}: {reason}");
    }
    std::fs::remove_dir_all(home.parent().unwrap()).unwrap();
}

#[test]
fn globs_that_could_still_reach_the_key_keep_the_review() {
    let (home, repo, tests) = fixture("held");
    for command in [
        // A later inclusion outranks the exclusion.
        format!("rg -l scrollTo -g '!fixtures' -g fixtures {tests}"),
        format!("rg -l scrollTo -g '!fixtures' -g '**/tls/**' {tests}"),
        // Spellings this does not read one by one.
        format!("rg -l scrollTo --iglob '!fixtures' {tests}"),
        format!("rg -lg '!fixtures' scrollTo {tests}"),
        // Not a plain name, or not the key's folder.
        format!("rg -l scrollTo -g '!fix*' {tests}"),
        format!("rg -l scrollTo -g '!fixtures/' {tests}"),
        format!("rg -l scrollTo -g '!app' {tests}"),
        // A pattern, not a glob.
        format!("rg -l -e '-g!fixtures' {tests}"),
        format!("rg -l scrollTo -- -g'!fixtures' {tests}"),
    ] {
        let (decision, reason) = evaluate(&command, &home, &repo);
        assert_ne!(decision, "allow", "{command}: {reason}");
    }
    // A folder with no key in it was never held.
    let app = home.join("work/site/app").display().to_string();
    let (decision, _) = evaluate(&format!("rg -l scrollTo {app}"), &home, &repo);
    assert_eq!(decision, "allow");
    std::fs::remove_dir_all(home.parent().unwrap()).unwrap();
}

#[test]
fn only_plain_negated_names_are_exclusions() {
    assert_eq!(
        super::excluded_names(&["!tls", "!.cache", "!a_b-c.d"]),
        ["tls", ".cache", "a_b-c.d"]
    );
    for globs in [
        &["!tls", "fixtures"][..],
        &["!*.key"],
        &["!a/b"],
        &["!"],
        &["!.."],
        &["tls"],
    ] {
        assert!(super::excluded_names(globs).is_empty(), "{globs:?}");
    }
}
