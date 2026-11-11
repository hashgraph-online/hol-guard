#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

struct FixtureDirectory(PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn allowed(command: &str, home: &Path, cwd: &Path) -> Vec<bool> {
    ["omp", "zcode", "claude-code"]
        .into_iter()
        .map(|harness| {
            evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                home.to_str(),
                cwd.to_str(),
            )
            .minimum_action
                == "allow"
        })
        .collect()
}

fn write(root: &Path, path: &str, contents: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn fixture(name: &str) -> (FixtureDirectory, PathBuf, PathBuf) {
    let nonce = crate::unique_nanos::unique_nanos();
    let home = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/read-directory-globs")
        .join(format!("{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(home.join("project")).unwrap();
    let guard = FixtureDirectory(home.clone());
    let home = std::fs::canonicalize(home).unwrap();
    let project = home.join("project");
    for path in [
        "crates/guard-core/Cargo.toml",
        "crates/guard-cli/Cargo.toml",
        "app/api/claims/[id]/start/route.ts",
        "app/api/claims/[id]/finish/route.ts",
        "app/api/claims/batch/start/route.ts",
    ] {
        write(&project, path, "ordinary\n");
    }
    // A directory with no manifest is not a match, as in the shell.
    std::fs::create_dir_all(project.join("crates/scratch")).unwrap();
    (guard, home, project)
}

#[test]
fn wildcard_directories_in_the_workspace_read_like_their_matches() {
    let (_guard, home, project) = fixture("allowed");
    for command in [
        "head -5 crates/*/Cargo.toml",
        "sed -n 1,5p crates/guard-*/Cargo.toml",
        "wc -l crates/*/Cargo.toml",
        "cat crates/*/*.toml",
        "sed -n 205,245p app/api/claims/*/start/route.ts",
        "head -20 app/*/claims/*/*/route.ts",
        "cat */guard-core/Cargo.toml",
    ] {
        assert_eq!(
            allowed(command, &home, &project),
            vec![true; 3],
            "{command}"
        );
    }
    let absolute = format!(
        "sed -n 1,5p {}/app/api/claims/*/start/route.ts",
        project.display()
    );
    assert_eq!(allowed(&absolute, &home, &project), vec![true; 3]);
}

#[test]
fn wildcard_directories_keep_review_when_a_match_is_not_a_plain_read() {
    let (_guard, home, project) = fixture("key");
    write(&project, "crates/guard-core/tls.key", "synthetic\n");
    write(&project, "crates/guard-cli/.env", "SYNTHETIC=1\n");
    for command in [
        // A matched key, and a hidden file a `dotglob` shell would read.
        "cat crates/*/*.key",
        "cat crates/*/*",
        // Nothing matches.
        "cat crates/*/missing.toml",
        // `?id?` matches `[id]` but has not walked the names `$f` could
        // expand that directory to.
        "cat app/api/claims/?id?/start/route.ts",
        // Brackets, `**` and hidden roots stay out of the model.
        "cat crates/[g]*/Cargo.toml",
        "cat crates/**/Cargo.toml",
        "cat .git/*/HEAD",
    ] {
        assert_eq!(
            allowed(command, &home, &project),
            vec![false; 3],
            "{command}"
        );
    }

    let (_guard, home, project) = fixture("hidden");
    write(&project, "crates/.archive/Cargo.toml", "ordinary\n");
    assert_eq!(
        allowed("head -5 crates/*/Cargo.toml", &home, &project),
        vec![false; 3]
    );

    let (_guard, home, project) = fixture("spaced");
    write(&project, "crates/guard -n/Cargo.toml", "ordinary\n");
    assert_eq!(
        allowed("head -5 crates/*/Cargo.toml", &home, &project),
        vec![false; 3]
    );

    let (_guard, home, project) = fixture("option");
    write(&project, "-n/guard-core/Cargo.toml", "ordinary\n");
    assert_eq!(
        allowed("cat */guard-core/Cargo.toml", &home, &project),
        vec![false; 3]
    );

    // A matched directory that links into a directory the literal read
    // proof refuses.
    let (_guard, home, project) = fixture("linked");
    write(&home, ".ssh/Cargo.toml", "ordinary\n");
    std::os::unix::fs::symlink(home.join(".ssh"), project.join("crates/linked")).unwrap();
    assert_eq!(
        allowed("head -5 crates/*/Cargo.toml", &home, &project),
        vec![false; 3]
    );
}
