#![cfg(unix)]

//! A file named once in a variable and read through the rest of the chain.
//!
//! `f=src/a.ts; sed -n 1,5p $f; grep -n export $f` was already judged as the
//! reads of `src/a.ts`. Two common spellings of the same reads were not:
//!
//! - `cd . && f=src/a.ts; sed -n 1,5p $f`, where the assignment sits behind
//!   the leading `cd`'s `&&`. It counted as conditional, so the `;` dropped it,
//!   though a `cd` into a directory that exists and can be searched cannot
//!   fail.
//! - `f=~/notes/plan.md; sed -n 1,5p $f`, where the value starts with the
//!   tilde the shell expands in an assignment.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const HARNESSES: &[&str] = &["omp", "zcode", "codex", "claude-code"];

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Built under the target directory: the macOS temporary directory sits below
/// `/private/var`, where every read is held for reasons of its own. The
/// directory name carries a hyphen before a letter run that ends in a bound
/// variable's name (`-of` for `f`), as a pytest temporary root such as
/// `/tmp/pytest-of-runner` does, so the path is read as one operand rather
/// than as the flag `-o f`.
fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-chain-literal-cd-and-tilde")
        .join(format!(
            "copy-of-home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    write(project.join("src/lib/a.ts"), "export const a = 1;\n");
    write(home.join("notes/plan.md"), "# Plan\n\n## Steps\n");
    write(
        home.join(".codex/plans/plan-todo.md"),
        "# Todo\n- [ ] retry window\n",
    );
    write(home.join(".ssh/id_ed25519"), "fixture\n");
    Fixture {
        root,
        home,
        project,
    }
}

/// The environment a hook stamps for a shell whose HOME is the declared
/// home and which inherits no CDPATH.
fn environment(f: &Fixture) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: Vec::new(),
        environment_digest: "0".repeat(64),
        home: f.home.to_str().map(str::to_owned),
        ..Default::default()
    }
}

/// The context a hook builds for a shell whose HOME is the declared home
/// and which inherits no CDPATH.
fn action(f: &Fixture, harness: &str, command: &str) -> String {
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            literal_words: &[],
            guard_home: None,
            home_dir: f.home.to_str(),
            cwd: f.project.to_str(),
            cdpath_unset: true,
            rustup_override_absent: false,
            go_toolchain_inert: false,
            cargo_config_inert: false,
            cargo_compiler_inert: false,
            npm_config_inert: false,
            pip_config_inert: false,
            python_environment_inert: false,
            shell_home_matches: true,
            ripgrep_config_absent: false,
            gem_config_absent: false,
            http_config_absent: false,
            openssl_config_absent: false,
            psql_environment: Default::default(),
            creates_nothing: false,
        },
        Some(&environment(f)),
    )
    .minimum_action
}

#[test]
fn a_variable_bound_after_a_leading_cd_reads_as_its_file() {
    let f = fixture();
    for command in [
        "cd . && f=src/lib/a.ts; sed -n 1,5p $f; sed -n 6,9p $f; grep -n \"export\" -B2 $f | head -8",
        "cd src && f=lib/a.ts; sed -n 1,5p $f; wc -l \"$f\"",
        "cd src/lib && f=a.ts && g=a.ts; sed -n 1,5p $f; grep -n export $g",
    ] {
        for harness in HARNESSES {
            assert_eq!(action(&f, harness, command), "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn a_variable_holding_a_home_path_reads_as_its_file() {
    let f = fixture();
    for command in [
        "f=~/notes/plan.md; sed -n 1,5p $f; sed -n 6,9p $f | cut -c1-600",
        "f=~/notes/plan.md && wc -l \"$f\"",
        "f=~/.codex/plans/plan-todo.md; sed -n 1,5p $f; sed -n 1,3p $f | cut -c1-600",
        "cd . && f=~/notes/plan.md; grep -n Steps ${f}",
    ] {
        for harness in HARNESSES {
            assert_eq!(
                action(&f, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
    // The same note named by its absolute path, which passes through the
    // hyphenated fixture directory.
    let plan = f.home.join(".codex/plans/plan-todo.md");
    let command = format!(
        "f={}; sed -n 1,5p $f; sed -n 1,3p $f | cut -c1-600",
        plan.display()
    );
    for harness in HARNESSES {
        assert_eq!(
            action(&f, harness, &command),
            "allow",
            "{harness}: {command}"
        );
    }
}

#[test]
fn a_variable_the_shell_may_not_hold_keeps_its_review() {
    let f = fixture();
    for command in [
        // The `cd` can fail, so the assignment behind it may never run.
        "cd missing && f=src/lib/a.ts; sed -n 1,5p $f",
        // The tilde names a key file.
        "f=~/.ssh/id_ed25519; sed -n 1,5p $f",
        "cd ~/.ssh && f=id_ed25519; sed -n 1,5p $f",
        // The command sets HOME, so the tilde may name another directory.
        "HOME=/etc; f=~/passwd; sed -n 1,5p $f",
        "export HOME=/etc && f=~/passwd; sed -n 1,5p $f",
        // A quoted tilde stays a tilde, and `~name` is another user's home.
        "f=\"~/notes/plan.md\"; sed -n 1,5p $f",
        "f=~root/.profile; sed -n 1,5p $f",
        // A bare tilde holds HOME as the shell spells it, which may differ
        // from the declared home in a way a joined suffix can see.
        "f=~; sed -n 1,5p ${f}/notes/plan.md",
        "f=~ && wc -l \"$f/notes/plan.md\"",
    ] {
        for harness in HARNESSES {
            assert_ne!(
                action(&f, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
