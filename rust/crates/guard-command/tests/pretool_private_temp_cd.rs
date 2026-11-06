//! An agent smoke-tests a CLI in a scratch directory with
//! `cd "$(mktemp -d)" && node <workspace>/src/cli.js add ...`. Inside the
//! workspace sandbox `mktemp -d` creates that directory under the run's
//! private `TMPDIR`, so the chain runs contained instead of waiting on a
//! review. The same holds for `export TODO_FILE=$(mktemp -d)/t.json` run as
//! its own command, and for `tmp=$(mktemp -d) && python3 todo.py --file
//! "$tmp/tasks.json" list` when every later use follows `&&`. A steered, climbed or misplaced temporary directory, a
//! sensitive or reused variable name, and any other substitution, stays out
//! of the sandbox. A quoted heredoc may feed `python3 -` a script that uses
//! only Python builtins; any other heredoc program keeps the command out.
#![cfg(unix)]

use crate::git_helper_fixture as fixture;

use fixture::{evaluate_with_node_and_python, git_github_controls, FixtureCleanup};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const CONTAINED: &str = "native_workspace_containment_required";

/// Home is the fixture root and the project sits below it, outside every
/// temporary root, so the project is an admissible sandbox workspace.
fn fixture(name: &str) -> (PathBuf, PathBuf, FixtureCleanup) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/private-temp-cd-tests")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    let project = root.join("project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::create_dir_all(project.join("test")).unwrap();
    std::fs::write(
        project.join("package.json"),
        "{\"name\":\"todo\",\"type\":\"module\"}\n",
    )
    .unwrap();
    std::fs::write(
        project.join("src/cli.js"),
        "console.log(process.argv.length);\n",
    )
    .unwrap();
    std::fs::write(
        project.join("test/cli.test.js"),
        "import test from 'node:test';\ntest('runs', () => {});\n",
    )
    .unwrap();
    let home = root.canonicalize().unwrap();
    let project = project.canonicalize().unwrap();
    (home.clone(), project, FixtureCleanup(home))
}

fn evaluate(home: &Path, project: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_with_node_and_python(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        Some(&git_github_controls("default", "default")),
        home,
        project.to_str(),
    )
}

#[test]
fn a_cli_smoke_test_in_a_fresh_temporary_directory_runs_contained() {
    let (home, project, _cleanup) = fixture("contained");
    let w = project.display();
    let command = format!(
        "node --test 2>&1 | tail -12; cd \"$(mktemp -d)\" && TODO_FILE=t.json node {w}/src/cli.js add Hello world && TODO_FILE=t.json node {w}/src/cli.js list"
    );
    let result = evaluate(&home, &project, &command);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason);
    if cfg!(target_os = "macos") {
        assert_eq!(
            result.minimum_action, "sandbox-required",
            "{}",
            result.reason
        );
        assert_eq!(result.reason_code, CONTAINED, "{}", result.reason);
    }
}

#[test]
fn steered_misplaced_or_other_substitutions_stay_out_of_the_sandbox() {
    let (home, project, _cleanup) = fixture("refused");
    let w = project.display();
    for command in [
        "cd \"$(mktemp -d)\" && cat ../x".to_owned(),
        format!("TMPDIR=/etc; cd \"$(mktemp -d)\" && node {w}/src/cli.js list"),
        format!("cd \"$(mktemp -d /etc/XXX)\" && node {w}/src/cli.js list"),
        format!("cd \"$(mktemp -d -p /)\" && node {w}/src/cli.js list"),
        format!("cd \"$(whoami)\" && node {w}/src/cli.js list"),
        format!("cd \"$(mktemp -d)\" && node {w}/src/cli.js > /etc/x"),
    ] {
        let result = evaluate(&home, &project, &command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
        assert_ne!(
            result.reason_code, CONTAINED,
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn a_cli_smoke_test_with_a_private_temporary_variable_runs_contained() {
    let (home, project, _cleanup) = fixture("assigned");
    for command in [
        "node --test test/ 2>&1 | tail -10; export TODO_FILE=$(mktemp -d)/t.json; node src/cli.js add Try it; node src/cli.js done 1; node src/cli.js list",
        "TODO_FILE=\"$(mktemp -d)/t.json\" && node src/cli.js add Try it && node src/cli.js list",
    ] {
        let result = evaluate(&home, &project, command);
        assert_ne!(result.minimum_action, "allow", "{command}: {}", result.reason);
        if cfg!(target_os = "macos") {
            assert_eq!(
                result.minimum_action, "sandbox-required",
                "{command}: {}",
                result.reason
            );
            assert_eq!(result.reason_code, CONTAINED, "{command}: {}", result.reason);
        }
    }
}

#[test]
fn a_script_smoke_test_reusing_a_fresh_temporary_directory_runs_contained() {
    let (home, project, _cleanup) = fixture("expanded");
    std::fs::write(project.join("todo.py"), "import sys\nprint(sys.argv)\n").unwrap();
    let command = "tmp=$(mktemp -d) && python3 todo.py --file \"$tmp/tasks.json\" add \"Test task\" && python3 todo.py --file \"$tmp/tasks.json\" list && python3 todo.py --file \"$tmp/tasks.json\" done 1 && python3 todo.py --file \"$tmp/tasks.json\" delete 1 && python3 todo.py --file \"$tmp/tasks.json\" list";
    let result = evaluate(&home, &project, command);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason);
    if cfg!(target_os = "macos") {
        assert_eq!(
            result.minimum_action, "sandbox-required",
            "{}",
            result.reason
        );
        assert_eq!(result.reason_code, CONTAINED, "{}", result.reason);
    }
}

#[test]
fn a_fresh_temporary_directory_reused_unsafely_stays_out_of_the_sandbox() {
    let (home, project, _cleanup) = fixture("expanded-refused");
    std::fs::write(project.join("todo.py"), "import sys\nprint(sys.argv)\n").unwrap();
    for command in [
        "tmp=$(mktemp -d); python3 todo.py --file \"$tmp/t.json\" list",
        "tmp=$(mktemp -d) || python3 todo.py --file \"$tmp/t.json\" list",
        "tmp=$(mktemp -d) && tmp=/etc && python3 todo.py --file \"$tmp/t.json\" list",
        "tmp=$(mktemp -d) && python3 todo.py --file \"${tmp:-/etc}/t.json\" list",
        "tmp=$(mktemp -d) && cd \"$tmp\" && python3 todo.py list > ../../x",
        // `mktemp -dq` needs review as a command of its own.
        "tmp=$(mktemp -dq) && python3 todo.py --file \"$tmp/t.json\" list",
    ] {
        let result = evaluate(&home, &project, command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
        assert_ne!(
            result.reason_code, CONTAINED,
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn sensitive_reused_or_misplaced_temporary_variables_stay_out_of_the_sandbox() {
    let (home, project, _cleanup) = fixture("assigned-refused");
    let mut commands: Vec<String> = [
        "TMPDIR",
        "PATH",
        "HOME",
        "GIT_DIR",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "NODE_OPTIONS",
        "BASH_ENV",
        "ENV",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PERL5OPT",
        "RUBYOPT",
        "PROMPT_COMMAND",
        "IFS",
        "SHELLOPTS",
        "CDPATH",
    ]
    .iter()
    .map(|name| format!("export {name}=$(mktemp -d)/x; node src/cli.js list"))
    .collect();
    commands.extend(
        [
            "export TODO_FILE=$(mktemp -d)/../t.json; node src/cli.js list",
            "export TODO_FILE=$(mktemp -d)/t.json; rm -rf \"$TODO_FILE\"",
            "export TODO_FILE=$(mktemp -d); cat $TODO_FILE/../x",
            "export TODO_FILE=$(whoami)/t.json; node src/cli.js list",
            "export TODO_FILE=$(mktemp -d -p /)/t.json; node src/cli.js list",
            "TODO_FILE=$(mktemp -d)/t.json node src/cli.js list",
            "export -n TODO_FILE=$(mktemp -d)/t.json; node src/cli.js list",
            "export -f TODO_FILE=$(mktemp -d)/t.json; node src/cli.js list",
            "declare TODO_FILE=$(mktemp -d)/t.json; node src/cli.js list",
            "readonly TODO_FILE=$(mktemp -d)/t.json; node src/cli.js list",
            "local TODO_FILE=$(mktemp -d)/t.json; node src/cli.js list",
            "export TODO_FILE=$(mktemp -d)/t.json; node src/cli.js > /etc/x",
        ]
        .map(str::to_owned),
    );
    for command in commands {
        let result = evaluate(&home, &project, &command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
        assert_ne!(
            result.reason_code, CONTAINED,
            "{command}: {}",
            result.reason
        );
    }
}

/// The command an agent sent: a quoted heredoc script that patches
/// `src/cli.js` using only Python builtins, the test run, then the smoke test
/// on its own line.
const SENT: &str = "python3 - <<'EOF'\np='src/cli.js'\ns=open(p).read()\ns=s.replace(\"import { load, save } from './storage.js';\",\"import { realpathSync } from 'node:fs';\\nimport { pathToFileURL } from 'node:url';\\nimport { load, save } from './storage.js';\")\ns=s.replace(\"if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('cli.js')) {\",\"if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {\")\nopen(p,'w').write(s)\nEOF\nnode --test test/ 2>&1 | tail -10\nexport TODO_FILE=$(mktemp -d)/t.json; node src/cli.js add Try it; node src/cli.js done 1; node src/cli.js list";

#[test]
fn a_multi_line_smoke_test_after_a_quoted_heredoc_runs_contained() {
    let (home, project, _cleanup) = fixture("assigned-lines");
    let w = project.display();
    for command in [
        SENT.to_owned(),
        format!("node --test test/ 2>&1 | tail -10\ncd \"$(mktemp -d)\"\nTODO_FILE=t.json node {w}/src/cli.js list"),
        "cat > src/url.js <<'EOF'\nexport const main = (url) => url === `file://${process.argv[1]}`;\nEOF\nnode --test test/ 2>&1 | tail -10\nexport TODO_FILE=$(mktemp -d)/t.json; node src/cli.js add Try it; node src/cli.js done 1; node src/cli.js list".to_owned(),
        // Files written as data may name the variable the smoke test sets.
        "cat > README.md <<'EOF'\n# Todo\nSet `TODO_FILE` to choose the store.\nEOF\ncat > src/store.js <<'EOF'\nexport const file = process.env.TODO_FILE;\nEOF\nnode --test test/ 2>&1 | tail -10\nexport TODO_FILE=$(mktemp -d)/t.json; node src/cli.js add Try it; node src/cli.js list".to_owned(),
    ] {
        let result = evaluate(&home, &project, &command);
        assert_ne!(result.minimum_action, "allow", "{command}: {}", result.reason);
        if cfg!(target_os = "macos") {
            assert_eq!(result.reason_code, CONTAINED, "{command}: {}", result.reason);
        }
    }
}

#[test]
fn a_program_fed_to_an_interpreter_or_an_expanding_heredoc_stays_out_of_the_sandbox() {
    let (home, project, _cleanup) = fixture("assigned-heredocs");
    let script = SENT.split_once("\nEOF\n").unwrap().1;
    let mut commands = vec![
        // A script that can start a program, or a substitution that runs
        // more than `mktemp -d`, in the same chain.
        format!("python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['gh','pr','list'])\nEOF\n{script}"),
        SENT.replace("$(mktemp -d)", "$(mktemp -d; gh pr list)"),
        SENT.replace("$(mktemp -d)", "$(mktemp $x)"),
        SENT.replace("python3 - <<'EOF'", "sh <<'EOF'"),
        SENT.replace("python3 - <<'EOF'", "python3 - <<EOF"),
    ];
    commands.extend(
        [
        // An unquoted heredoc expands its substitutions.
        "cat > run.sh <<EOF\n$(whoami)\nEOF\nexport TODO_FILE=$(mktemp -d)/t.json; node src/cli.js list",
        // The stand-in used inside a heredoc body.
        "cat > run.sh <<EOF\ncd $(mktemp -d)\nEOF\nsh run.sh",
        // A body piped to a program rather than written to a file.
        "export TODO_FILE=$(mktemp -d)/t.json\ncat <<'EOF' | sh\nrm -rf \"$TODO_FILE\"\nEOF",
        // A later use on its own line.
        "export TODO_FILE=$(mktemp -d)/t.json\nrm -rf \"$TODO_FILE\"",
        // A heredoc that never closes.
        "export TODO_FILE=$(mktemp -d)/t.json\ncat > f <<'EOF'\nnode src/cli.js list",
        ]
        .map(str::to_owned),
    );
    for command in commands {
        let result = evaluate(&home, &project, &command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
        assert_ne!(
            result.reason_code, CONTAINED,
            "{command}: {}",
            result.reason
        );
    }
}
