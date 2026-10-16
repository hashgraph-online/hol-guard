use crate::pretool::workspace_contained_tests::workspace;
use std::path::Path;

/// The stand-in `chain_literals_inert.rs` writes for `"$(mktemp -d)"`.
const STAND_IN: &str = "/hol-guard-substituted/temporary-path";

fn shaped(command: &str, workspace: &Path) -> bool {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .unwrap();
    super::super::command_shape(&model, workspace, Some(command)).is_some()
}

#[test]
fn the_temporary_stand_in_is_bounded_only_as_a_cd_operand() {
    let ws = workspace("temp-cd-shape", true);
    let (t, w) = (STAND_IN, ws.display());
    for command in [
        format!("cd \"{t}\" && TODO_FILE=t.json node {w}/src/cli.js list"),
        format!("pushd {t} && ls"),
    ] {
        assert!(shaped(&command, &ws), "{command}");
    }
    for command in [
        format!("ls {t}"),
        format!("cd {t} && cat {t}/x"),
        format!("cd {t}/sub && ls"),
        format!("cd {t} {t}"),
        format!("export TMPDIR=/etc; cd {t} && ls"),
        format!("cd {t} && node {w}/src/cli.js > /etc/x"),
        "cd /etc && ls".to_owned(),
    ] {
        assert!(!shaped(&command, &ws), "{command}");
    }
}

/// The launcher re-derives the shape from the raw text and runs it whole, so
/// the real `mktemp` creates its directory under the sandbox's `TMPDIR`.
#[cfg(unix)]
#[test]
fn the_launcher_runs_the_raw_text_that_enters_a_private_directory() {
    let ws = workspace("temp-cd-launcher", true);
    let w = ws.display();
    let raw = format!(
        "node --test 2>&1 | tail -12; cd \"$(mktemp -d)\" && TODO_FILE=t.json node {w}/src/cli.js add Hello world && TODO_FILE=t.json node {w}/src/cli.js list"
    );
    let shape = crate::restricted_pytest::workspace_exact_shape(&raw, &ws).unwrap();
    assert!(shape.bootstrap.is_none() && shape.prefix.is_none() && shape.remainder.is_none());
    for command in [
        "cd \"$(mktemp -d)\" && cat ../x",
        "TMPDIR=/etc; cd \"$(mktemp -d)\" && ls",
        "cd \"$(mktemp -d /etc/XXX)\" && ls",
        "cd \"$(mktemp -d -p /)\" && ls",
        "cd \"$(whoami)\" && ls",
        "ls \"$(mktemp -d)\"",
    ] {
        assert!(
            crate::restricted_pytest::workspace_exact_shape(command, &ws).is_none(),
            "{command}"
        );
    }
    // A bootstrapped `git init` would run a rewritten remainder, not the raw
    // text the projection judged.
    let fresh = workspace("temp-cd-fresh", false);
    assert!(crate::restricted_pytest::workspace_exact_shape(
        "git init && cd \"$(mktemp -d)\" && ls",
        &fresh
    )
    .is_none());
}

#[test]
fn the_temporary_stand_in_is_bounded_as_a_private_assignment() {
    let ws = workspace("temp-assign-shape", true);
    let (t, w) = (STAND_IN, ws.display());
    for command in [
        format!(
            "export TODO_FILE={t}/t.json; node {w}/src/cli.js add Try it; node {w}/src/cli.js list"
        ),
        format!("TODO_FILE=\"{t}/t.json\" && node {w}/src/cli.js list"),
        format!("export OUT={t}; cd {t} && ls"),
    ] {
        assert!(shaped(&command, &ws), "{command}");
    }
    for command in [
        format!("export PATH={t}; ls"),
        format!("export GIT_DIR={t}; git status"),
        format!("export NODE_OPTIONS={t}; node {w}/src/cli.js list"),
        format!("LD_PRELOAD={t}/x.so; ls"),
        format!("export X={t}/../y; ls"),
        format!("export X={t}; rm -rf \"$X\""),
        format!("export X={t}; ls {t}"),
        format!("X={t}; X={t}; ls"),
        format!("X={t} node {w}/src/cli.js list"),
        format!("export TMPDIR=/etc; X={t}; ls"),
        format!("declare X={t}; ls"),
        format!("export -n X={t}; ls"),
        format!("export X={t} Y=1; ls"),
    ] {
        assert!(!shaped(&command, &ws), "{command}");
    }
}

/// The launcher accepts the raw `export NAME=$(mktemp -d)/...` it will run.
#[cfg(unix)]
#[test]
fn the_launcher_runs_the_raw_text_that_assigns_a_private_directory() {
    let ws = workspace("temp-assign-launcher", true);
    for raw in [
        "node --test test/ 2>&1 | tail -10; export TODO_FILE=$(mktemp -d)/t.json; node src/cli.js add Try it; node src/cli.js done 1; node src/cli.js list",
        "TODO_FILE=\"$(mktemp -d)/t.json\" && node src/cli.js list",
        // A file written from a quoted heredoc, its template literal data.
        "cat > src/url.js <<'EOF'\nexport const url = `file://${process.argv[1]}`;\nEOF\nexport TODO_FILE=$(mktemp -d)/t.json\nnode src/cli.js list",
        // A builtin-only program fed to `python3 -` from a quoted heredoc.
        "python3 - <<'EOF'\nprint(1)\nEOF\nexport X=$(mktemp -d)/t.json\nls",
    ] {
        let shape = crate::restricted_pytest::workspace_exact_shape(raw, &ws).unwrap();
        assert!(shape.bootstrap.is_none() && shape.prefix.is_none() && shape.remainder.is_none());
    }
    for command in [
        "export PATH=$(mktemp -d); ls",
        "export GIT_DIR=$(mktemp -d); git status",
        "export X=$(mktemp -d); rm -rf \"$X\"",
        "export X=$(mktemp -d)/../x; ls",
        "export X=$(whoami); ls",
        "X=$(mktemp -d) ls",
        "declare X=$(mktemp -d); ls",
        "TMPDIR=/etc; export X=$(mktemp -d); ls",
        "export X=$(mktemp -d)\nrm -rf \"$X\"",
        "cat > run.sh <<EOF\ncd $(mktemp -d)\nEOF\nsh run.sh",
        // Any other program fed to an interpreter on stdin.
        "python3 - <<'EOF'\nimport subprocess\nEOF\nexport X=$(mktemp -d)/t.json\nls",
        "python3 - <<EOF\nprint(1)\nEOF\nexport X=$(mktemp -d)/t.json\nls",
        "python3 <<'EOF'\nprint(1)\nEOF\nexport X=$(mktemp -d)/t.json\nls",
        "sh <<'EOF'\necho 1\nEOF\nexport X=$(mktemp -d)/t.json\nls",
        "node - <<'EOF'\nconsole.log(1)\nEOF\nexport X=$(mktemp -d)/t.json\nls",
    ] {
        assert!(
            crate::restricted_pytest::workspace_exact_shape(command, &ws).is_none(),
            "{command}"
        );
    }
}
