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
    let shape = crate::pretool::workspace_exact_shape(&raw, &ws).unwrap();
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
            crate::pretool::workspace_exact_shape(command, &ws).is_none(),
            "{command}"
        );
    }
    // A bootstrapped `git init` would run a rewritten remainder, not the raw
    // text the projection judged.
    let fresh = workspace("temp-cd-fresh", false);
    assert!(
        crate::pretool::workspace_exact_shape("git init && cd \"$(mktemp -d)\" && ls", &fresh)
            .is_none()
    );
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
        let shape = crate::pretool::workspace_exact_shape(raw, &ws).unwrap();
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
            crate::pretool::workspace_exact_shape(command, &ws).is_none(),
            "{command}"
        );
    }
}

/// Going into a directory, working there and climbing back is how a developer
/// visits one package of a checkout. The climb leaves no operand that reads
/// as staying inside on its own, so each `cd` used to be judged alone and the
/// whole chain fell out of containment. The walk reads the chain instead: it
/// joins every move onto the directory before it, so a climb that lands back
/// in the workspace is a directory the sandbox already bounds.
#[test]
fn a_chain_that_climbs_back_into_the_workspace_is_still_bounded() {
    let ws = workspace("cd-return", true);
    for name in ["app", "web"] {
        std::fs::create_dir_all(ws.join(name)).unwrap();
        std::fs::write(ws.join(name).join("package.json"), "{}").unwrap();
    }
    std::fs::create_dir_all(ws.join("app/src")).unwrap();
    for command in [
        "cd app && ls && cd ..",
        "cd app && cd ..",
        // A pipeline is one element of the list: the `&&` at its head governs
        // every segment in it, so the climb after it still starts one
        // directory down.
        "cd app && ls 2>&1 | tail -5 && cd ..",
        "cd app && ls && cd ../web && ls",
        "cd app/src && ls && cd ../..",
        // A `;` runs the climb whatever the work did. The only branch it
        // leaves the workspace on is the one whose first `cd` failed, which
        // never descended and runs nothing afterwards.
        "cd app && ls; cd ..",
    ] {
        assert!(shaped(command, &ws), "{command}");
    }
    // The walk proves where each move lands, so a climb out of the workspace,
    // a move to a directory that is not there, and an operand naming a place
    // the walk never joined are all refused as before.
    let outside = Path::new("/etc").display();
    for command in [
        "ls && cd ..".to_owned(),
        "ls 2>&1 | tail -5 && cd ..".to_owned(),
        "cd app && ls && cd ../..".to_owned(),
        format!("cd app && ls && cd {outside}"),
        "cd app && ls && cd ../missing-name".to_owned(),
        // `cd -` is the one stand-in the walk follows, since it carries the
        // directory each shell moved out of;
        // `a_return_to_the_previous_directory_follows_the_move_the_walk_saw`
        // covers it. An `$OLDPWD` spelling is an expansion the walk never
        // reads, so it stays out.
        "cd app && ls && cd $OLDPWD".to_owned(),
        // A `;` resumes the branch whose `cd` failed as well, and a climb
        // from there is a step out — but only a step, with nothing left to
        // run from it.
        // `a_climb_that_only_leaves_where_the_descent_failed_stays_contained`
        // holds that reading, and keeps the spellings that do run something
        // after the climb out.
        "cd app && ls; cd ..; ls".to_owned(),
        "CDPATH=/ cd app && ls && cd ..".to_owned(),
    ] {
        assert!(!shaped(&command, &ws), "{command}");
    }
}

/// A shell spends a parent step on the name it last printed rather than on
/// what that name points to, so a chain that enters a link and climbs twice
/// leaves the workspace while resolving the link first lands back inside it.
/// A pattern is not the name of the directory entered either, and the last
/// element of a pipeline may be read by the shell itself, so neither shape
/// carries the walk.
#[test]
fn a_move_the_walk_cannot_read_as_the_shell_does_is_refused() {
    let ws = workspace("cd-walk-divergence", true);
    std::fs::create_dir_all(ws.join("a/b")).unwrap();
    std::fs::create_dir_all(ws.join("app")).unwrap();
    std::fs::create_dir_all(ws.join("x*")).unwrap();
    std::fs::create_dir_all(ws.join("{1..1}")).unwrap();
    std::os::unix::fs::symlink(ws.join("a/b"), ws.join("deep")).unwrap();
    std::os::unix::fs::symlink(Path::new("/etc"), ws.join("1")).unwrap();
    for command in [
        // `deep` names a link to `a/b`, so the shell stands two steps from
        // the workspace root by its own reckoning and one by the resolved
        // one; the climb out has to be read the shell's way.
        "cd deep && ls && cd ../..",
        // The shell hands `cd` whatever the pattern matched, which the walk
        // cannot take for the literal directory of that name.
        "cd x* && ls",
        "cd app && ls && cd ../x*",
        // A brace list is rewritten before the file system is consulted at
        // all, so the walk clears the literal directory `{1..1}` while the
        // run enters `1`, which is a link out of the workspace.
        "cd {1..1} && ls",
        "cd app && ls && cd ../{1..1}",
        // bash's `lastpipe` and zsh's default both run the last element of a
        // pipeline in the shell that read it, so this `cd ..` may be the
        // shell's own move and the climb after it a second one.
        "cd app && ls | cd .. && cd ..",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
    // One step in and one step back through the same link is still the
    // directory the sandbox bounds.
    assert!(shaped("cd deep && ls && cd ..", &ws));
}

/// Only the shell's own `cd` moves the shell. A program in the workspace that
/// carries the builtin's name is an ordinary executable, and the walk never
/// moved for it, so its operand is read as the path it is.
#[test]
fn a_program_named_after_the_builtin_earns_no_move_exemption() {
    let ws = workspace("cd-lookalike", true);
    std::fs::create_dir_all(ws.join("app")).unwrap();
    for command in [
        "cd app && ./cd /etc/passwd",
        "cd app && ./cd /etc",
        "cd app && bin/cd /etc/passwd",
        "cd app && ./pushd /etc/passwd",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// Git's metadata belongs to `git`. The reach check refuses that directory to
/// every other program, and a move into it must not carry the name past that
/// refusal for whatever runs next.
#[test]
fn a_move_into_git_metadata_is_refused() {
    let ws = workspace("cd-git-metadata", true);
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::create_dir_all(ws.join("app/.git")).unwrap();
    for command in [
        "cd .git && cat config",
        "cd .git && ls",
        "cd app/.git && cat config",
        "cd app && cd ../.git && cat config",
        "pushd .git && cat config",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}
