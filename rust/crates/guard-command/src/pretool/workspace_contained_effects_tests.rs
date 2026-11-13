//! Workspace file effects inside the sandbox.
//!
//! A write under the private temp directory, a recursive removal of ignored or
//! missing targets, and a truncation of a workspace file are the effects the
//! sandbox bounds, while a target it cannot hold to the workspace is refused
//! for the target. These read the same route as their neighbours in
//! [`super::workspace_contained_tests`].

use super::workspace_contained_tests::{controls, host, reason, workspace, CONTAINED};
use std::path::Path;

/// The host `PATH`, led by a Node the sandbox may run. Hosted runners keep
/// Node where the sandbox will not execute from, so a version manager's
/// directory under `home` stands in for it.
#[cfg(unix)]
fn path_with_node(home: &Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    let bin = home.join(".nvm/versions/node/v25.2.1/bin");
    std::fs::create_dir_all(&bin).unwrap();
    for name in ["node", "npm"] {
        let tool = bin.join(name);
        std::fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap())
}

#[cfg(not(unix))]
fn path_with_node(_home: &Path) -> String {
    std::env::var("PATH").unwrap()
}

#[test]
fn private_temp_paths_run_in_the_workspace_sandbox() {
    let ws = workspace("private-temp", true);
    for command in [
        "OUT_DIR=\"$TMPDIR/report-test\" npm run build",
        "OUT_DIR=\"${TMPDIR}/report-test\" npm run build",
        "OUT_DIR=$TMPDIR/report-test PORT=4173 npm run build",
        "OUT_DIR=\"${TMPDIR:-/tmp}/report-test\" npm run build",
    ] {
        assert_eq!(
            reason("omp", command, &ws, true) == CONTAINED,
            host(),
            "{command}"
        );
    }
    // A runner reaches the sandbox only once its tool is installed, since
    // `bunx` would otherwise fetch it; macOS may claim it with a narrower
    // node profile first.
    let runner = "OUT_DIR=\"$TMPDIR/report-test\" bunx vitest run src/report.test.ts";
    assert_ne!(reason("omp", runner, &ws, true), CONTAINED);
    std::fs::create_dir_all(ws.join("node_modules/.bin")).unwrap();
    std::fs::write(ws.join("node_modules/.bin/vitest"), "#!/bin/sh\n").unwrap();
    if cfg!(target_os = "linux") && host() {
        assert_eq!(reason("omp", runner, &ws, true), CONTAINED);
    }
    // Another variable, a rebound TMPDIR, a default or a command
    // substitution could name a host directory, and a single-quoted `$` is
    // left for the program to expand.
    for command in [
        "OUT_DIR=\"$HOME/report-test\" npm run build",
        "OUT_DIR=\"$TMPDIR/$(id -un)\" npm run build",
        "OUT_DIR=\"$TMPDIR/`id -un`\" npm run build",
        "OUT_DIR=\"${TMPDIR:-/Users/nobody}/x\" npm run build",
        "OUT_DIR=\"$TMPDIRS/x\" npm run build",
        "OUT_DIR='$TMPDIR/x' npm run build",
        "TMPDIR=/Users/nobody/.ssh OUT_DIR=\"$TMPDIR/x\" npm run build",
        "export TMPDIR=/Users/nobody && OUT_DIR=\"$TMPDIR/x\" npm run build",
        "OUT_DIR=\"$HOME/x\" bunx vitest run src/report.test.ts",
        "TMPDIR=/Users/nobody OUT_DIR=\"$TMPDIR/x\" bunx vitest run src/report.test.ts",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn recursive_removal_runs_in_the_sandbox_only_for_ignored_or_missing_targets() {
    let root = std::env::temp_dir().join(format!("guard-ws-{}-removal", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (home, repo) = (root.join("home"), root.join("repo"));
    for directory in [&home, &repo.join("dist"), &repo.join("src")] {
        std::fs::create_dir_all(directory).unwrap();
    }
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repo)
        .status()
        .unwrap()
        .success());
    std::fs::write(repo.join(".gitignore"), "dist/\n").unwrap();
    std::fs::write(repo.join("dist/out.js"), "1").unwrap();
    std::fs::write(repo.join("src/a.ts"), "1").unwrap();
    let (home, repo) = (home.canonicalize().unwrap(), repo.canonicalize().unwrap());
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: path_with_node(&home),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: home.to_str().map(str::to_owned),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        ..Default::default()
    };
    let controls = controls();
    let reason = |command: &str| {
        crate::pretool::evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls),
            None,
            crate::pretool::PathContext {
                home_dir: home.to_str(),
                cwd: repo.to_str(),
                ..Default::default()
            },
            Some(&environment),
        )
        .reason_code
    };
    // Git answers for a lone recursive removal of a missing target on every
    // platform, before the sandbox is asked. Git cannot restore ignored
    // files, so `dist` is left to the sandbox.
    let missing = "rm -rf coverage";
    assert_eq!(
        reason(missing),
        "native_exact_safe_recoverable_removal",
        "{missing}"
    );
    for command in [
        "rm -rf dist",
        "rm -rf dist && npm run build",
        "rm src/a.ts",
        "rm -f src/a.ts dist/out.js",
        "sed --in-place=.orig -n 'p' src/a.ts && rm -f src/a.ts.orig",
    ] {
        let got = reason(command);
        if host() {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
    // A plain substitution on a workspace file is proven on the host. The
    // GNU operand form is proven only where GNU sed parses it that way.
    for (command, proven) in [
        ("sed -i 's/1/2/' src/a.ts", cfg!(target_os = "linux")),
        ("sed -i '' -e 's/1/2/g' src/a.ts", true),
        ("sed -E -i.bak 's/(1)/2/' src/a.ts", true),
    ] {
        let got = reason(command);
        if proven {
            assert_eq!(got, "native_exact_safe_command", "{command}");
        } else if host() {
            assert_eq!(got, CONTAINED, "{command}");
        }
    }
    // The `e` flag runs the pattern space as a command; it is never proven.
    let exec = "sed -i '' 's/1/2/e' src/a.ts";
    assert_ne!(reason(exec), "native_exact_safe_command", "{exec}");
    // A tracked or unknown tree may hold uncommitted work the sandbox would
    // write back as deleted. `truncate` rewrites one file in place the way
    // `sed -i` above does, so it reaches the sandbox instead; see
    // `truncating_a_workspace_file_runs_in_the_workspace_sandbox`.
    for command in [
        "rm -rf src",
        "rm -rf src 2>&1",
        "rm -rf dist src",
        "rm -rf *.egg-info",
        "npm run build && rm -rf dist",
        // Perl's script can move source work into the ignored tree first.
        "perl -i -e 'rename(q(src/a.ts), q(dist/a.ts))' && rm -rf dist",
        "cd src && rm -rf .",
        "rm -rf $DIR",
        "shred -u src/a.ts",
        "rm --no-preserve-root -rf dist",
        "GLOBIGNORE=x rm -rf dist",
        "sed --follow-symlinks -i 's/1/2/' src/a.ts",
        "LC_ALL=C sed -i 's/1/2/' src/a.ts",
    ] {
        assert_ne!(reason(command), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// `truncate -s 0 log` empties a file the way `> log` does, and `truncate -s
/// 1M blob` grows one the way a write does. Both are the sandbox's ordinary
/// workspace write, so they reach it like the removal they stand next to,
/// while a target outside the workspace is refused for the target.
#[test]
fn truncating_a_workspace_file_runs_in_the_workspace_sandbox() {
    let ws = workspace("truncate", true);
    std::fs::create_dir_all(ws.join("logs")).unwrap();
    std::fs::write(ws.join("logs/app.log"), "old\n").unwrap();
    for command in [
        "truncate -s 0 logs/app.log",
        "truncate -s0 logs/app.log",
        "truncate --size 0 logs/app.log",
        "truncate --size=0 logs/app.log",
        "truncate -c -s 0 logs/app.log",
        "truncate -s 1M data/blob.bin",
        "truncate -r logs/app.log logs/copy.log",
        "truncate -s 0 -- logs/app.log",
    ] {
        let got = reason("omp", command, &ws, true);
        if host() {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
    for command in [
        "truncate -s 0 /etc/hosts",
        "truncate -s 0 ../outside.txt",
        "truncate -s 0 ~/.bashrc",
        "truncate -s 0 $HOME/.bashrc",
        "truncate -s 0 .git/config",
        // A reference attached to its own option is skipped by the reach
        // check, so the spelling is refused instead of read as a bare size.
        "truncate -r/etc/passwd logs/app.log",
        "truncate --reference=/etc/passwd logs/app.log",
        // The shell picks what a pattern names, and these select inside
        // `.git` while their literal spelling does not say so.
        "truncate -s 0 .*/*",
        "truncate -s 0 logs/*.log",
        // An option neither spelling documents could mean anything.
        "truncate -z 0 logs/app.log",
        "truncate --follow logs/app.log",
        // With no operand there is no target to hold to the workspace.
        "truncate -s 0",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

/// `perl -i -pe 's/a/b/' file` is the same in-place edit as `perl -pi -e`.
/// The destructive-shell rule flags the first spelling and not the second,
/// so the sandbox accepts the flag for perl the way it does for `sed -i`.
/// Perl runs its script there like any other perl program, and the reach
/// check still holds each file to the workspace.
#[test]
fn a_perl_in_place_edit_runs_in_the_workspace_sandbox() {
    let ws = workspace("perl-in-place", true);
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::write(ws.join("src/a.py"), "x = _old\n").unwrap();
    for command in [
        "perl -i -pe 's/_old/_new/g' src/a.py",
        "perl -i -p -e 's/_old/_new/g' src/a.py",
        "perl -i.bak -pe 's/_old/_new/g' src/a.py",
        "perl -pe 's/_old/_new/g' -i src/a.py",
        "perl -pi -e 's/(?<![\\w-])_old(?![\\w-])/_new/g' src/a.py",
        "perl -i -pe 's/_old/_new/g' src/a.py && rm -f src/a.py.bak",
    ] {
        let got = reason("omp", command, &ws, true);
        if host() {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
    for command in [
        "perl -i -pe 's/a/b/' ~/.bashrc",
        "perl -i -pe 's/a/b/' $HOME/.bashrc",
        "perl -i -pe 's/a/b/' ../outside.py",
        "perl -i -pe 's/a/b/' /etc/hosts",
        "perl -i -pe 's/a/b/' .git/config",
        "PERL5OPT=-Mevil perl -i -pe 's/a/b/' src/a.py",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

/// The script of an in-place edit is not a target, so braces in it are not a
/// glob at the workspace root. A real root glob is still refused.
#[test]
fn braces_in_an_in_place_edit_script_are_not_a_root_glob() {
    let ws = workspace("edit-script-braces", true);
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::write(ws.join("src/a.tsx"), "href={OLD}\n").unwrap();
    for command in [
        "perl -i -pe 's|href={OLD}|href={NEW}|g' src/a.tsx",
        "perl -pi -e 's/a{2}/b/' src/a.tsx",
        "perl -pe 's|{OLD}|{NEW}|' -i src/a.tsx",
        "sed -i 's|href={OLD}|href={NEW}|g' src/a.tsx",
        "sed -i -e 's|{OLD}|{NEW}|' src/a.tsx",
        "sed -i.bak --expression 's|{OLD}|{NEW}|' src/a.tsx",
    ] {
        let got = reason("omp", command, &ws, true);
        if host() {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
    for command in [
        "perl -i -pe 's|{OLD}|{NEW}|' *",
        "perl -i -pe 's|{OLD}|{NEW}|' -- *",
        "perl -i -pe 's/.*//' -- -e *",
        "sed -i 's|{OLD}|{NEW}|' *",
        "sed -i * -e 's|{OLD}|{NEW}|'",
        "sed -i -- 's|{OLD}|{NEW}|' {a,b}",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}
