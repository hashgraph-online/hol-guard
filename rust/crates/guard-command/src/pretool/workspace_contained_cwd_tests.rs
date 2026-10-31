use crate::pretool::workspace_contained_tests::workspace;
use std::path::Path;

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

/// `cd build && cmake ..` is how every out-of-tree build is spelled. The
/// parent step returns to the workspace root the descent just left, so the
/// path never leaves the sandbox the shape builds.
#[test]
fn a_parent_step_after_a_proven_descent_stays_inside_the_workspace() {
    let ws = workspace("cwd-parent", true);
    std::fs::create_dir_all(ws.join("build")).unwrap();
    std::fs::create_dir_all(ws.join("build/sub")).unwrap();
    for command in [
        "cd build && ls ..",
        "cd build && ls -la ..",
        "cd build && cat ../package.json",
        "cd build/sub && cat ../../package.json",
        "cd build && ls .. && ls .",
    ] {
        assert!(shaped(command, &ws), "{command}");
    }
    for command in [
        // No descent to spend: the step leaves the workspace.
        "ls ..",
        "cat ../package.json",
        // One descent, two steps.
        "cd build && ls ../..",
        "cd build/sub && cat ../../../package.json",
        // `;` runs the second command whether or not the descent succeeded,
        // so the shallower shell decides.
        "cd build; ls ..",
        // A descent the file system does not confirm proves no depth.
        "cd absent && ls ..",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// `CDPATH` makes bash search its own list before the current directory, so a
/// bare `cd etc` can land outside the workspace while the walk here joins the
/// name onto the directory it is tracking. No segment may spend a step then.
#[test]
fn a_command_that_mentions_cdpath_spends_no_descent() {
    let ws = workspace("cwd-cdpath", true);
    std::fs::create_dir_all(ws.join("etc")).unwrap();
    for command in [
        "CDPATH=/ cd etc && cat ../etc/passwd",
        "export CDPATH=/ && cd etc && cat ../etc/passwd",
        "CDPATH=/ cd etc && ls ..",
        // zsh ties the same search to a lowercase `cdpath` array, which an
        // uppercase-only match read as an ordinary assignment.
        "cdpath=/ cd etc && cat ../etc/passwd",
        "export cdpath=/ && cd etc && ls ..",
        "CdPath=/ cd etc && ls ..",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// A run that sets the search path itself is not contained at all, whether or
/// not it spends a parent step. `CDPATH=/ cd etc && ls` reads here as a
/// descent into `etc` below the workspace while the shell it describes lands
/// in `/etc` and lists that.
#[test]
fn a_command_that_sets_a_directory_search_path_is_not_contained() {
    let ws = workspace("cwd-cdpath-shape", true);
    std::fs::create_dir_all(ws.join("etc")).unwrap();
    for command in [
        "CDPATH=/ cd etc && ls",
        "CDPATH=/ cd etc && cat passwd",
        "cdpath=/ cd etc && ls",
        "CdPath=/ cd etc && ls",
        "export CDPATH=/ && cd etc && ls",
        "export cdpath=/ && cd etc && ls",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
    // The same descent without a search path is the ordinary contained shape.
    for command in ["cd etc && ls", "cd etc && ls ."] {
        assert!(shaped(command, &ws), "{command}");
    }
}

/// Only the bare builtin moves the shell. A program the workspace happens to
/// carry at `tools/cd` is an ordinary child process: it cannot change its
/// parent's directory, so the shell is still at the root when the next segment
/// runs and the `..` there leaves the workspace.
#[test]
fn a_program_named_cd_spends_no_descent() {
    let ws = workspace("cwd-named-cd", true);
    std::fs::create_dir_all(ws.join("build")).unwrap();
    std::fs::create_dir_all(ws.join("tools")).unwrap();
    for command in [
        "./tools/cd build && ls ..",
        "tools/cd build && cat ../package.json",
        "/usr/local/bin/cd build && ls ..",
        "./tools/pushd build && ls ..",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// The walk carries the spelling the shell prints so that a later `cd ..` is
/// read the way the shell spends it. A `..` in an ordinary operand is spent
/// by the kernel instead, on what the spelling points to, so a link that
/// leads back to its own directory leaves the two readings at different
/// depths and only the shallower one may be spent.
#[test]
fn a_step_the_kernel_will_not_grant_is_not_spent() {
    let ws = workspace("cwd-link-depth", true);
    std::fs::create_dir_all(ws.join("app")).unwrap();
    std::os::unix::fs::symlink(".", ws.join("here")).unwrap();
    for command in [
        // Two names deep by the shell's reckoning, still at the root by the
        // kernel's, so neither step is there to spend.
        "cd here/here && cat ../../package.json",
        "cd here/here && ls ../..",
        "cd here && ls ..",
        // One name of the descent is the link, so one step is real.
        "cd here/app && ls ../..",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
    // The step the link does grant is still spent.
    assert!(shaped("cd here/app && ls ..", &ws));
}

/// `cd app && npm test; cd ..` is the same visit spelled so the climb back
/// runs whatever the work did. The only branch where that climb leaves the
/// workspace is the one where the first `cd` failed, and on that branch the
/// shell never descended and nothing runs after the climb, so the chain is
/// bounded exactly as the `&&` spelling is.
#[test]
fn a_climb_that_only_leaves_where_the_descent_failed_stays_contained() {
    let ws = workspace("cwd-failed-branch", true);
    std::fs::create_dir_all(ws.join("app/sub")).unwrap();
    for command in [
        "cd app && ls; cd ..",
        "cd app && cat package.json; cd ..",
        "cd app; ls; cd ..",
        "cd app || ls; cd ..",
        "cd app && ls || cd ..",
        "cd app/sub && ls; cd ../..",
        "cd app; cd ..",
    ] {
        assert!(shaped(command, &ws), "{command}");
    }
    for command in [
        // The climb leaves on the branch the command really takes.
        "cd app && ls && cd ../..",
        "cd app && cd ../..",
        // Something runs after the shell that climbed out, and the walk
        // never bounded the directory it would read.
        "cd app && ls; cd ..; ls",
        "cd app && ls; cd ..; cat package.json",
        // No descent at all, so the climb is the step out.
        "cd ..",
        "ls; cd ..",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// `cd app && npm test && cd -` is the same visit with the return spelled as
/// the shell's own shorthand for where it came from. The walk carries that
/// directory, so the return is as bounded as the descent was; a `-` the walk
/// never saw a move for is the inherited `OLDPWD` and stays refused.
#[test]
fn a_return_to_the_previous_directory_follows_the_move_the_walk_saw() {
    let ws = workspace("cwd-previous-directory", true);
    std::fs::create_dir_all(ws.join("app/sub")).unwrap();
    for command in [
        "cd app && ls && cd -",
        "cd app && cat package.json && cd -",
        "cd app/sub && ls && cd -",
        "cd app && ls && cd - && ls",
        "cd app && cd - && cd app",
        "pushd app && ls && cd -",
        "cd app && ls; cd -",
    ] {
        assert!(shaped(command, &ws), "{command}");
    }
    for command in [
        // Nothing moved, so `-` is whatever directory the run was started
        // from, which the walk never bounded.
        "cd -",
        "ls && cd -",
        // The branch whose descent failed never moved either, and this time
        // something runs from the directory its `-` would reach.
        "cd app && ls; cd -; ls",
        "cd app && ls; cd -; cat package.json",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// `cd -` reads `$OLDPWD`, which the shell is free to set to anywhere. The
/// walk follows moves, not assignments, so the two part company as soon as a
/// run writes that variable and the return can no longer be taken for the
/// descent's own step back.
#[test]
fn a_return_to_a_rewritten_previous_directory_is_refused() {
    let ws = workspace("cwd-oldpwd", true);
    std::fs::create_dir_all(ws.join("app")).unwrap();
    for command in [
        "cd app && export OLDPWD=/etc && cd - && cat passwd",
        "cd app && OLDPWD=/etc && cd - && ls",
        "cd app && ls && OLDPWD=/etc cd -",
        "cd app && ls && cd - && cat $OLDPWD/passwd",
        "cd app && oldpwd=/etc && cd - && ls",
        // The shell strips the quoting before it reads the assignment, so
        // these write the same variable as the plain spelling above.
        "cd app && export OLD\"\"PWD=/etc && cd - && cat passwd",
        "cd app && export 'OLDPWD'=/etc && cd - && cat passwd",
        "cd app && OLD\"PWD\"=/etc && cd - && ls",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// The failed-descent branch is carried only so a climb back out of a
/// descent that never happened does not sink the whole walk. A move that
/// names somewhere else is that shell leaving for it, which is the step out
/// the sandbox exists to refuse.
#[test]
fn a_failed_descent_branch_carries_a_climb_and_nothing_else() {
    let ws = workspace("cwd-failed-descent", true);
    std::fs::create_dir_all(ws.join("app")).unwrap();
    for command in [
        "cd app || cd /etc",
        "cd app || cd /etc && ls",
        "cd app; cd /etc",
        "cd app || cd ~",
        "cd app && ls || cd /tmp",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
    // The climb itself is still carried: the branch that would land above the
    // root is the one where the first move failed, and nothing runs there.
    for command in ["cd app && ls; cd ..", "cd app && ls || cd .."] {
        assert!(shaped(command, &ws), "{command}");
    }
}
