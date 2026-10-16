use super::super::TEMPORARY_VALUE;
use super::{mentions, private_assignment, private_directory, project};

#[test]
fn a_private_directory_entered_by_cd_takes_the_stand_in() {
    let t = TEMPORARY_VALUE;
    for (command, expected) in [
        (
            "node --test 2>&1 | tail -12; cd \"$(mktemp -d)\" && TODO_FILE=t.json node /w/src/cli.js add Hello world && TODO_FILE=t.json node /w/src/cli.js list".to_owned(),
            format!("node --test 2>&1 | tail -12; cd \"{t}\" && TODO_FILE=t.json node /w/src/cli.js add Hello world && TODO_FILE=t.json node /w/src/cli.js list"),
        ),
        ("cd $(mktemp -d) && ls".to_owned(), format!("cd {t} && ls")),
        ("cd `mktemp -d` && ls".to_owned(), format!("cd {t} && ls")),
        (
            "pushd \"$(mktemp -dq)\"; ls".to_owned(),
            format!("pushd \"{t}\"; ls"),
        ),
        (
            "cd \"$(mktemp -d -t run.XXXXXX)\" || exit 1".to_owned(),
            format!("cd \"{t}\" || exit 1"),
        ),
        (
            "cd \"$(mktemp -qdt run.XXXXXX)\" && ls".to_owned(),
            format!("cd \"{t}\" && ls"),
        ),
    ] {
        assert_eq!(project(&command).as_deref(), Some(expected.as_str()), "{command}");
    }
}

#[test]
fn other_directories_and_positions_keep_the_command_opaque() {
    for command in [
        "cd \"$(mktemp -d)\" && cat ../x",
        "TMPDIR=/etc; cd \"$(mktemp -d)\" && ls",
        "cd \"$(mktemp -d /etc/XXX)\"",
        "cd \"$(mktemp -d -p /)\"",
        "cd \"$(whoami)\"",
        "cd \"$(date +%F)\"",
        // A template without `-t` names a path below the working directory.
        "cd \"$(mktemp -d run.XXXXXX)\"",
        "cd \"$(mktemp)\"",
        // BSD reads `d` as the prefix of `-t`, so no directory is made.
        "cd \"$(mktemp -td run.XXXXXX)\"",
        "cd \"$(mktemp -d -t)\"",
        "cd \"$(mktemp -d -t a.XXX -t)\"",
        "cd \"$(mktemp -d)/sub\"",
        "cd x\"$(mktemp -d)\"",
        "ls \"$(mktemp -d)\"",
        "echo \"cd $(mktemp -d)\"",
        "X=1 cd \"$(mktemp -d)\"",
        "D=$(mktemp -d) && cd $D",
        "cd \"$(mktemp -d)\" | cat",
        "cd \"$(mktemp -d)\" > log",
        "cd \"$(mktemp -d)\" &",
        "(cd \"$(mktemp -d)\" && ls)",
        "cd \"$(mktemp -d)\" \"$(mktemp -d)\"",
        "cd \"$(mktemp -d)\" && echo \"$(date +%F)\"",
        "echo 'cd \"$(mktemp -d)\"'",
        "ls",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn only_the_absent_stand_in_names_a_private_directory() {
    let t = TEMPORARY_VALUE;
    assert!(private_directory(t));
    let below = format!("{t}/sub");
    for target in [
        "/hol-guard-substituted",
        below.as_str(),
        "/tmp",
        "temporary-path",
    ] {
        assert!(!private_directory(target), "{target}");
    }
    assert_eq!(mentions(&format!("cd {t} && ls {t}/x")), 2);
    assert_eq!(mentions("cd /tmp"), 0);
}

/// Names that steer the shell, program lookup, loading or temporary files.
const SENSITIVE_NAMES: [&str; 22] = [
    "TMPDIR",
    "PATH",
    "HOME",
    "GIT_DIR",
    "GIT_CONFIG_GLOBAL",
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
    "CLASSPATH",
    "TMP",
    "npm_config_userconfig",
    "path",
];

#[test]
fn a_private_directory_assigned_as_its_own_command_takes_the_stand_in() {
    let t = TEMPORARY_VALUE;
    for (command, expected) in [
        (
            "node --test test/ 2>&1 | tail -10; export TODO_FILE=$(mktemp -d)/t.json; node src/cli.js add Try it; node src/cli.js done 1; node src/cli.js list".to_owned(),
            format!("node --test test/ 2>&1 | tail -10; export TODO_FILE={t}/t.json; node src/cli.js add Try it; node src/cli.js done 1; node src/cli.js list"),
        ),
        (
            "TODO_FILE=\"$(mktemp -d)/t.json\" && node src/cli.js list".to_owned(),
            format!("TODO_FILE=\"{t}/t.json\" && node src/cli.js list"),
        ),
        (
            "export OUT=\"$(mktemp -d)\"/run/out.json; ls".to_owned(),
            format!("export OUT=\"{t}\"/run/out.json; ls"),
        ),
        (
            "ls || OUT_DIR=`mktemp -dt run.XXXXXX`".to_owned(),
            format!("ls || OUT_DIR={t}"),
        ),
        (
            "export A=$(mktemp -d); cd \"$(mktemp -d)\" && ls".to_owned(),
            format!("export A={t}; cd \"{t}\" && ls"),
        ),
    ] {
        assert_eq!(project(&command).as_deref(), Some(expected.as_str()), "{command}");
    }
}

#[test]
fn other_assignments_keep_the_command_opaque() {
    for name in SENSITIVE_NAMES {
        for command in [
            format!("export {name}=$(mktemp -d)/x; ls"),
            format!("{name}=\"$(mktemp -d)\" && ls"),
        ] {
            assert_eq!(project(&command), None, "{command}");
        }
    }
    for command in [
        // A climbed, expanded or patterned suffix.
        "export X=$(mktemp -d)/../x; ls",
        "export X=$(mktemp -d)/a/; ls",
        "export X=$(mktemp -d)/$Y; ls",
        "export X=$(mktemp -d)/*.json; ls",
        "export X=$(mktemp -d)x; ls",
        "export X=x$(mktemp -d); ls",
        "export X=$(mktemp -d)\"/t.json\"; ls",
        // A later use, rebinding or second assignment of the name.
        "export TODO_FILE=$(mktemp -d)/t.json; rm -rf \"$TODO_FILE\"",
        "export D=$(mktemp -d); ls ${D}",
        "export D=$(mktemp -d); unset D",
        "export D=$(mktemp -d); export D=$(mktemp -d)",
        "D=$(mktemp -d); export D",
        // Other substitutions.
        "export X=$(whoami); ls",
        "export X=$(mktemp); ls",
        "export X=$(mktemp -d -p /); ls",
        "export X=$(mktemp -d /etc/XXX); ls",
        "export X=$(date +%F); ls",
        // A prefix, a builtin other than plain `export`, or another position.
        "X=$(mktemp -d) node src/cli.js list",
        "export X=$(mktemp -d) Y=1; ls",
        "export -n X=$(mktemp -d); ls",
        "export -f X=$(mktemp -d); ls",
        "declare X=$(mktemp -d); ls",
        "readonly X=$(mktemp -d); ls",
        "local X=$(mktemp -d); ls",
        "typeset X=$(mktemp -d); ls",
        "command export X=$(mktemp -d); ls",
        "X+=$(mktemp -d); ls",
        "X[0]=$(mktemp -d); ls",
        "echo X=$(mktemp -d)",
        "ls --out=$(mktemp -d)",
        "X=$(mktemp -d) | cat",
        "X=$(mktemp -d) &",
        "(X=$(mktemp -d)); ls",
        "X=$(mktemp -d) > log",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn only_an_ordinary_name_named_once_assigns_the_stand_in() {
    let t = TEMPORARY_VALUE;
    for item in [
        format!("export TODO_FILE={t}/t.json"),
        format!("TODO_FILE=\"{t}/t.json\""),
        format!("OUT=\"{t}\"/a/b"),
    ] {
        let text = format!("{item}; node src/cli.js list");
        assert!(private_assignment(&item, &text), "{item}");
    }
    for item in [
        format!("export PATH={t}"),
        format!("export GIT_DIR={t}"),
        format!("export X={t}/../y"),
        format!("export X={t}/*"),
        format!("export X=y{t}"),
        format!("export -n X={t}"),
        format!("declare X={t}"),
        format!("ls {t}"),
        format!("X={t} ls"),
        "X=/hol-guard-substituted/other".to_owned(),
    ] {
        assert!(!private_assignment(&item, &item), "{item}");
    }
    let item = format!("X={t}");
    assert!(!private_assignment(&item, &format!("{item}; echo $X")));
}

/// The script an agent sent before its smoke test: it rewrites `src/cli.js`
/// and carries a JavaScript template literal as data.
const SCRIPT: &str = "python3 - <<'EOF'\np='src/cli.js'\ns=open(p).read()\ns=s.replace(\"if (import.meta.url === `file://${process.argv[1]}`) {\",\"if (main) {\")\nopen(p,'w').write(s)\nEOF";

#[test]
fn line_breaks_end_the_command_that_enters_or_assigns_the_directory() {
    let t = TEMPORARY_VALUE;
    for (command, expected) in [
        (
            format!("{SCRIPT}\nnode --test test/ 2>&1 | tail -10\nexport TODO_FILE=$(mktemp -d)/t.json; node src/cli.js add Try it; node src/cli.js list"),
            format!("{SCRIPT}\nnode --test test/ 2>&1 | tail -10\nexport TODO_FILE={t}/t.json; node src/cli.js add Try it; node src/cli.js list"),
        ),
        (
            "ls\nTODO_FILE=\"$(mktemp -d)/t.json\"\nnode src/cli.js list".to_owned(),
            format!("ls\nTODO_FILE=\"{t}/t.json\"\nnode src/cli.js list"),
        ),
        (
            "cd \"$(mktemp -d)\"\nnode /w/src/cli.js list".to_owned(),
            format!("cd \"{t}\"\nnode /w/src/cli.js list"),
        ),
    ] {
        assert_eq!(project(&command).as_deref(), Some(expected.as_str()), "{command}");
    }
}

#[test]
fn heredocs_and_continued_lines_keep_the_directory_opaque() {
    for command in [
        // A stand-in in a body that expands, or one the shell continues.
        "cat > run.sh <<EOF\nexport X=$(mktemp -d)\nEOF\nsh run.sh".to_owned(),
        "cat > run.sh <<EOF\ncd $(mktemp -d)\nEOF\nsh run.sh".to_owned(),
        "echo \\\nexport X=$(mktemp -d)\nls".to_owned(),
        "ls \\\ncd $(mktemp -d)".to_owned(),
        // A later use on its own line.
        "export TODO_FILE=$(mktemp -d)/t.json\nrm -rf \"$TODO_FILE\"".to_owned(),
        "export TODO_FILE=$(mktemp -d)/t.json\nnode -e 'process.env.TODO_FILE'".to_owned(),
        // A body that names the variable may read it.
        "export TODO_FILE=$(mktemp -d)/t.json\npython3 - <<'EOF'\nprint(open('TODO_FILE').read())\nEOF".to_owned(),
        // A body that never closes.
        "export X=$(mktemp -d)\ncat <<'EOF'\nls".to_owned(),
        // An unquoted-heredoc substitution, even one that is a fresh directory.
        "cat <<EOF\n$(mktemp -d)\nEOF\nexport X=$(mktemp -d)".to_owned(),
    ] {
        assert_eq!(project(&command), None, "{command:?}");
    }
}

/// Files an agent wrote before its smoke test: documentation and a program
/// that both name the variable the test then sets.
const WRITTEN: &str = "cat > README.md <<'EOF'\nSet `TODO_FILE` to choose the store.\nEOF\ncat >src/cli.js <<'EOF'\nconst file = process.env.TODO_FILE;\nEOF\ncat <<\"EOF\" >> notes/todo.txt\nTODO_FILE\nEOF";

#[test]
fn a_path_named_alias_or_a_quoted_operator_is_still_written_data() {
    let t = TEMPORARY_VALUE;
    let tail = "export TODO_FILE=$(mktemp -d)/t.json; node src/cli.js list";
    for prefix in [
        "cat > alias.txt <<'EOF'\nTODO_FILE\nEOF\n",
        "cat > function.txt <<'EOF'\nTODO_FILE\nEOF\n",
        "echo '<<'\ncat > notes/todo.txt <<'EOF'\nTODO_FILE\nEOF\n",
    ] {
        let command = format!("{prefix}{tail}");
        let expected = format!("{prefix}export TODO_FILE={t}/t.json; node src/cli.js list");
        assert_eq!(
            project(&command).as_deref(),
            Some(expected.as_str()),
            "{command:?}"
        );
    }
}

#[test]
fn a_quoted_body_cat_writes_to_a_file_is_not_a_use() {
    let t = TEMPORARY_VALUE;
    let command = format!("{WRITTEN}\nexport TODO_FILE=$(mktemp -d)/t.json; node src/cli.js list");
    let expected = format!("{WRITTEN}\nexport TODO_FILE={t}/t.json; node src/cli.js list");
    assert_eq!(project(&command).as_deref(), Some(expected.as_str()));
    assert!(private_assignment(
        &format!("export TODO_FILE={t}/t.json"),
        &command
    ));
}

#[test]
fn a_body_the_shell_expands_runs_or_redirects_elsewhere_stays_a_use() {
    let tail = "\nexport TODO_FILE=$(mktemp -d)/t.json; node src/cli.js list";
    for body in [
        // The delimiter is unquoted, so the shell expands the body.
        "cat > f <<EOF\n$TODO_FILE\nEOF",
        // The body goes to a program, or the line runs one after `cat`.
        "cat <<'EOF' | sh\nrm -rf \"$TODO_FILE\"\nEOF",
        "sh <<'EOF'\nrm -rf \"$TODO_FILE\"\nEOF",
        "cat > f <<'EOF' && unset TODO_FILE\nTODO_FILE\nEOF",
        "tee f <<'EOF'\nTODO_FILE\nEOF",
        // The target is not a plain path.
        "cat > \"$TODO_FILE\" <<'EOF'\nx\nEOF",
        "cat > f$TODO_FILE <<'EOF'\nx\nEOF",
        // The line continues another command, or sits inside quotes.
        "echo \\\ncat > f <<'EOF'\nTODO_FILE\nEOF",
        "echo \"\ncat > f <<'EOF'\nTODO_FILE\nEOF\n\"",
        // `cat` may not be the program.
        "cat() { sh; }\ncat > f <<'EOF'\nTODO_FILE\nEOF",
        "alias cat=sh\ncat > f <<'EOF'\nTODO_FILE\nEOF",
        // A quote left open at a newline makes the next line's `<<` a
        // different operator than a scan that starts fresh on that line.
        "export X=$(mktemp -d)\necho \"x\n<<'A'\"\ncat <<B\n$(evil)\nA\nB",
    ] {
        let command = format!("{body}{tail}");
        assert_eq!(project(&command), None, "{command:?}");
    }
}
