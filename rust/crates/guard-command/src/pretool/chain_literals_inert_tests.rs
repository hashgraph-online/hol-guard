use super::{project, DATE_VALUE, TEMPORARY_VALUE};
use std::cell::RefCell;

fn projected(command: &str) -> Option<String> {
    project(command, |_| true)
}

#[test]
fn value_producers_take_their_stand_ins() {
    let t = TEMPORARY_VALUE;
    let d = DATE_VALUE;
    for (command, expected) in [
        (
            "cd \"$(mktemp -d)\" && ls".to_owned(),
            format!("cd \"{t}\" && ls"),
        ),
        ("cd `mktemp -d` && ls".to_owned(), format!("cd {t} && ls")),
        (
            "echo \"$(date +%Y-%m-%d)\"".to_owned(),
            format!("echo \"{d}\""),
        ),
        (
            "D=$(date -u +%Y%m%dT%H%M%SZ) && echo build-$D.log".to_owned(),
            format!("D={d} && echo build-$D.log"),
        ),
        (
            "cat ../logs/$( date +%F ).log".to_owned(),
            format!("cat ../logs/{d}.log"),
        ),
        (
            "node --test 2>&1 | tail -12; cd \"$(mktemp -d)\" && TODO_FILE=t.json node /work/src/cli.js add Hello world && TODO_FILE=t.json node /work/src/cli.js list".to_owned(),
            format!("node --test 2>&1 | tail -12; cd \"{t}\" && TODO_FILE=t.json node /work/src/cli.js add Hello world && TODO_FILE=t.json node /work/src/cli.js list"),
        ),
        (
            "mkdir -p \"$(mktemp -dq -t run.XXXXXX)/out\"".to_owned(),
            format!("mkdir -p \"{t}/out\""),
        ),
    ] {
        assert_eq!(projected(&command).as_deref(), Some(expected.as_str()), "{command}");
    }
}

#[test]
fn assigned_stand_ins_reach_later_uses() {
    let t = TEMPORARY_VALUE;
    let opened = projected("TMP=$(mktemp -d) && cd $TMP && ls").unwrap();
    assert_eq!(
        super::super::substitute(&opened).as_deref(),
        Some(format!("TMP={t} && cd {t} && ls").as_str())
    );
}

#[test]
fn other_substitutions_keep_the_command_opaque() {
    for command in [
        "cd \"$(gh pr list)\"",
        "echo $(cat ~/.ssh/id_rsa)",
        "echo $(git rev-parse HEAD)",
        "echo $(env)",
        "echo $(pwd)",
        "cat \"$(dirname x)/.env\"",
        "echo $(mktemp -p /etc)",
        "echo $(mktemp --tmpdir)",
        "echo $(mktemp -u)",
        "echo $(mktemp ../x.XXX)",
        "echo $(mktemp /tmp/x.XXXXXX)",
        "echo $(mktemp x.XX)",
        "echo $(mktemp -d a.XXX b.XXX)",
        "echo $(mktemp -d $(whoami))",
        "echo $(mktemp -d; id)",
        "echo $(mktemp -d | tee x)",
        "echo $(mktemp -d > x)",
        "echo $(TMPDIR=/etc mktemp -d)",
        "echo $(\"mktemp\" -d)",
        "echo $(date)",
        "echo $(date -u)",
        "echo $(date -s 2020)",
        "echo $(date +.env)",
        "echo $(date +id_rsa%s)",
        "echo $(date +-rf%s)",
        "echo $(date +%c)",
        "echo $(date +%D)",
        "echo $(date +%_d)",
        "echo $(date +%%)",
        "echo $(date +%F +%T)",
        "echo $(date -d @0 +%F)",
        "echo $((1 + 2))",
        "echo $(date +%F) $(whoami)",
        "echo $(date +%F",
        "echo \\$(date +%F)",
        "ls",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
}

#[test]
fn a_temporary_path_that_could_be_steered_or_climbed_stays_opaque() {
    for command in [
        "rm -rf \"$(mktemp -d)/../..\"",
        "cd \"$(mktemp -d)\" && cat ../../etc/passwd",
        "export TMPDIR=$HOME/.ssh && cd \"$(mktemp -d)\" && ls",
        "TMPDIR=. && echo $(mktemp -d)",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
    // A date names no directory, so a relative climb beside it is literal.
    assert!(projected("cat ../$(date +%s).log").is_some());
}

#[test]
fn each_value_producer_is_judged_once_as_its_own_command() {
    let seen = RefCell::new(Vec::new());
    let opened = project("cd $(mktemp -d) && echo $(mktemp -d) $(date +%s)", |body| {
        seen.borrow_mut().push(body.to_owned());
        true
    });
    assert!(opened.is_some());
    assert_eq!(*seen.borrow(), ["mktemp -d", "date +%s"]);
    assert_eq!(project("cd \"$(mktemp -d)\" && ls", |_| false), None);
    assert_eq!(
        project("echo $(date +%F) $(mktemp -d)", |body| body != "mktemp -d"),
        None
    );
}

#[test]
fn a_bare_lookup_is_also_judged_with_the_operand_it_prints_back() {
    let seen = RefCell::new(Vec::new());
    let opened = project("git diff $(git rev-parse origin/main) --stat", |body| {
        seen.borrow_mut().push(body.to_owned());
        true
    });
    assert_eq!(
        opened.as_deref(),
        Some("git diff 0123456789abcdef0123456789abcdef01234567 --stat")
    );
    assert_eq!(
        *seen.borrow(),
        [
            "git rev-parse origin/main",
            "git diff  --stat",
            "git diff origin/main --stat"
        ]
    );
    // Outside a repository the lookup prints nothing, and that reading
    // must pass as well.
    assert_eq!(
        project("git log -1 $(git rev-parse release/x)", |body| {
            body != "git log -1 "
        }),
        None
    );
    // The reading with the operand in place must pass as well.
    assert_eq!(
        project("git log -1 $(git rev-parse release/x)", |body| {
            body != "git log -1 release/x"
        }),
        None
    );
    // A lookup that prints a hash or nothing still drops the word.
    let seen = RefCell::new(Vec::new());
    project("git log -1 $(git rev-parse --verify origin/main)", |body| {
        seen.borrow_mut().push(body.to_owned());
        true
    });
    assert_eq!(
        *seen.borrow(),
        ["git rev-parse --verify origin/main", "git log -1 "]
    );
}

#[test]
fn each_combination_of_lookup_outcomes_is_judged() {
    let command = "git diff $(git rev-parse origin/main) $(git rev-parse release/x) --stat";
    let seen = RefCell::new(Vec::new());
    project(command, |body| {
        seen.borrow_mut().push(body.to_owned());
        true
    });
    let hash = "0123456789abcdef0123456789abcdef01234567";
    for mixed in [
        format!("git diff {hash}  --stat"),
        "git diff  release/x --stat".to_owned(),
        format!("git diff origin/main {hash} --stat"),
        "git diff   --stat".to_owned(),
        "git diff origin/main release/x --stat".to_owned(),
    ] {
        assert!(seen.borrow().contains(&mixed), "{mixed}");
    }
    // A mixed outcome that a control refuses refuses the projection.
    assert_eq!(
        project(command, |body| body != format!("git diff {hash}  --stat")),
        None
    );
    // Past the bound the projection is not attempted.
    assert_eq!(
        project(
            "git diff $(git rev-parse a/x) $(git rev-parse b/x) $(git rev-parse c/x)",
            |_| true
        ),
        None
    );
}

#[test]
fn a_printed_back_peel_is_judged_without_its_quotes() {
    let seen = RefCell::new(Vec::new());
    project("git show \"$(git rev-parse 'HEAD^{}')\" --stat", |body| {
        seen.borrow_mut().push(body.to_owned());
        true
    });
    assert!(
        seen.borrow()
            .contains(&"git show \"HEAD^{}\" --stat".to_owned()),
        "{:?}",
        seen.borrow()
    );
}

#[test]
fn a_substitution_beside_a_pattern_character_stays_opaque() {
    for command in [
        // The shell globs `2026*`; the projection would glob the stand-in's
        // own spelling and prove the wrong set of files.
        "rg TODO -g \"$(date +%Y)*\"",
        "rg TODO -g '*$(date +%Y)'",
        "find . -name \"$(date +%F)?.log\"",
        "ls $(mktemp -d)/*",
        "ls [a-z]$(date +%Y)",
        "cat build-$(date +%F).{log,txt}",
        // A bracket expression is a pattern too, wherever the word sits.
        "rg -g \"$(date +%Y)[0-9]\" TODO",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
    // A pattern elsewhere in the command leaves the substitution's own word
    // whole, so it still projects.
    assert_eq!(
        projected("cd \"$(mktemp -d)\" && rg TODO -g '*.rs'").as_deref(),
        Some(format!("cd \"{TEMPORARY_VALUE}\" && rg TODO -g '*.rs'").as_str())
    );
}

/// A script that rewrites a source file, as an agent sends it before a smoke
/// test: its JavaScript template literal is data in a quoted heredoc.
const SCRIPT: &str = "s=s.replace(\"`file://${process.argv[1]}`\", \"$(x)\")";

#[test]
fn line_breaks_and_quoted_heredoc_bodies_keep_the_projection() {
    let t = TEMPORARY_VALUE;
    for (command, expected) in [
        (
            "node --test test/ 2>&1 | tail -10\ncd \"$(mktemp -d)\"\nls".to_owned(),
            format!("node --test test/ 2>&1 | tail -10\ncd \"{t}\"\nls"),
        ),
        (
            format!("python3 - <<'EOF'\n{SCRIPT}\nEOF\nexport F=$(mktemp -d)/t.json; ls"),
            format!("python3 - <<'EOF'\n{SCRIPT}\nEOF\nexport F={t}/t.json; ls"),
        ),
        (
            format!("cat > a.js <<\"EOF\"\n{SCRIPT}\nEOF\ncd $(mktemp -d)"),
            format!("cat > a.js <<\"EOF\"\n{SCRIPT}\nEOF\ncd {t}"),
        ),
        (
            format!("cat > a.js <<-'EOF'\n\t{SCRIPT}\n\tEOF\ncd $(mktemp -d)"),
            format!("cat > a.js <<-'EOF'\n\t{SCRIPT}\n\tEOF\ncd {t}"),
        ),
    ] {
        assert_eq!(
            projected(&command).as_deref(),
            Some(expected.as_str()),
            "{command}"
        );
    }
    // A quoted body alone substitutes nothing, so there is nothing to project.
    assert_eq!(
        projected(&format!(
            "python3 - <<'EOF'\n{SCRIPT}\nEOF\nnode --test test/"
        )),
        None
    );
}

#[test]
fn heredocs_that_could_expand_or_never_close_keep_the_command_opaque() {
    for command in [
        // An unquoted delimiter expands the body.
        "cat > f <<EOF\n$(mktemp -d)\nEOF\ncd $(mktemp -d)".to_owned(),
        "cat > f <<EOF\n`whoami`\nEOF\ncd $(mktemp -d)".to_owned(),
        "cat > f <<-EOF\n\t$(cat ~/.ssh/id_rsa)\n\tEOF\ncd $(mktemp -d)".to_owned(),
        // The shared parser does not read a backslash-quoted delimiter.
        format!("python3 - <<\\EOF\n{SCRIPT}\nEOF\ncd $(mktemp -d)"),
        // A body that never closes runs to the end of the text.
        format!("python3 - <<'EOF'\n{SCRIPT}\ncd $(mktemp -d)"),
        "cd $(mktemp -d) && cat <<'EOF'".to_owned(),
        // Line breaks other than `\n` stay refused.
        "cd $(mktemp -d)\r\nls".to_owned(),
        // A substitution after a quoted body still has to be a value producer.
        format!("python3 - <<'EOF'\n{SCRIPT}\nEOF\necho $(whoami)"),
    ] {
        assert_eq!(projected(&command), None, "{command}");
    }
}

/// The commit-message form an agent writes by hand: a quoted heredoc read by
/// a bare `cat`, inside the double quotes of `-m`. The value is known exactly,
/// so the projection carries the message itself and every screen downstream
/// reads the words the shell passes.
#[test]
fn a_quoted_heredoc_read_by_cat_becomes_its_own_text() {
    for (command, expected) in [
        (
            "git commit -m \"$(cat <<'EOF'\nfeat(x): subject\n\nbody line\nEOF\n)\"",
            "git commit -m \"feat(x): subject\n\nbody line\"",
        ),
        ("echo \"$(cat <<\"EOF\"\nhello\nEOF\n)\"", "echo \"hello\""),
        // Trailing blank lines go the way the shell drops them.
        (
            "git commit -m \"$(cat <<'EOF'\nsubject\n\n\nEOF\n)\"",
            "git commit -m \"subject\"",
        ),
        // Parentheses are ordinary message text: a conventional-commit scope
        // is the commonest thing an agent writes here.
        (
            "git commit -m \"$(cat <<'EOF'\nfix(x): drop the old path\n\nRefs: #12\nEOF\n)\"",
            "git commit -m \"fix(x): drop the old path\n\nRefs: #12\"",
        ),
        // An apostrophe is literal inside the double quotes, so the message
        // is the text the program receives.
        (
            "git commit -m \"$(cat <<'EOF'\nfix: keep 'in' checks\n\nit's the old path\nEOF\n)\"",
            "git commit -m \"fix: keep 'in' checks\n\nit's the old path\"",
        ),
    ] {
        assert_eq!(projected(command).as_deref(), Some(expected), "{command}");
    }
    let seen = RefCell::new(Vec::new());
    let opened = project("git commit -m \"$(cat <<'EOF'\nsubject\nEOF\n)\"", |body| {
        seen.borrow_mut().push(body.to_owned());
        true
    });
    assert!(opened.is_some());
    // The heredoc is the whole of what the `cat` reads, so the command judged
    // is the bare `cat`, not the text of the message.
    assert_eq!(*seen.borrow(), ["cat"]);
    assert_eq!(
        project("git commit -m \"$(cat <<'EOF'\nsubject\nEOF\n)\"", |_| {
            false
        }),
        None
    );
}

#[test]
fn a_cat_that_reads_more_than_a_quoted_heredoc_stays_opaque() {
    for command in [
        // An unquoted delimiter expands the body, so its text is not data.
        "git commit -m \"$(cat <<EOF\nsubject\nEOF\n)\"",
        // A tab-stripping body is not the text the shell would pass.
        "git commit -m \"$(cat <<-'EOF'\n\tsubject\n\tEOF\n)\"",
        // The `cat` also reads a file.
        "git commit -m \"$(cat notes.txt <<'EOF'\nsubject\nEOF\n)\"",
        // Another command runs inside the substitution.
        "git commit -m \"$(cat <<'EOF'\nsubject\nEOF\n; id)\"",
        "git commit -m \"$(id; cat <<'EOF'\nsubject\nEOF\n)\"",
        // Unquoted, the shell would split and glob the value.
        "git commit -m $(cat <<'EOF'\nsubject\nEOF\n)",
        // The word carries more than the substitution, so the value would be
        // spliced into text the shell quotes differently.
        "git commit -m x\"$(cat <<'EOF'\nsubject\nEOF\n)\"",
        // Outside a commit message, a body that could reopen the shell is
        // never spliced.
        "echo \"$(cat <<'EOF'\nuse `id` here\nEOF\n)\"",
        "echo \"$(cat <<'EOF'\ncost $(id)\nEOF\n)\"",
        "echo \"$(cat <<'EOF'\nsay \"hi\"\nEOF\n)\"",
        "echo \"$(cat <<'EOF'\nit's a \\ path\nEOF\n)\"",
        // Inside a substitution other than a commit message the projection
        // is ASCII only.
        "echo \"$(cat <<'EOF'\nit's a caf\u{e9}\nEOF\n)\"",
        "echo \"$(cat <<'EOF'\nwipe *\nEOF\n)\"",
        // A pattern character is refused even though the double quotes keep
        // the shell from matching it: the screens downstream read the
        // projection as a command, and a bracket there is a glob.
        "rm \"$(cat <<'EOF'\ndrop [legacy]\nEOF\n)\"",
        "echo \"$(cat <<'EOF'\npath\\\\x\nEOF\n)\"",
        // Only the value of `git commit -m` or `--message` is a message.
        "git commit -F \"$(cat <<'EOF'\n[notes]\nEOF\n)\"",
        "git commit --author \"$(cat <<'EOF'\nA \u{e9} <a@b>\nEOF\n)\"",
        "git -c core.hooksPath=x commit -m \"$(cat <<'EOF'\nuse `id`\nEOF\n)\"",
        "git tag -m \"$(cat <<'EOF'\nuse `id`\nEOF\n)\"",
        "git commit --file=x -m \"$(cat <<'EOF'\nuse `id`\nEOF\n)\"",
        // A flag before `-m` that takes a value, a repeated `-m` or `--`
        // makes Git read the substitution as that value or as a path.
        "git commit -m -m \"$(cat <<'EOF'\n*\nEOF\n)\"",
        "git commit -- -m \"$(cat <<'EOF'\n*\nEOF\n)\"",
        "git commit -F -m \"$(cat <<'EOF'\n*\nEOF\n)\"",
        "git commit --author -m \"$(cat <<'EOF'\n*\nEOF\n)\"",
        "git commit -t -m \"$(cat <<'EOF'\n*\nEOF\n)\"",
        "git commit -Sa -m \"$(cat <<'EOF'\n*\nEOF\n)\"",
        "git commit --trailer -m \"$(cat <<'EOF'\n*\nEOF\n)\"",
        "git commit -m\"$(cat <<'EOF'\nuse `id`\nEOF\n)\"",
        "echo git commit -m && echo -m \"$(cat <<'EOF'\nuse `id`\nEOF\n)\"",
        // An unquoted delimiter expands the body, so its text is not data.
        "git commit -m \"$(cat <<EOF\nuse caf\u{e9}\nEOF\n)\"",
        // The quote in front of the substitution closes a quoted space
        // rather than opening the word, so the shell runs the substitution
        // unquoted and the value would be spliced in as code.
        "git commit -m \" \"$(cat <<'EOF'\nx # EOF\nEOF\n)\" \" && id",
        "git commit -m \"a\"\"$(cat <<'EOF'\nsubject\nEOF\n)\"",
        // The quote that would open the word sits inside an earlier heredoc
        // body, where the shell reads it as data. The substitution is
        // unquoted, so its value would be spliced in as code.
        "cat <<'PRE'\n\"\nPRE\ngit commit -m \" \"$(cat <<'EOF'\nx # EOF\nEOF\n)\" \" && id",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
}

/// Agents write backticks, brackets, quotes and em dashes in commit
/// messages. Git reads the value of `-m` only as the message, so there the
/// projection keeps it and writes each character it may not carry as `_`.
#[test]
fn a_commit_message_writes_characters_it_cannot_carry_as_stand_ins() {
    for (command, expected) in [
        (
            "git commit -m \"$(cat <<'EOF'\nuse `id` here\nEOF\n)\"",
            "git commit -m \"use _id_ here\"",
        ),
        (
            "git commit -m \"$(cat <<'EOF'\ncost $(id)\nEOF\n)\"",
            "git commit -m \"cost _(id)\"",
        ),
        (
            "git commit -m \"$(cat <<'EOF'\nsay \"hi\" or \"\\n\"\nEOF\n)\"",
            "git commit -m \"say _hi_ or __n_\"",
        ),
        (
            "git commit -m \"$(cat <<'EOF'\nit's a caf\u{e9}\nEOF\n)\"",
            "git commit -m \"it's a caf_\"",
        ),
        (
            "git commit -m \"$(cat <<'EOF'\nwipe * and ~ {a,b} [legacy]?\nEOF\n)\"",
            "git commit -m \"wipe _ and _ _a,b_ _legacy__\"",
        ),
        // As Claude Code writes it, after `cd` and `git add`.
        (
            "cd /w && git add -A && git commit -m \"$(cat <<'EOF'\nFix x\n\nThe check was inverted\u{2014}it returned early.\nEOF\n)\"",
            "cd /w && git add -A && git commit -m \"Fix x\n\nThe check was inverted_it returned early.\"",
        ),
        (
            "git commit -a -s --message \"$(cat <<'EOF'\nuse a[key]\tnow\nEOF\n)\"",
            "git commit -a -s --message \"use a_key__now\"",
        ),
    ] {
        assert_eq!(projected(command).as_deref(), Some(expected), "{command}");
    }
}

#[test]
fn a_heredoc_message_longer_than_the_bound_stays_opaque() {
    let line = "a".repeat(80);
    let long: Vec<&str> = std::iter::repeat_n(line.as_str(), 60).collect();
    let command = format!(
        "git commit -m \"$(cat <<'EOF'\n{}\nEOF\n)\"",
        long.join("\n")
    );
    assert!(command.len() < super::MAX_COMMAND_CHARS);
    assert_eq!(projected(&command), None);
}

#[test]
fn printed_values_take_the_display_stand_in() {
    let v = super::display::DISPLAY_VALUE;
    for (command, expected) in [
        (
            "echo \"version: $(grep -m1 version package.json)\"".to_owned(),
            format!("echo \"version: {v}\""),
        ),
        (
            // A revision lookup outside a Git command is only printed.
            "echo \"commit: $(git rev-parse HEAD)\"".to_owned(),
            format!("echo \"commit: {v}\""),
        ),
        (
            // So is a line-number lookup outside a `sed` range.
            "echo \"line: $(grep -n foo f | cut -d: -f1)\"".to_owned(),
            format!("echo \"line: {v}\""),
        ),
        (
            "printf 'version %s\\n' \"$(cat VERSION)\"".to_owned(),
            format!("printf 'version %s\\n' \"{v}\""),
        ),
        (
            "printf '%s\\n' \"release $(cat VERSION)\"".to_owned(),
            format!("printf '%s\\n' \"release {v}\""),
        ),
        (
            "echo -n \"$(cat VERSION) is current\"".to_owned(),
            format!("echo -n \"{v} is current\""),
        ),
        (
            // A preceding printf without -v does not change the environment.
            "printf '%s' ready && echo \"version: $(cat VERSION)\"".to_owned(),
            format!("printf '%s' ready && echo \"version: {v}\""),
        ),
        (
            "ls && echo \"lines: $(wc -l < package.json)\" | head -1".to_owned(),
            format!("ls && echo \"lines: {v}\" | head -1"),
        ),
        (
            "for d in a b; do echo \"d: $(cat d/package.json)\"; done".to_owned(),
            format!("for d in a b; do echo \"d: {v}\"; done"),
        ),
        (
            "echo \"run: $(cat package.json)\" | sh".to_owned(),
            format!("echo \"run: {v}\" | sh"),
        ),
    ] {
        assert_eq!(
            projected(&command).as_deref(),
            Some(expected.as_str()),
            "{command}"
        );
    }
}

#[test]
fn printed_values_judge_the_inner_command_on_its_own() {
    let seen = RefCell::new(Vec::new());
    let refused = project("echo \"key: $(cat ~/.ssh/id_rsa)\"", |body| {
        seen.borrow_mut().push(body.to_owned());
        false
    });
    assert_eq!(refused, None);
    assert_eq!(seen.into_inner(), vec!["cat ~/.ssh/id_rsa".to_owned()]);
}

#[test]
fn values_used_as_more_than_output_stay_opaque() {
    for command in [
        // The inner command would run somewhere other than where it is judged.
        // Shell builtins can also rebind HOME/PATH before the read.
        "printf -v HOME '%s' /tmp/inert; echo \"label: $(cat ~/marker)\"",
        // Bash accepts redirection before -v, which still changes HOME.
        "printf >/dev/null -v HOME '%s' /tmp/inert; echo \"label: $(cat ~/marker)\"",
        "printf -vPATH '%s' /tmp/inert; echo \"label: $(cat marker)\"",
        "read HOME; echo \"label: $(cat ~/marker)\"",
        "mapfile HOME; echo \"label: $(cat marker)\"",
        "readarray HOME; echo \"label: $(cat marker)\"",
        "getopts a opt; echo \"label: $(cat marker)\"",
        "let HOME=1; echo \"label: $(cat marker)\"",
        // zsh's `chdir` and `print -v`, appends, subscripts and expansions
        // that assign also change what the read sees.
        "chdir ~/.ssh; echo \"key: $(cat id_rsa)\"",
        "print -v PATH /tmp/inert; echo \"label: $(cat marker)\"",
        "HOME+=/x; echo \"key: $(cat ~/id_rsa)\"",
        "PATH+=:/tmp/inert; echo \"label: $(cat marker)\"",
        "HOME[0]=/etc; echo \"key: $(cat ~/passwd)\"",
        "echo \"${PATH:=/tmp/inert}\"; echo \"label: $(cat marker)\"",
        ": ${HOME=/etc}; echo \"key: $(cat ~/passwd)\"",
        ": $((HOME=1)); echo \"label: $(cat marker)\"",
        // Legacy `$[...]` arithmetic, zsh's unbraced subscript, the
        // arithmetic operands of `[[ -eq ]]`, zsh's numeric `printf` and a
        // zsh glob qualifier that runs code all assign as well.
        ": $[PATH=0]; echo \"label: $(cat marker)\"",
        "echo \"$[PATH=0]\"; echo \"label: $(cat marker)\"",
        ": $path[PATH=0]; echo \"label: $(cat marker)\"",
        "[[ 1 -eq PATH=0 ]]; echo \"label: $(cat marker)\"",
        "printf '%d' PATH=0; echo \"label: $(cat marker)\"",
        ": *(e:PATH=0:); echo \"label: $(cat marker)\"",
        ": *(+steer); echo \"label: $(cat marker)\"",
        "for i in 1 2; do echo \"key: $(cat id_rsa)\"; : (marker|x)(e:'cd ~/.ssh':); done",
        "for i in 1 2; do echo \"key: $(cat id_rsa)\"; : {marker,x}(e:'cd ~/.ssh':); done",
        "trap 'HOME=/tmp/inert' DEBUG; echo \"label: $(cat ~/marker)\"",
        "cd ~/.ssh && echo \"$(cat id_rsa)\"",
        "pushd ~/.ssh; echo \"$(cat id_rsa)\"",
        "HOME=/etc; echo \"$(cat ~/passwd)\"",
        "export F=x && echo \"$(cat x)\"",
        "echo \"$(cat \"$F\")\"",
        "echo \"$(cat ${F})\"",
        // `echo` might not be the echo builtin.
        "alias echo=rm; echo \"$(cat x)\"",
        "echo() { rm \"$1\"; }; echo \"$(cat x)\"",
        // The value is a format, a variable name, a path or a program.
        "printf \"$(cat x)\"",
        "printf -v out '%s' \"$(cat x)\"",
        "cat \"$(cat x)\"",
        "echo > \"$(cat x)\"",
        "echo 2>/dev/null \"$(cat x)\"",
        "eval \"$(cat x)\"",
        "sh -c \"echo $(cat x)\"",
        "xargs echo \"$(cat x)\"",
        "command echo \"$(cat x)\"",
        // Split and matched by the shell.
        "echo $(cat x)",
        "echo '$(cat x)' \"$(cat x)\"x$(cat y)",
        // The print adds nothing of its own to the value.
        "echo \"$(cat x)\"",
        "echo -n -e \"$(cat x)\"",
        "printf '%s' \"$(cat x)\"",
        "printf '%s\\n' \"$(cat x)\"",
        "printf '%-10.3s%%\\t' \"$(cat x)\"",
        "printf '%s' \"$(cat workspace/notes)\" \"$(cat x)\"",
        "printf '%ls' \"$(cat x)\"",
        // zsh's `%n` stores into the variable its argument names.
        "printf 'label %n' \"$(cat x)\"",
        "printf 'label %s %n' \"$(cat x)\" PATH",
        // zsh evaluates the argument of a numeric conversion or a `*` width
        // as arithmetic, which can run a substitution held in the value.
        "printf 'count: %d\\n' \"$(cat x)\"",
        "printf 'label: %x' \"$(cat x)\"",
        "printf 'label: %*s' \"$(cat x)\" y",
        "echo \"$(cat x)\" | sh",
        // Nested or heredoc-fed substitutions.
        "echo \"$(cat $(ls))\"",
        "echo \"$(cat `ls`)\"",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
}

#[test]
fn a_slot_this_scan_cannot_place_stays_opaque() {
    for command in [
        // A loop body runs again, so a `cd` written after the print still
        // runs before the read on the next pass.
        "for i in 1 2; do echo \"key: $(cat id_rsa)\"; cd ~/.ssh; done",
        "while echo \"key: $(cat id_rsa)\"; cd ~/.ssh; do :; done",
        "until false; do echo \"key: $(cat id_rsa)\"; cd ~/.ssh; done",
        "repeat 2; do echo \"key: $(cat id_rsa)\"; cd ~/.ssh; done",
        "repeat 2 do\necho \"key: $(cat id_rsa)\"\ncd ~/.ssh\ndone",
        "foreach i (1 2); echo \"key: $(cat id_rsa)\"; cd ~/.ssh; end",
        // `$'...'` and `$"..."` carry the shell's own escape rules, so the
        // quoting ahead of the slot is not what a character walk reads.
        "rm $'\\'; echo \"' $(cat x) \"\"",
        "cat $'a' && echo \"name: $(cat y)\"",
        "cat $\"a\" && echo \"name: $(cat y)\"",
        // `}` can end a word and `{a,b}` is one word, so neither starts the
        // command that holds the slot.
        "cat a} echo \"name: $(cat y)\"",
        "cat {a,b} echo \"name: $(cat y)\"",
        // A group, a subshell and a process substitution put the command
        // somewhere this scan does not read.
        "{ cd ~/.ssh; } echo \"key: $(cat x)\"",
        "(cd ~/.ssh) echo \"key: $(cat x)\"",
        "cat <(ls); echo \"name: $(cat y)\"",
        // A function definition written with a space still redefines the name
        // the inner command is judged against.
        "cat( ) { command cat ~/.ssh/id_rsa; }; echo \"key: $(cat x)\"",
        // `>&` and `>|` are redirections, not separators.
        "ls >| out; echo \"name: $(cat y)\"",
        "ls >&2; echo \"name: $(cat y)\"",
        // A comment hides its quotes from the shell, so a `cd` after a quote
        // in a comment still runs.
        "echo a # '\ncd ~/.ssh\necho \"it's\"\" $(cat id_rsa)\"",
        "echo a #'\ncd ~/.ssh\necho \"it's\"\" $(cat id_rsa)\"",
        // A loop that binds a name the shell reads for itself.
        "for PATH in bin; do echo \"v: $(cat README.md)\"; done",
        "for HOME in ~/.aws; do echo \"k: $(cat ~/config)\"; done",
        "select HOME in ~/.aws; do echo \"k: $(cat ~/config)\"; done",
        "for path in bin; do echo \"v: $(cat README.md)\"; done",
        // zsh binds every name up to `in`.
        "for a PATH in x /evil; do echo \"v: $(ls)\"; done",
        "for a HOME in x ~/.aws; do echo \"k: $(cat ~/config)\"; done",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
}

#[test]
fn a_literal_printf_commit_message_becomes_its_own_text() {
    for (command, expected) in [
        (
            "git commit -q -m \"$(printf 'Add host audit\\n\\nCo-Authored-By: A Model <noreply@example.com>')\"",
            "git commit -q -m \"Add host audit\n\nCo-Authored-By: A Model <noreply@example.com>\"",
        ),
        (
            "git add -A && git commit -m \"$(printf 'fix(x): 100%% done\\n')\"",
            "git add -A && git commit -m \"fix(x): 100% done\"",
        ),
        // Characters the message may not carry are written as `_`, as the
        // heredoc form writes them.
        (
            "git commit --message \"$(printf 'use a[key] \u{2014} now')\"",
            "git commit --message \"use a_key_ _ now\"",
        ),
        // Shell blanks around the command are not part of it.
        (
            "git commit -m \"$( printf 'subject'\t)\"",
            "git commit -m \"subject\"",
        ),
    ] {
        assert_eq!(projected(command).as_deref(), Some(expected), "{command}");
    }
    let seen = RefCell::new(Vec::new());
    let opened = project("git commit -m \"$(printf 'subject')\"", |body| {
        seen.borrow_mut().push(body.to_owned());
        true
    });
    assert!(opened.is_some());
    // The format is the whole of what `printf` reads, so the command judged
    // is the bare `printf`.
    assert_eq!(*seen.borrow(), ["printf"]);
    assert_eq!(
        project("git commit -m \"$(printf 'subject')\"", |_| false),
        None
    );
}

#[test]
fn a_printf_that_computes_its_output_or_runs_elsewhere_stays_opaque() {
    for command in [
        // Conversions and escapes other than `\n` and `%%`.
        "git commit -m \"$(printf '%s' x)\"",
        "git commit -m \"$(printf 'a %s b')\"",
        "git commit -m \"$(printf '\\x41')\"",
        "git commit -m \"$(printf '\\101')\"",
        "git commit -m \"$(printf 'a\\c')\"",
        "git commit -m \"$(printf 'trailing\\')\"",
        "git commit -m \"$(printf 'trailing%')\"",
        // A format the shell expands, or more than one word.
        "git commit -m \"$(printf \"$X\")\"",
        "git commit -m \"$(printf \"subject\")\"",
        "git commit -m \"$(printf 'a' 'b')\"",
        "git commit -m \"$(printf 'a'; rm -rf build)\"",
        "git commit -m \"$(printf 'a' > out)\"",
        "git commit -m \"$(printf -v X 'a')\"",
        // A newline after `printf` runs the quoted word as its own command.
        "git commit -m \"$(printf \n'./payload')\"",
        "git commit -m \"$(printf \t\n'./payload')\"",
        "git commit -m \"$(printf '-a')\"",
        // A no-break space is not a shell blank: it joins the format word, so
        // `printf` prints it too.
        "git commit -m \"$(printf 'x'\u{a0})\"",
        "git commit -m \"$(\u{a0}printf 'x')\"",
        // Not the value of `git commit -m`, or not a whole double-quoted word.
        "$(printf rm) -rf build",
        "$(printf 'rm') -rf build",
        "git commit -m $(printf 'subject')",
        "git commit -m \"x$(printf 'subject')\"",
        "git tag -m \"$(printf 'subject')\" v1",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
}

/// A word such as `café`, an em dash or an emoji outside every substitution
/// is text the shell passes through as written, so the projection keeps it.
/// A Unicode space or a direction or zero-width mark, or a letter zsh would
/// read into a `$NAME`, keeps the command opaque.
#[test]
fn plain_text_outside_ascii_beside_a_substitution_keeps_the_projection() {
    let d = DATE_VALUE;
    for (command, expected) in [
        (
            "echo caf\u{e9} && git commit -m \"$(cat <<'EOF'\nsubject\nEOF\n)\"".to_owned(),
            "echo caf\u{e9} && git commit -m \"subject\"".to_owned(),
        ),
        (
            "echo \"$(date +%F) \u{2014} build \u{2705}\u{fe0f}\"".to_owned(),
            format!("echo \"{d} \u{2014} build \u{2705}\u{fe0f}\""),
        ),
        (
            "D=$(date +%F); echo '\u{65e5}\u{4ed8}' \"$D\"".to_owned(),
            format!("D={d}; echo '\u{65e5}\u{4ed8}' \"$D\""),
        ),
    ] {
        assert_eq!(projected(&command), Some(expected), "{command}");
    }
    for command in [
        "echo caf\u{e9}\u{a0}x \"$(date +%F)\"",
        "echo \"a\u{202e}b\" \"$(date +%F)\"",
        "echo \"a\u{200b}b\" \"$(date +%F)\"",
        "echo $caf\u{e9} \"$(date +%F)\"",
        "echo ${caf\u{e9}} \"$(date +%F)\"",
        // The shell drops a backslash-newline before it reads the name.
        "echo $caf\\\n\u{e9} \"$(date +%F)\"",
        "echo $\\\ncaf\u{e9} \"$(date +%F)\"",
        "echo $\\\n{caf\u{e9}} \"$(date +%F)\"",
        "echo \"$(date +%F)\u{3000}\"",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
}
