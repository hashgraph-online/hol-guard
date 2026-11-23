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
        // Outside a commit message the projection is ASCII only.
        "echo \"$(cat <<'EOF'\nit's a caf\u{e9}\nEOF\n)\"",
        "echo caf\u{e9} && git commit -m \"$(cat <<'EOF'\nsubject\nEOF\n)\"",
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
            "printf '%s\\n' \"$(cat VERSION)\"".to_owned(),
            format!("printf '%s\\n' \"{v}\""),
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
            "echo \"$(cat package.json)\" | sh".to_owned(),
            format!("echo \"{v}\" | sh"),
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
        // Nested or heredoc-fed substitutions.
        "echo \"$(cat $(ls))\"",
        "echo \"$(cat `ls`)\"",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
}
