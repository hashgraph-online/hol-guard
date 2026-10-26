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
