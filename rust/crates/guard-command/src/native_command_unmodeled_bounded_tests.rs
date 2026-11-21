//! An `xargs` names the program it runs in the command text: standard input
//! supplies its arguments, not its program.
use super::tests::{controls, decision, github};
use super::xargs::{xargs_input_is_named, xargs_names_its_program};

const FAILED: &str = "native_command_extension_evaluation_failed";

#[test]
fn an_xargs_that_names_its_program_is_reviewable() {
    let controls = controls(github("enabled", None), false);
    // A redirect into `xargs` is judged by the redirect proof, which does not
    // yet read an input redirect from a literal path, so `xargs rm -f <
    // list.txt` keeps its evaluation failure for that reason instead.
    for command in [
        "cat list.txt | xargs -0 rm -f",
        "cat list.txt | xargs -n 20 rm -f",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
}

/// A grouped `find` is not a read-only fan-out the parser models, so its
/// `xargs` reaches this floor. Silencing the search's errors moves no data,
/// so the redirect must not take the review away and block it outright.
#[test]
fn a_named_xargs_pipeline_that_discards_output_is_reviewable() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "find . -type f \\( -name \"*.ts\" -o -name \"*.json\" \\) -not -path \"*/node_modules/*\" | xargs grep -l canonical 2>/dev/null",
        "find . -type f \"(\" -name \"*.ts\" -o -name \"*.json\" \")\" | xargs grep -l canonical 2>&1",
        "find . -type f \\( -name \"*.ts\" \\) 2>/dev/null | xargs grep -l canonical",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
    // Only a redirect that discards output is read past. A write to a file
    // can follow a link the `xargs` program made from operands this text
    // does not hold, and a parameter target is not a path at all.
    for command in [
        "find . \\( -name a -o -name b \\) | xargs grep -l x 2>\"$LOG\"",
        "find /tmp/target \\( -type f \\) | xargs ln -s -t .; echo data >target",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// A double-quoted home directory is a fixed path, so a listing under it
/// that pipes into a named program reaches review instead of failing.
#[test]
fn a_quoted_home_root_does_not_fail_a_named_xargs_pipeline() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "find \"$HOME/.github/workflows\" -maxdepth 1 -type f -print 2>/dev/null | sort | xargs -r grep -nE 'runs-on|runner'",
        "find \"${HOME}/notes\" -type f | xargs grep -l todo",
        "printf '%s\\n' 'NVM:'; if [ -d \"$HOME/.nvm/versions/node\" ]; then find \"$HOME/.nvm/versions/node\" -mindepth 1 -maxdepth 1 -type d -print | sort; else echo '(missing)'; fi; printf '%s\\n' 'Workflow:'; if [ -f \"$HOME/.github/workflows\" ]; then :; fi; find \"$HOME/.github/workflows\" -maxdepth 1 -type f -print 2>/dev/null | sort | xargs -r grep -nE 'runs-on|runner' || true",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}\n{}", diagnose(command));
        assert_ne!(action, "block", "{command}: {code}");
    }
    for command in [
        "find \"$HOME/$DIR\" -type f | xargs grep -l todo",
        // Bash binds HOME without writing `HOME=`.
        "printf -v HOME -- -delete; find \"$HOME\" | xargs echo",
        "read HOME; find \"$HOME/notes\" -type f | xargs grep -l todo",
        "for HOME in /etc; do find \"$HOME\" -type f | xargs grep -l x; done",
        "HOME+=/x; find \"$HOME/notes\" -type f | xargs grep -l todo",
        // Quoting or escaping splits the name the shell still binds.
        "printf -v HO''ME -- -delete; find \"$HOME\" | xargs echo",
        "read HO\\ME; find \"$HOME/notes\" -type f | xargs grep -l todo",
        "for H\"\"OME in /etc; do find \"$HOME\" -type f | xargs grep -l x; done",
        "find $HOME/notes -type f | xargs grep -l todo",
    ] {
        assert_ne!(decision(&controls, command).0, "allow", "{command}");
    }
}

/// Subshells that only discard errors or join them to output move no data,
/// so a test run behind a manifest read reaches review instead of failing.
#[test]
fn a_subshell_chain_that_only_joins_errors_is_reviewable() {
    let controls = controls(github("enabled", None), false);
    let command = "ls -la && (cat package.json 2>/dev/null || true) && (npm test -- --runInBand 2>&1 || npm test 2>&1)";
    let (action, code) = decision(&controls, command);
    assert_ne!(code, FAILED, "{command}\n{}", diagnose(command));
    assert_ne!(action, "block", "{command}: {code}");
}

/// What each step of the xargs floor answered, for a failure message.
fn diagnose(command: &str) -> String {
    let request = crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: crate::default_dialect(),
        transport: crate::default_transport(),
        extraction_provenance: crate::default_provenance(),
    };
    let parsed = crate::parse_command(&request);
    let (reason, confidence, normalized) = match &parsed {
        Ok(parsed) => (
            parsed.uncertainty_reason.clone(),
            parsed.confidence.clone(),
            parsed.normalized_text.clone(),
        ),
        Err(error) => (Some(error.clone()), String::new(), String::new()),
    };
    let fixed = super::xargs::with_fixed_home(&normalized);
    let looked = super::without_lookups(&normalized);
    let shell = match super::data_heredocs(&looked) {
        Some((shell, _)) => shell,
        None => super::shell_text(&looked),
    };
    let bare = super::without_plain_awk(&super::without_redirections(&shell));
    let shell = super::without_plain_awk(&shell);
    let interpreted = super::named_words(&super::joined_quotes(&bare));
    let commanded = super::named_words(&super::joined_quotes(&super::text_in_command_positions(
        &bare,
    )));
    let hits: Vec<&str> = super::INTERPRETERS
        .iter()
        .copied()
        .filter(|name| interpreted.contains(*name) && commanded.contains(*name))
        .collect();
    format!(
        "reason={reason:?} confidence={confidence} names={} input={} fixed_rejects={} named_pipeline={} moves={} brace={} ansi={} synth={} hits={hits:?} xargs={:?} xinput={} exec={:?} fd={:?} shell={shell:?} normalized={normalized:?}",
        xargs_names_its_program(&normalized),
        xargs_input_is_named(&normalized),
        fixed.contains(['<', '`', '$', '\n']),
        super::named_xargs_pipeline(&normalized),
        super::moves_data(&super::unquoted_literal(&normalized)),
        crate::parser_brace_command::brace_runs_a_command_unquoted(&looked),
        shell.contains("$'") || shell.contains("$\""),
        super::synthesizes_program(&super::unquoted_literal(&shell), false),
        super::xargs_programs(&shell),
        xargs_input_is_named(&shell),
        super::find_exec_programs(&shell),
        super::fd_exec_programs(&shell),
    )
}

/// Reading the program out of an `xargs` leaves the operands standard input
/// supplies unread. An extension that owns that program judges arguments this
/// text does not hold, so the read-through does not stand in for its rules.
#[test]
fn an_xargs_into_a_programs_own_extension_stays_unreadable() {
    // Every permission enabled is the softest the extension gets; a disabled
    // or default permission only holds the command higher.
    let controls = controls(github("enabled", None), false);
    for command in [
        "xargs gh pr merge 17 --squash < list.txt",
        "cat list.txt | xargs gh pr close",
        "xargs -n 1 gh pr close",
        // A prefix option or a leading redirect is not the command, so the
        // `xargs` after it still names `gh`.
        "cat list.txt | xargs rm; time -p xargs gh pr merge < list.txt",
        "xargs rm < list.txt; 2>/dev/null xargs gh pr merge",
        "cat list.txt | xargs rm; command -p xargs gh pr close",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

#[test]
fn an_xargs_that_names_no_program_stays_unreadable() {
    let controls = controls(github("enabled", None), false);
    // With no operand `xargs` runs `echo`, and with its program fed in from
    // somewhere else the command names nothing to own it.
    for command in [
        "xargs < list.txt",
        "xargs -I {} < list.txt",
        "xargs sh -c 'rm -rf \"$1\"' _ < list.txt",
        // A pipe carries arguments into the program `xargs` names, and
        // nothing else: into a shell it carries the program itself.
        "cat list.txt | sh",
        "cat list.txt | xargs sh -c 'rm -rf \"$1\"' _",
        // An assignment or `export` still hides the program that runs, even
        // when the pipe ends in an `xargs` that names one.
        "LD_PRELOAD=./x.so find . | xargs rm -f",
        "export PATH=./evil; ls | xargs rm",
        // The boundary this keeps: a substitution still runs whatever it
        // prints, so `eval \"$(curl ...)\"` cannot be read from the text.
        "eval \"$(direnv hook bash)\"",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

#[test]
fn xargs_options_are_read_past_to_its_program() {
    for bounded in [
        "xargs rm",
        "xargs -0 rm -f",
        "xargs -n 20 rm",
        "xargs -n20 rm",
        "xargs -I{} cp {} /tmp",
        "xargs -i rm",
        "xargs -J rm evil",
        "xargs --max-args=3 rm",
        "xargs -- rm -f",
        "time -p xargs rm",
        "command -p xargs rm",
        "2>/dev/null xargs rm",
        "cat list.txt | xargs -P 4 -I {} mv {} archive/",
    ] {
        assert!(xargs_names_its_program(bounded), "{bounded}");
    }
    for unbounded in [
        "xargs",
        "xargs -0",
        // The value of `-I` is not the program.
        "xargs -I {}",
        // The program is the replacement token, so each input line names it.
        "xargs -I{} {}",
        "xargs -I X X",
        "xargs -I CMD CMD --flag",
        "cat list | xargs -I % %",
        // A clustered short option still carries `-I`, and `-J` takes the
        // replacement rather than the program.
        "xargs -0I{} {}",
        "xargs -tI X X",
        "xargs -0n 3 sh -c 'rm'",
        "xargs -J {} {}",
        "xargs -Z rm",
        // A non-ASCII short option is not a letter this reader knows, and
        // slicing it by bytes would panic inside the character.
        "xargs -é rm",
        "xargs --max-args 3",
        // A bare `--replace` leaves it open whether the next word is its
        // token or the program.
        "xargs --replace mv",
        "xargs --max-args 1 --replace ITEM mv",
        // A long option this does not know may take the next word.
        "xargs --future-option rm",
        // Programs this cannot read from the text.
        "xargs sh -c 'rm $0'",
        "xargs $tool",
        "xargs bin/*",
        // The word is an argument of `echo`, not an `xargs` invocation.
        "echo xargs rm",
        // An option this does not read past still hides the `xargs`.
        "time --portability xargs rm",
        "command -v xargs rm",
        "cat list.txt | xargs rm; time --foo xargs gh",
        // A wrapper this does not read past runs the `xargs` behind it, so
        // another piece's bounded `xargs` cannot speak for the whole text.
        "cat list.txt | xargs rm; env xargs gh pr merge",
        "cat list.txt | xargs rm; sudo xargs gh pr close",
        "cat list.txt | xargs rm; timeout 5 xargs gh pr merge",
        "cat list.txt | xargs rm; stdbuf -o0 xargs gh pr close",
        // The operand of an `xargs` is itself an unbounded `xargs`.
        "xargs xargs < list.txt",
        // Every `xargs` in the text has to name its program.
        "cat list.txt | xargs rm -f && cat more.txt | xargs",
    ] {
        assert!(!xargs_names_its_program(unbounded), "{unbounded}");
    }
}

/// A bare `xargs` takes the caller's standard input, so the operands it hands
/// the program it names are not in the text. `xargs rm -rf BUILD` deletes
/// whatever that input holds, and the text proves nothing about it.
#[test]
fn an_xargs_without_a_named_input_stays_unreadable() {
    for named in [
        "cat list.txt | xargs -0 rm -f",
        "find . -name '*.log' | xargs rm",
        "xargs rm -f < list.txt",
        "xargs -a list.txt rm -f",
        "xargs --arg-file=list.txt rm -f",
        "time -p cat list.txt | xargs rm",
        "time -p xargs rm < list.txt",
    ] {
        assert!(xargs_input_is_named(named), "{named}");
    }
    for unnamed in [
        "xargs rm -rf BUILD",
        "xargs rm -rf '<tmp>'",
        "xargs rm -rf < /dev/stdin",
        "xargs rm -rf <&0",
        "xargs rm -rf < /dev/fd/0",
        "xargs rm -rf < /proc/self/fd/0",
        "xargs rm 2<list.txt",
        "cat list.txt | xargs rm; time -p xargs gh",
        "xargs rm < list.txt; 2>/dev/null xargs gh",
        "xargs -a - rm",
        "xargs -a /dev/stdin rm",
        "xargs --arg-file=- rm",
        "xargs -0 rm -f",
        "xargs grep -a pattern",
        // The right side of a `||` follows no pipe.
        "test -f list.txt || xargs rm -f",
        // Every `xargs` in the text needs its own input.
        "cat list.txt | xargs rm -f && xargs rm -rf BUILD",
        // A wrapper this does not read past still runs an `xargs` on the
        // caller's standard input.
        "cat list.txt | xargs rm; env xargs gh pr merge",
        "cat list.txt | xargs rm; sudo xargs gh pr close",
    ] {
        assert!(!xargs_input_is_named(unnamed), "{unnamed}");
    }
}
