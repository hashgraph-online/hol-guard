use super::substitute;

fn substituted(command: &str) -> Option<String> {
    substitute(command)
}

#[test]
fn chained_uses_take_the_literal_assigned_earlier() {
    for (command, expected) in [
        (
            "export TODO_FILE=/tmp/todo_smoke.json && rm -f $TODO_FILE && ./todo.py add \"buy milk\" && ./todo.py list",
            "export TODO_FILE=/tmp/todo_smoke.json && rm -f /tmp/todo_smoke.json && ./todo.py add \"buy milk\" && ./todo.py list",
        ),
        (
            "F=out.txt; touch \"$F\" && cat ${F}",
            "F=out.txt; touch \"out.txt\" && cat out.txt",
        ),
        ("F=\"src/a.ts\" && wc -l $F", "F=\"src/a.ts\" && wc -l src/a.ts"),
        ("F='a.txt' && echo '$F' $F", "F='a.txt' && echo '$F' a.txt"),
        ("D=build && ls $D/out > $D.log", "D=build && ls build/out > build.log"),
        ("X=./todo.py && $X list", "X=./todo.py && ./todo.py list"),
        // A prefix setting applies after its command's words expand.
        (
            "F=a && F=b cat $F && rm $F",
            "F=a && F=b cat a && rm $F",
        ),
        // Only an assignment that always ran survives a `;`.
        (
            "F=a; G=b && H=c; cat $F $G $H",
            "F=a; G=b && H=c; cat a b $H",
        ),
        (
            "export LD_PRELOAD=./x.so && export F=a && cat $F $LD_PRELOAD",
            "export LD_PRELOAD=./x.so && export F=a && cat a $LD_PRELOAD",
        ),
    ] {
        assert_eq!(substituted(command).as_deref(), Some(expected), "{command}");
    }
}

#[test]
fn values_that_are_not_plain_literals_stay_unresolved() {
    for command in [
        "F=$(pwd)/x && rm $F",
        "F=`pwd`/x && rm $F",
        "F=$HOME/x && rm $F",
        "F=${HOME}/x && rm $F",
        "F=*.txt && rm $F",
        "F=\"a b\" && rm $F",
        "F='a'\"b\" && rm $F",
        "F=~/x && rm $F",
        "F= && rm $F",
        "F=if && $F true",
        "F=a && X=$F && rm $X",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn assignments_that_might_not_run_first_stay_unresolved() {
    for command in [
        "rm $F && F=a",
        "true || export F=a && rm $F",
        "false && F=a; rm $F",
        "F=a | cat && rm $F",
        "F=a cat x && rm $F",
        "(F=a) && rm $F",
        "F=a && (rm $F)",
        "F=a & rm $F",
        "F=a && rm $F &",
        "F=a && for x in 1; do rm $F; done",
        "F=a && if true; then rm $F; fi",
        "f() { F=a; } && rm $F",
        "F=a\nrm $F",
        "F=a && cat <<EOF $F",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn rebinding_by_other_means_stays_unresolved() {
    for command in [
        "F=a && read F && rm $F",
        "F=a && F+=b && rm $F",
        "F=a && F[1]=b && rm $F",
        "F=a && eval \"rm $F\"",
        "F=a && source env.sh && rm $F",
        "F=a && . ./env.sh && rm $F",
        "F=a && command export F=b && rm $F",
        "F=a && builtin read F && rm $F",
        "F=a && printf -v F x && rm $F",
        "F=a && declare F=b && rm $F",
        "F=a && export -n F && rm $F",
        "F=a && unset F && rm $F",
        "F=a && $G && rm $F",
        "F=a && cat x | read F; rm $F",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn special_and_unknown_variables_stay_unresolved() {
    for command in [
        "export PATH=/tmp/bin && ls $PATH",
        "export path=/tmp/bin && ls $path",
        "export LD_PRELOAD=./x.so && echo $LD_PRELOAD",
        "export DYLD_INSERT_LIBRARIES=./x.dylib && echo $DYLD_INSERT_LIBRARIES",
        "export NODE_OPTIONS=--require=./x.js && echo $NODE_OPTIONS",
        "export npm_config_prefix=/tmp && echo $npm_config_prefix",
        "export GIT_DIR=/tmp/x && echo $GIT_DIR",
        "export HOME=/tmp && cat $HOME",
        "export IFS=: && echo $IFS",
        "export GITHUB_TOKEN=abc && echo $GITHUB_TOKEN",
        "SECONDS=5 && echo $SECONDS",
        "F=a && rm $G",
        "rm -f $TODO_FILE",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn quoted_escaped_and_zsh_qualified_uses_are_left_alone() {
    for command in [
        "F=a && echo '$F'",
        "F=a && echo \\$F",
        "F=a && echo \"\\$F\"",
        "F=src/a.ts && echo $F:h",
        "F=a && echo $F[1]",
        "F=a && echo ~$F",
        "F=a && echo ${F:-b}",
        "F=a && echo ${#F}",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn a_changed_ifs_refuses_the_whole_chain() {
    // bash splits `$F` on the comma; the literal would be one operand.
    for command in [
        "IFS=,; F=build,/Users/me/.bashrc; rm -f $F",
        "export IFS=, && F=a,b && rm -f $F",
        "F=a,b && IFS=, cat x && rm -f $F",
        "F=a,b && zformat -f IFS , && rm -f $F",
        "F=a,b && printf -vIFS , && rm -f $F",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn non_ascii_text_refuses_the_whole_chain() {
    // zsh reads `$Dé` as the variable `Dé`, not `$D` followed by `é`.
    for command in [
        "D=build; rm -rf /ws/$D\u{e9}",
        "D=build; rm -rf /ws/$D && echo caf\u{e9}",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn a_command_naming_a_bound_variable_refuses_the_chain() {
    for command in [
        "X=build; zformat -f X /Users/me/.ssh; rm -rf $X",
        "X=build && zstyle -s ctx style X && rm -rf $X",
        // `zstyle -e` stores code that a later lookup runs.
        "x=/srv; c='x=/Users/me'; zstyle -e :x s 'eval $c'; zstyle -s :x s y; cat $x/.ssh/id_rsa",
        "X=build && strftime -s X %s 0 && rm -rf $X",
        "X=build && zstat -A X f && rm -rf $X",
        "X=build && sysread X && rm -rf $X",
        "X=build && getln -vX && rm -rf $X",
        "X=build && sometool --into=X && rm -rf $X",
        // The variable's name can reach the builtin through another binding.
        "N=X && X=build && zformat -f $N /tmp && rm -rf $X",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn quoted_or_escaped_names_still_count() {
    // The shell removes the quotes, so the builtin receives `OUT` or `IFS`.
    for command in [
        "OUT=build; zformat -f O\"UT\" /Users/me/.ssh; rm -rf $OUT",
        "OUT=build; zformat -f \"O\"\"UT\" /Users/me/.ssh; rm -rf $OUT",
        "OUT=build; zstyle -s :a b O\\UT; rm -rf $OUT",
        "OUT=build; zformat -f 'O'UT /Users/me/.ssh; rm -rf $OUT",
        "OUT=build; compgen -V O\"UT\" x; rm -rf $OUT",
        "OUT=build; getln -v'OUT'; rm -rf $OUT",
        "I\"FS\"=,; F=a,b; rm -f $F",
        "F=a,b; zformat -f 'IFS' ,; rm -f $F",
        // Substitution can assemble `IFS` that the raw text never spells.
        "N=I; compgen -V ${N}FS -W , ; F=a,b; rm -f $F",
        "N=F; zformat -f I${N}S ,; F=a,b; rm -f $F",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn special_parameters_are_never_reparsed_as_a_binding() {
    // `$$F` is the shell's PID followed by `F`, never `$` and then `$F`.
    for command in ["F=a && rm $$F", "F=a && rm $${F}", "F=a && rm $!F"] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[test]
fn text_the_pass_cannot_see_ends_substitution() {
    // An unresolved expansion or a glob could expand to a bound name.
    assert_eq!(
        substituted("X=build && cat $X && zformat -f $G /tmp && rm -rf $X").as_deref(),
        Some("X=build && cat build && zformat -f $G /tmp && rm -rf $X")
    );
    for command in [
        "X=build && zformat -f ? /tmp && rm -rf $X",
        "X=build && zformat -f [X] /tmp && rm -rf $X",
        "X=build && zformat -f $G /tmp && rm -rf $X",
    ] {
        assert_eq!(substituted(command), None, "{command}");
    }
}

#[cfg(unix)]
mod envelope {
    use crate::native_command_controls::CompiledNativeCommandControls;
    use crate::native_command_program::packaged_command_program;
    use guard_contracts::NativeCommandControlBindingV1;
    use std::path::{Path, PathBuf};

    const CONTAINED: &str = "native_workspace_containment_required";

    fn controls() -> CompiledNativeCommandControls {
        let program = packaged_command_program().unwrap();
        let mut binding: NativeCommandControlBindingV1 =
            serde_json::from_value(serde_json::json!({
                "schema": "guard.native-command-control-binding.v1",
                "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
                "trust_digest": program.trust_digest, "health": "protected",
                "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
            }))
            .unwrap();
        binding.effective_digest = binding.compute_effective_digest().unwrap();
        CompiledNativeCommandControls::new(&binding).unwrap()
    }

    fn workspace(name: &str, git: bool) -> PathBuf {
        let root = std::env::temp_dir().join(format!("guard-chain-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("package.json"), "{}").unwrap();
        if git {
            std::fs::create_dir_all(root.join(".git")).unwrap();
            std::fs::write(root.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
        }
        root.canonicalize().unwrap()
    }

    fn verdict(command: &str, cwd: &Path) -> (String, String) {
        let controls = controls();
        let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls),
            None,
            Some("/Users/nobody"),
            cwd.to_str(),
        );
        (result.minimum_action, result.reason_code)
    }

    fn host() -> bool {
        cfg!(target_os = "macos") || crate::restricted_pytest::linux_workspace_sandbox_available()
    }

    fn assert_judged_as_literal(raw: &str, literal: &str, cwd: &Path) {
        let (raw_action, raw_reason) = verdict(raw, cwd);
        let (literal_action, literal_reason) = verdict(literal, cwd);
        assert_eq!(raw_action, literal_action, "{raw}");
        if literal_action != "review" {
            assert_eq!(raw_reason, literal_reason, "{raw}");
        }
    }

    #[test]
    fn chained_uses_are_judged_as_their_literal() {
        let ws = workspace("judged", true);
        let raw = "export TODO_FILE=todo_smoke.json && rm -f $TODO_FILE && ./todo.py add x && ./todo.py list";
        let literal = "export TODO_FILE=todo_smoke.json && rm -f todo_smoke.json && ./todo.py add x && ./todo.py list";
        assert_judged_as_literal(raw, literal, &ws);
        if host() {
            assert_eq!(verdict(raw, &ws).1, CONTAINED);
        }
        assert_judged_as_literal(
            "F=package.json && cat $F && wc -l \"$F\"",
            "F=package.json && cat package.json && wc -l \"package.json\"",
            &ws,
        );
    }

    #[test]
    fn substituted_operands_keep_their_path_checks() {
        let ws = workspace("paths", true);
        for (raw, literal) in [
            (
                "export TODO_FILE=/tmp/todo_smoke.json && rm -f $TODO_FILE && ./todo.py add \"buy milk\" && ./todo.py done 1 && ./todo.py list",
                "export TODO_FILE=/tmp/todo_smoke.json && rm -f /tmp/todo_smoke.json && ./todo.py add \"buy milk\" && ./todo.py done 1 && ./todo.py list",
            ),
            ("F=../outside.txt && rm -f $F", "F=../outside.txt && rm -f ../outside.txt"),
            ("F=/var/tmp/x && rm -f $F", "F=/var/tmp/x && rm -f /var/tmp/x"),
        ] {
            assert_judged_as_literal(raw, literal, &ws);
            let (action, _) = verdict(raw, &ws);
            assert!(matches!(action.as_str(), "review" | "block"), "{raw}: {action}");
        }
        // A loader setting keeps exactly the treatment it has when written out.
        let raw = "export LD_PRELOAD=./x.so && export F=a.txt && touch $F";
        assert_judged_as_literal(
            raw,
            "export LD_PRELOAD=./x.so && export F=a.txt && touch a.txt",
            &ws,
        );
        assert_ne!(verdict(raw, &ws).0, "allow");
        let (action, _) = verdict("export F=package.json && cat $G", &ws);
        assert_eq!(action, "review");
    }

    #[test]
    fn working_directory_uses_are_judged_as_the_session_directory() {
        let ws = workspace("pwd", true);
        let d = ws.display();
        for (raw, literal) in [
            (
                "ln -s \"$(pwd)/node_modules\" ../x-wt/node_modules".to_owned(),
                format!("ln -s \"{d}/node_modules\" ../x-wt/node_modules"),
            ),
            (
                "ls \"$PWD\" && cat ${PWD}/package.json".to_owned(),
                format!("ls \"{d}\" && cat {d}/package.json"),
            ),
            (
                "cat $(pwd)/package.json; wc -l `pwd`/package.json".to_owned(),
                format!("cat {d}/package.json; wc -l {d}/package.json"),
            ),
        ] {
            // A sandbox launches the raw text, so a literal the workspace
            // sandbox contains leaves a raw `$PWD` form at its review.
            let (literal_action, literal_reason) = verdict(&literal, &ws);
            if host() && literal_action == "sandbox-required" && literal_reason == CONTAINED {
                assert_eq!(verdict(&raw, &ws).0, "review", "{raw}");
                continue;
            }
            assert_judged_as_literal(&raw, &literal, &ws);
        }
        // A plain read of a workspace file stays allowed. On macOS the
        // fixture lives below `/private/var/folders`, a system root that the
        // fake home cannot vouch for, so its literal is the contained case
        // above and the raw form keeps that review.
        let (literal_action, literal_reason) = verdict(&format!("cat {d}/package.json"), &ws);
        let contained =
            host() && literal_action == "sandbox-required" && literal_reason == CONTAINED;
        assert_eq!(
            verdict("cat $(pwd)/package.json", &ws).0,
            if contained { "review" } else { "allow" }
        );
        // A chain that also creates the sibling and runs a project script is
        // reviewed on its real operands instead of failing to evaluate.
        let chain = "git worktree add ../x-wt -b report && ln -s \"$(pwd)/node_modules\" ../x-wt/node_modules && cd ../x-wt && npm run report";
        let (action, reason) = verdict(chain, &ws);
        assert_ne!(action, "allow", "{reason}");
        assert_ne!(reason, super::super::EVALUATION_FAILED);
        // A Git read after the `cd` keeps Git's reapproval floor, not a
        // failed evaluation.
        let read = format!("{chain} && cat reports/weekly.md && git status --short");
        let (action, reason) = verdict(&read, &ws);
        assert_ne!(action, "allow", "{reason}");
        assert_ne!(reason, super::super::EVALUATION_FAILED);
        // After a directory change the expansion stays opaque.
        let (action, reason) = verdict("cd .git && cat $(pwd)/config", &ws);
        assert_ne!(action, "allow", "{reason}");
    }

    #[test]
    fn a_parent_substitution_is_judged_as_the_parent_it_prints() {
        let ws = workspace("parent", true);
        let parent = ws.parent().unwrap().display().to_string();
        let raw = "printf 'parent=%s\\n' \"$(dirname \"$PWD\")\"";
        let literal = format!("printf 'parent=%s\\n' \"{parent}\"");
        let producer = verdict(&format!("dirname {}", ws.display()), &ws);
        let (literal_action, _) = verdict(&literal, &ws);
        assert_eq!(literal_action, "allow", "{literal}");
        // Allowed, or contained by the sandbox because no read rule names it.
        if producer.0 == "allow" || (producer.0 == "sandbox-required" && producer.1 == CONTAINED) {
            assert_eq!(verdict(raw, &ws), verdict(&literal, &ws), "{producer:?}");
        } else {
            assert_ne!(verdict(raw, &ws).0, "allow", "{producer:?}");
        }
    }

    #[test]
    fn the_launcher_runs_only_the_raw_text_it_judged() {
        let ws = workspace("launcher", true);
        let raw = "export F=a.txt && touch $F && cat $F";
        let literal = "export F=a.txt && touch a.txt && cat a.txt";
        let shape = crate::pretool::workspace_exact_shape(raw, &ws);
        assert_eq!(
            shape.is_some(),
            crate::pretool::workspace_exact_shape(literal, &ws).is_some()
        );
        assert!(shape.is_none_or(|shape| shape.remainder.is_none() && shape.bootstrap.is_none()));
        // A bootstrapped `git init` would run a rewritten remainder, not the
        // raw text, so a substituted chain never gets that shape.
        let fresh = workspace("launcher-fresh", false);
        assert!(crate::pretool::workspace_exact_shape(
            "git init && export F=a.txt && touch $F",
            &fresh
        )
        .is_none());
    }
}
