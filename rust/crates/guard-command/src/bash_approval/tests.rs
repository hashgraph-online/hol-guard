use super::*;

const SCRIPT: &str = include_str!("../../../../../tests/fixtures/script_approvals/maintenance.sh");
const HELPER: &str =
    include_str!("../../../../../tests/fixtures/script_approvals/fixture-registry");

fn environment() -> BTreeMap<String, String> {
    BTreeMap::from([("HOME".to_owned(), "/isolated/home".to_owned())])
}

#[test]
fn expanded_words_and_repeated_operations_are_bounded() {
    let argv = ["script.sh".into()];
    let oversized = format!("printf '%s' '{}'", "x".repeat(MAX_WORD_BYTES + 1));
    assert!(analyze(&oversized, &argv, &environment()).is_err());
    let expanded = format!(
        "value='{}'; for item in {}; do printf '%s' \"$value\"; done",
        "x".repeat(MAX_WORD_BYTES),
        "x ".repeat(64)
    );
    assert!(analyze(&expanded, &argv, &environment()).is_err());
    let zero_args = "true;".repeat(MAX_OPERATIONS + 1);
    assert!(analyze(&zero_args, &argv, &environment()).is_err());
    let empty_arguments = format!("printf {}", "'' ".repeat(256));
    assert!(analyze(&empty_arguments, &argv, &environment()).is_err());
    let copies = format!(
        "large='{}'; {}",
        "x".repeat(MAX_WORD_BYTES),
        (0..40)
            .map(|index| format!("copy{index}=\"$large\"; "))
            .collect::<String>()
    );
    assert!(analyze(&copies, &argv, &environment()).is_err());
}

#[test]
fn exported_values_cannot_change_behind_a_helpers_environment_proof() {
    let environment = BTreeMap::from([("mode".into(), "before".into())]);
    for source in [
        "mode=after; printf x",
        "for mode in after; do printf x; done",
    ] {
        assert_eq!(
            analyze(source, &["script.sh".into()], &environment)
                .unwrap_err()
                .reason,
            "bash_exported_environment_assignment_unproven"
        );
    }
}

#[test]
fn shell_state_variables_never_become_ordinary_data() {
    for name in [
        "POSIXLY_CORRECT",
        "LC_COLLATE",
        "LC_CTYPE",
        "LANGUAGE",
        "TZ",
        "TMOUT",
        "FUNCNEST",
        "OPTERR",
        "HISTFILE",
        "HISTCONTROL",
        "MAILPATH",
        "PS1",
    ] {
        for source in [
            format!("{name}=value; printf x"),
            format!("for {name} in value; do printf x; done"),
            format!("printf '%s' \"${name}\""),
        ] {
            let mut context = environment();
            context.insert(name.into(), "value".into());
            assert!(
                analyze(&source, &["script.sh".into()], &context).is_err(),
                "accepted {source}"
            );
        }
    }
    assert!(analyze(
        "history_label=value; printf '%s' \"$history_label\"",
        &["script.sh".into()],
        &environment()
    )
    .is_ok());
}

#[test]
fn realistic_dry_and_delete_have_distinct_reachable_operations() {
    let dry = analyze(
        SCRIPT,
        &["maintenance.sh".into(), "dry".into()],
        &environment(),
    )
    .unwrap();
    let delete = analyze(
        SCRIPT,
        &["maintenance.sh".into(), "delete".into()],
        &environment(),
    )
    .unwrap();
    let calls = |analysis: &Analysis| {
        analysis
            .operations
            .iter()
            .filter(|op| op.argv[0] == "fixture-registry")
            .map(|op| op.argv.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        calls(&dry),
        vec![
            vec!["fixture-registry", "list", "alpha"],
            vec!["fixture-registry", "inspect", "alpha"],
            vec!["fixture-registry", "list", "beta"],
            vec!["fixture-registry", "inspect", "beta"]
        ]
    );
    assert_eq!(
        calls(&delete),
        vec![
            vec!["fixture-registry", "list", "alpha"],
            vec!["fixture-registry", "delete", "alpha", "obsolete"],
            vec!["fixture-registry", "list", "beta"],
            vec!["fixture-registry", "delete", "beta", "obsolete"]
        ]
    );
    assert_eq!(dry.writes.len(), 5);
    assert!(dry
        .writes
        .iter()
        .all(|write| write.path == "/isolated/home/maintenance-report.tsv"));
}

#[test]
fn helper_mode_dispatch_exposes_deletion_only_for_delete() {
    let run = |mode: &str| {
        analyze(
            HELPER,
            &[
                "fixture-registry".into(),
                mode.into(),
                "alpha".into(),
                "obsolete".into(),
            ],
            &environment(),
        )
        .unwrap()
    };
    assert!(!run("list").operations.iter().any(|op| op.argv[0] == "rm"));
    assert!(run("delete")
        .operations
        .iter()
        .any(|op| op.argv == ["rm", "--", "/isolated/home/fixture-registry/alpha/obsolete"]));
}

#[test]
fn dynamic_and_hidden_shell_effects_never_produce_partial_success() {
    for source in [
        "printf x; eval \"$code\"",
        "$(printf rm) file",
        "printf %s $HOME",
        "source ./helper.sh",
        "PATH=/other; tool",
        "for item in $(cat names); do tool \"$item\"; done",
        "trap 'rm file' EXIT",
        "tool > >(rm file)",
        "tool & rm file",
        "printf x |& cat",
        "IFS=/; tool",
        "mode=delete; mode+=dry; tool \"$mode\"",
        "case x in x) tool ;& y) rm file;; esac",
    ] {
        assert!(
            analyze(source, &["script.sh".into()], &environment()).is_err(),
            "accepted {source}"
        );
    }
}

#[test]
fn launch_internal_descriptors_cannot_change_script_tests() {
    for source in [
        "test -t 0",
        "test -f //dev//fd/6",
        "test -e /dev/./stdin",
        "test -e /proc/self/fd/6",
        "test -e /proc/thread-self/fd/6",
    ] {
        assert_eq!(
            analyze(source, &["script.sh".into()], &environment())
                .unwrap_err()
                .reason,
            "bash_process_descriptor_unproven"
        );
    }
    assert!(analyze(
        "printf '%s' '/dev/fd/6'; test -n /ordinary/report; test dry = dry; test 1 -eq 1",
        &["script.sh".into()],
        &environment()
    )
    .is_ok());
    for source in [
        "[ -p /dev/fd/6 ]",
        "test -p ./descriptor-alias/6",
        "test -f /ordinary/report",
        "test value -eq 1",
    ] {
        assert!(analyze(source, &["script.sh".into()], &environment()).is_err());
    }
}

#[test]
fn default_arguments_and_quoted_values_match_bash() {
    let result = analyze(
        "mode=${1:-dry}\nprintf '%s' \"$mode\"",
        &["script.sh".into()],
        &environment(),
    )
    .unwrap();
    assert_eq!(result.operations[0].argv, ["printf", "%s", "dry"]);
    let result = analyze(
        "printf '%s' \"${1:-dry}\"",
        &["script.sh".into(), "two words*".into()],
        &environment(),
    )
    .unwrap();
    assert_eq!(result.operations[0].argv, ["printf", "%s", "two words*"]);
}

#[test]
fn startup_and_builtin_state_cannot_hide_reachable_operations() {
    for key in [
        "BASH_ENV",
        "ENV",
        "BASH_FUNC_tool%%",
        "__BASH_FUNC<tool>()",
        "SHELLOPTS",
        "BASHOPTS",
        "POSIXLY_CORRECT",
    ] {
        let mut context = environment();
        context.insert(key.into(), "unbound startup input".into());
        assert_eq!(
            analyze("tool", &["script.sh".into()], &context)
                .unwrap_err()
                .reason,
            "bash_startup_inputs_unbound"
        );
    }
    for code in [
        "printf -v mode delete; tool \"$mode\"",
        "mode=dry; printf '%n' mode; tool \"$mode\"",
        "let mode=1; tool \"$mode\"",
        "shift; tool \"$1\"",
        "tool \"$_\"",
        "ulimit -n 1; tool",
    ] {
        assert!(
            analyze(code, &["script.sh".into(), "dry".into()], &environment()).is_err(),
            "accepted {code}"
        );
    }
}

#[test]
fn case_background_jobs_never_hide_later_operations() {
    for source in [
        "case x in x) exit & printf hidden ;; esac",
        "case x in x) printf first & printf hidden ;; esac",
        "case x in y) exit & printf hidden ;; x) printf selected ;; esac",
    ] {
        assert_eq!(
            analyze(source, &["script.sh".into()], &environment())
                .unwrap_err()
                .reason,
            "bash_control_operator"
        );
    }
    #[cfg(unix)]
    {
        let result = std::process::Command::new("/bin/bash")
            .args([
                "--noprofile",
                "--norc",
                "-c",
                "case x in x) exit & printf hidden ;; esac",
            ])
            .env_clear()
            .output()
            .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"hidden");
    }
}

#[test]
fn anonymous_word_tokens_cannot_disappear_from_the_analysis() {
    for source in [
        "printf '%s' \"mode$\"",
        "printf '%s' \"$\"",
        "printf '%s' \"safe\"$",
    ] {
        assert!(
            analyze(source, &["script.sh".into()], &environment()).is_err(),
            "accepted {source}"
        );
    }
    let result = analyze(
        "printf '%s' \"dollar\\$\" \"\" \"a\"\"b\"",
        &["script.sh".into()],
        &environment(),
    )
    .unwrap();
    assert_eq!(
        result.operations[0].argv,
        ["printf", "%s", "dollar$", "", "ab"]
    );
    let mut context = environment();
    context.insert("LANG".into(), "() { printf hidden; }".into());
    assert_eq!(
        analyze("printf x", &["script.sh".into()], &context)
            .unwrap_err()
            .reason,
        "bash_startup_inputs_unbound"
    );
}

#[test]
fn quoted_case_wildcard_is_literal_and_analysis_is_bounded() {
    let result = analyze(
        "case dry in '*') delete ;; dry) inspect ;; esac",
        &["script.sh".into()],
        &environment(),
    )
    .unwrap();
    assert_eq!(result.operations[0].argv, ["inspect"]);
    assert_eq!(
        analyze_before(
            "tool",
            &["script.sh".into()],
            &environment(),
            Instant::now()
        )
        .unwrap_err()
        .reason,
        "bash_analysis_timeout"
    );
    let code = "tool\n".repeat(1100);
    assert!(analyze(&code, &["script.sh".into()], &environment()).is_err());
}
