use super::peel;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-sinkpeel-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("web")).unwrap();
    root.canonicalize().unwrap()
}

/// The peel as the sink calls it, from the workspace root with no home.
fn peeled(command: &str, workspace: &Path) -> Option<(String, PathBuf, Option<String>, u32)> {
    peel(command, workspace.to_str().unwrap(), None, None, false)
        .unwrap()
        .map(|core| {
            let kind = core.output.as_ref().map(|output| output.kind.to_owned());
            let count = core.output.as_ref().map_or(0, |output| output.count);
            (core.core, core.directory, kind, count)
        })
}

/// The directory flag's rewrite happens inside the peel, so the core the
/// sandbox runs has to carry the assignments the caller typed. A peel that
/// dropped them would run a different command from the one native authority
/// admitted: `PORT=3000` decides which port the build binds, and a build that
/// loses it answers on the default port instead.
#[test]
fn the_peeled_core_keeps_the_assignments_the_caller_typed() {
    let root = fixture("assignments");
    let web = root.join("web");
    for (command, core) in [
        (
            "PORT=3000 bun --cwd web run build",
            "PORT=3000 bun run build",
        ),
        (
            "PORT=3000 PROJECT=probe bun --cwd=web build",
            "PORT=3000 PROJECT=probe bun build",
        ),
        (
            "CI=1 LANG=C pnpm -C web run test",
            "CI=1 LANG=C pnpm run test",
        ),
        (
            "_UNDERSCORE=1 npm --prefix web run build",
            "_UNDERSCORE=1 npm run build",
        ),
        // A static value in double quotes is one word by the time the
        // program is called, so the peel carries it across unquoted.
        (
            "PORT=\"3000\" bun --cwd web run build",
            "PORT=3000 bun run build",
        ),
    ] {
        assert_eq!(
            peeled(command, &root),
            Some((core.to_owned(), web.clone(), None, 0)),
            "{command}"
        );
    }
}

/// An output filter after the manager call survives the rewrite, so the
/// sandbox still bounds what the run prints.
#[test]
fn an_output_filter_survives_the_assignments() {
    let root = fixture("filter");
    let web = root.join("web");
    assert_eq!(
        peeled("CI=1 npm --prefix web run build 2>&1 | tail -20", &root),
        Some((
            "CI=1 npm run build".to_owned(),
            web,
            Some("tail".to_owned()),
            20
        ))
    );
}

/// `PATH` is refused before the peel is reached (`path_overridden`), so the
/// sink refuses to peel past it too. Nothing is wrapped, and the whole text
/// goes to the sandbox rather than a core that silently kept a rewritten
/// executable search path.
#[test]
fn an_assignment_that_sets_the_search_path_is_not_peeled() {
    let root = fixture("path");
    for command in [
        "PATH=/tmp bun --cwd web run build",
        "PATH=/tmp:$PATH npm --prefix web run build",
        "CI=1 PATH=/tmp pnpm -C web run test",
    ] {
        assert_eq!(peeled(command, &root), None, "{command}");
    }
}

/// An assignment the peel cannot copy over as the word the source holds is
/// not peeled either: an expansion is read by the shell, so the sink does not
/// know the value the program would see. A word that is not an assignment at
/// all leaves no manager call to peel.
#[test]
fn an_assignment_the_sink_cannot_read_exactly_is_not_peeled() {
    let root = fixture("unreadable");
    for command in [
        "PORT=$OTHER bun --cwd web run build",
        "PORT=\"$OTHER\" bun --cwd web run build",
        "PORT=$(cat .port) bun --cwd web run build",
        "3PORT=3000 bun --cwd web run build",
    ] {
        assert_eq!(peeled(command, &root), None, "{command}");
    }
}

/// The labels a trailing report prints, as the sink reads them off the text.
fn reported(
    command: &str,
    workspace: &Path,
) -> (String, Option<String>, Option<String>, Option<String>) {
    let core = peel(command, workspace.to_str().unwrap(), None, None, false)
        .unwrap()
        .expect("the report wraps the command");
    let output = core.output.expect("a report describes the output");
    (
        core.core,
        output.status_label,
        output.success_label,
        output.failure_label,
    )
}

/// An agent closes a run with a line of its own. Each arm is read off the
/// text so the sink prints the one the shell would have reached, and the run
/// behind it keeps the core it would have had alone.
#[test]
fn a_trailing_report_leaves_the_core_alone_and_names_the_arm_it_prints() {
    let root = fixture("report");
    for (command, status, success, failure) in [
        ("bun run build; echo \"exit=$?\"", Some("exit="), None, None),
        ("bun run build; echo done", None, Some("done"), Some("done")),
        ("bun run build && echo PASS", None, Some("PASS"), None),
        ("bun run build || echo FAIL", None, None, Some("FAIL")),
        (
            "bun run build && echo PASS || echo FAIL",
            None,
            Some("PASS"),
            Some("FAIL"),
        ),
    ] {
        let (core, read_status, read_success, read_failure) = reported(command, &root);
        assert_eq!(core, "bun run build", "{command}");
        assert_eq!(read_status.as_deref(), status, "{command}");
        assert_eq!(read_success.as_deref(), success, "{command}");
        assert_eq!(read_failure.as_deref(), failure, "{command}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// An agent that pipes a run into `grep` and `head` cannot read the run's own
/// status from `$?`, which the filters have replaced, so it writes
/// `${PIPESTATUS[0]}`. That is the same report, and the sink answers it with
/// the core's own status rather than the one the chain left.
#[test]
fn a_report_reading_the_first_stage_status_is_read_as_a_report() {
    let root = fixture("report-pipestatus");
    let workspace = root.to_str().unwrap();
    for command in [
        "bun run build; echo \"exit=${PIPESTATUS[0]}\"",
        "bun run build 2>&1 | grep error | head -5; echo \"exit=${PIPESTATUS[0]}\"",
    ] {
        let core = peel(command, workspace, None, None, false)
            .unwrap()
            .expect("the report wraps the command");
        assert_eq!(core.core, "bun run build", "{command}");
        let output = core.output.expect("a report describes the output");
        assert_eq!(output.status_label.as_deref(), Some("exit="), "{command}");
        assert!(output.status_from_core, "{command}");
    }
    // After `&&` or `||` the array the echo would read is its own run's, so
    // the sequenced spelling is still the only report.
    for command in [
        "bun run build && echo \"exit=${PIPESTATUS[0]}\"",
        "bun run build || echo \"exit=${PIPESTATUS[0]}\"",
    ] {
        assert_eq!(peel(command, workspace, None, None, false).unwrap(), None);
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// A newline after `;`, `&&` or `||` is ordinary shell whitespace before
/// the report's echo, and must be read the same way as a horizontal blank.
#[test]
fn a_line_break_after_a_report_separator_is_preserved() {
    let root = fixture("report-newline");
    for (command, status, success, failure) in [
        (
            "bun run build;\n echo done",
            None,
            Some("done"),
            Some("done"),
        ),
        ("bun run build &&\n echo PASS", None, Some("PASS"), None),
        ("bun run build ||\n echo FAIL", None, None, Some("FAIL")),
        (
            "bun run build && echo PASS ||\n echo FAIL",
            None,
            Some("PASS"),
            Some("FAIL"),
        ),
    ] {
        let (core, read_status, read_success, read_failure) = reported(command, &root);
        assert_eq!(core, "bun run build", "{command}");
        assert_eq!(read_status.as_deref(), status, "{command}");
        assert_eq!(read_success.as_deref(), success, "{command}");
        assert_eq!(read_failure.as_deref(), failure, "{command}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// A report rides on whatever shaping the command already carries, so the
/// filter chain and the merge it describes are read beside its labels.
#[test]
fn a_trailing_report_keeps_the_shaping_in_front_of_it() {
    let root = fixture("report-shaped");
    let core = peel(
        "bun run build 2>&1 | tail -20 && echo PASS",
        root.to_str().unwrap(),
        None,
        None,
        false,
    )
    .unwrap()
    .expect("the chain wraps the command");
    let output = core.output.expect("a filtered run describes its output");
    assert_eq!(core.core, "bun run build");
    assert_eq!(output.kind, "tail");
    assert_eq!(output.count, 20);
    assert!(output.merge_stderr);
    assert_eq!(output.success_label.as_deref(), Some("PASS"));
    assert_eq!(output.failure_label, None);
    std::fs::remove_dir_all(root).unwrap();
}

/// An operator inside an argument is text the program reads, not a step the
/// shell runs. Truncating there would hand the sandbox half a word.
#[test]
fn an_operator_inside_a_quoted_argument_is_not_a_report() {
    let root = fixture("report-quoted");
    let core = peel(
        "bun run build --name 'a && echo PASS'",
        root.to_str().unwrap(),
        None,
        None,
        false,
    )
    .unwrap();
    assert!(core.is_none(), "{core:?}");
    std::fs::remove_dir_all(root).unwrap();
}

/// `echo -n`, `-e` and `-E` are options the shell's own echo consumes rather
/// than prints. The sink would print them as a label, so the text would not
/// match what the command produces and the run keeps its review.
#[test]
fn an_echo_option_word_is_not_a_report() {
    let root = fixture("report-option");
    for command in [
        "bun run build && echo -n PASS",
        "bun run build; echo -e done",
        "bun run build || echo -E FAIL",
        "bun run build; echo -n \"exit=$?\"",
    ] {
        let core = peel(command, root.to_str().unwrap(), None, None, false).unwrap();
        assert!(core.is_none(), "{command}: {core:?}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// A `|` inside a quoted word is text the program reads, such as a test-title
/// alternation, so the peel keeps the word and quotes it back whole. A list or
/// redirect character inside a word still refuses the peel.
#[cfg(unix)]
#[test]
fn a_quoted_alternation_survives_the_peel() {
    let root = fixture("alternation");
    let web = root.join("web");
    let cd = format!("cd {}", web.display());
    for (title, core) in [
        ("\"loads|saves\"", "bunx vitest run -t 'loads|saves'"),
        (
            "'stores the form|masks the field'",
            "bunx vitest run -t 'stores the form|masks the field'",
        ),
        ("loads\\|saves", "bunx vitest run -t 'loads|saves'"),
    ] {
        let command = format!("{cd} && bunx vitest run -t {title}");
        let (peeled_core, directory, _, _) = peeled(&command, &root).expect(&command);
        assert_eq!(peeled_core, core, "{command}");
        assert_eq!(directory, web, "{command}");
    }
    for title in ["\"a;b\"", "\"a&b\"", "\"a>b\"", "\"a<b\""] {
        let command = format!("{cd} && bunx vitest run -t {title}");
        assert!(
            peel(&command, root.to_str().unwrap(), None, None, false).is_err(),
            "{command}"
        );
    }
}
