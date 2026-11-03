//! How a tsx run reads the Node test-runner flags and the words behind them.
use super::*;

fn words(line: &str) -> Vec<String> {
    line.split(' ')
        .map(ToOwned::to_owned)
        .collect::<Vec<String>>()
}

#[test]
fn a_tsx_test_run_reads_past_the_node_runner_flags() {
    for line in [
        "npx tsx --test src/parse.test.ts",
        "npx --no-install tsx --test --test-only src/parse.test.ts",
        "tsx --test-concurrency=4 --test-timeout=30000 src/parse.test.ts",
        "node ./node_modules/tsx/dist/cli.mjs --test src/parse.test.ts",
    ] {
        let command = words(line);
        assert_eq!(
            tsx_test_invocation(&command).unwrap(),
            Some((Some("src/parse.test.ts".to_owned()), vec![])),
            "{line}"
        );
        let flags = tsx_test_runner_flags(&command).unwrap();
        assert!(!flags.is_empty(), "{line}");
        assert!(
            flags.iter().all(|flag| flag.starts_with("--test")),
            "{line}"
        );
    }

    // A reporter names a module to load and a file to write, and a
    // concurrency that is not a number is not the flag this reads, so none of
    // them opens the run.
    for line in [
        "tsx --test-reporter=spec src/parse.test.ts",
        "tsx --test --test-reporter-destination=out.txt src/parse.test.ts",
        "tsx --test-concurrency=all src/parse.test.ts",
        "tsx --watch src/parse.test.ts",
    ] {
        let command = words(line);
        assert_eq!(tsx_test_invocation(&command).unwrap(), None, "{line}");
        assert!(
            tsx_test_runner_flags(&command).unwrap().is_empty(),
            "{line}"
        );
    }
}

#[test]
fn test_mode_reads_every_word_behind_the_flags_as_a_path_node_loads() {
    // With `--test` Node is a test runner: each remaining word names another
    // path it loads, so a run that lists two workspace specs is still the
    // shape the sink plans, and the second path is read as a path.
    let command = words("tsx --test src/parse.test.ts src/render.test.ts");
    assert_eq!(
        tsx_test_invocation(&command).unwrap(),
        Some((
            Some("src/parse.test.ts".to_owned()),
            vec!["src/render.test.ts".to_owned()]
        ))
    );
    assert_eq!(
        tsx_test_runner_flags(&command).unwrap(),
        vec!["--test".to_owned()]
    );

    // The same position carries no inert argv: a word Node would load from
    // outside the workspace leaves the run at review rather than riding in
    // behind the first spec.
    for line in [
        "tsx --test src/parse.test.ts --expose-gc",
        "tsx --test src/parse.test.ts ../elsewhere/payload.test.mjs",
        "npx tsx --test src/parse.test.ts /tmp/payload.test.mjs",
        "npx tsx --test ~/payload.test.mjs",
    ] {
        assert_eq!(tsx_test_invocation(&words(line)).unwrap(), None, "{line}");
    }

    // Without the runner flags Node runs the one script it is given, and the
    // rest of the line is that script's own argv.
    let command = words("tsx src/parse.test.ts --expose-gc");
    assert_eq!(
        tsx_test_invocation(&command).unwrap(),
        Some((
            Some("src/parse.test.ts".to_owned()),
            vec!["--expose-gc".to_owned()]
        ))
    );
    assert!(tsx_test_runner_flags(&command).unwrap().is_empty());
}

#[test]
fn the_test_runner_takes_the_paths_node_takes_rather_than_the_names_it_ignores() {
    // `node --test` runs whatever path it is handed: a spec whose leaf carries
    // no `.test` marker, a directory it walks, or nothing at all. Reading the
    // same line through tsx used to demand a test-shaped leaf and at least one
    // operand, so the same run was contained one way and sent to review the
    // other. The workspace is still the boundary -- the leaf name is not.
    for (line, script, arguments) in [
        (
            "npx tsx --test test/a.ts",
            Some("test/a.ts".to_owned()),
            vec![],
        ),
        ("npx tsx --test test/", Some("test/".to_owned()), vec![]),
        ("npx tsx --test", None, vec![]),
        (
            "tsx --test src/lib.ts test/a.ts",
            Some("src/lib.ts".to_owned()),
            vec!["test/a.ts".to_owned()],
        ),
        (
            "npx tsx --test --test-only test/a.ts",
            Some("test/a.ts".to_owned()),
            vec![],
        ),
    ] {
        assert_eq!(
            tsx_test_invocation(&words(line)).unwrap(),
            Some((script, arguments)),
            "{line}"
        );
    }

    // Outside test-runner mode the first word is a script Node runs, so its
    // leaf still has to name a test file and a bare `tsx` names nothing.
    for line in [
        "npx tsx src/index.ts",
        "npx tsx",
        "npx tsx watch src/app.ts",
    ] {
        assert_eq!(tsx_test_invocation(&words(line)).unwrap(), None, "{line}");
    }
}
