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
            Some(("src/parse.test.ts".to_owned(), vec![])),
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
fn test_mode_reads_every_word_behind_the_flags_as_a_file_node_loads() {
    // With `--test` Node is a test runner: each remaining word names another
    // file it loads, so a run that lists two workspace specs is still the
    // shape the sink plans, and the second file is read as a file.
    let command = words("tsx --test src/parse.test.ts src/render.test.ts");
    assert_eq!(
        tsx_test_invocation(&command).unwrap(),
        Some((
            "src/parse.test.ts".to_owned(),
            vec!["src/render.test.ts".to_owned()]
        ))
    );
    assert_eq!(
        tsx_test_runner_flags(&command).unwrap(),
        vec!["--test".to_owned()]
    );

    // The same position carries no inert argv: a word Node would load from
    // outside the workspace, or from a file the screen does not name a test,
    // leaves the run at review rather than riding in behind the first spec.
    for line in [
        "tsx --test src/parse.test.ts --expose-gc",
        "tsx --test src/parse.test.ts ../elsewhere/payload.test.mjs",
        "tsx --test src/parse.test.ts scripts/deploy.ts",
        "npx tsx --test src/parse.test.ts /tmp/payload.test.mjs",
    ] {
        assert_eq!(tsx_test_invocation(&words(line)).unwrap(), None, "{line}");
    }

    // Without the runner flags Node runs the one script it is given, and the
    // rest of the line is that script's own argv.
    let command = words("tsx src/parse.test.ts --expose-gc");
    assert_eq!(
        tsx_test_invocation(&command).unwrap(),
        Some((
            "src/parse.test.ts".to_owned(),
            vec!["--expose-gc".to_owned()]
        ))
    );
    assert!(tsx_test_runner_flags(&command).unwrap().is_empty());
}
