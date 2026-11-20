//! How a package manager spelling peels to the script or tool it runs.
use super::reason;

#[test]
fn a_package_script_run_keeps_the_words_it_passes_on() {
    // `npm run lint -- --max-warnings=0` runs the project's own lint script
    // with one more checking option. The manager hands the words after `--`
    // to the script, so they belong to the run the manifest spells and the
    // run is still the read-only tool the script names.
    for command in [
        "npm run lint -- --max-warnings=0",
        "npm run lint -- --max-warnings 0",
        "npm run typecheck -- --pretty",
        "pnpm lint -- --max-warnings=0",
        "yarn typecheck -- --pretty",
        "bun run lint -- --max-warnings=0",
    ] {
        assert_eq!(
            reason(command),
            Some("native_node_tool_readonly_containment_required"),
            "{command}"
        );
    }
    // Words that write or chain are refused wherever they sit, and a tail is
    // only a tail when `--` introduces it.
    for command in [
        "npm run lint -- --fix",
        "npm run lint -- --output-file out.txt",
        "npm run lint -- --max-warnings=0 && rm -rf dist",
        "npm run lint extra",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_passed_on_word_cannot_turn_a_reporting_tool_into_a_writing_one() {
    // The tail is the agent's own text, and the tool reads it as part of its
    // own command line. TypeScript takes an optional `true`/`false` after a
    // boolean option, so `tsc --noEmit false` compiles and writes while the
    // script's `--noEmit` is still there; `--init`, `--outDir` and the trace
    // options write without touching `--noEmit` at all. Each is refused at
    // the admission and left to ordinary review rather than reaching the sink
    // as a read-only run.
    for command in [
        "npm run typecheck -- false",
        "npm run typecheck -- --noEmit false",
        "npm run typecheck -- --init",
        "npm run typecheck -- --outDir dist",
        "npm run typecheck -- --outFile bundle.js",
        "npm run typecheck -- --build",
        "npm run typecheck -- --generateTrace trace",
        "npm run typecheck -- --generateCpuProfile profile.cpuprofile",
        "npm run typecheck -- --declaration",
        "pnpm typecheck -- false",
        "yarn typecheck -- --init",
        "bun run typecheck -- --noEmit false",
        // ESLint's formatter is a module the run loads, and a count is a
        // count: neither a path nor a word of another shape is a value this
        // option takes.
        "npm run lint -- --format ./reporter.js",
        "npm run lint -- --max-warnings false",
        "npm run lint -- src",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_quiet_manager_run_takes_the_route_its_loud_spelling_takes() {
    // An option that only chooses how much the manager prints names no
    // script. Reading it as one left `npm --silent test` and
    // `npm run --silent lint` under review while the same runs spelled
    // without the option were admitted, which is the whole false positive.
    for command in [
        "npm --silent test",
        "npm -s test",
        "npm run --silent test",
        "npm --loglevel error test",
        "npm --loglevel=error run test",
        "pnpm -s test",
        "pnpm --reporter silent test",
        "yarn --silent test",
        "bun run --silent test",
        "bun --silent run test",
    ] {
        assert_eq!(
            reason(command),
            Some("native_package_test_readonly_containment_required"),
            "{command}"
        );
    }
    for command in [
        "npm run --silent lint",
        "npm --silent run lint",
        "npm run --silent typecheck",
        "pnpm -s lint",
        "yarn --silent typecheck",
    ] {
        assert_eq!(
            reason(command),
            Some("native_node_tool_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn an_option_that_moves_or_fans_out_a_manager_run_is_not_peeled() {
    // The peeled options are the manager's own reporting options. An option
    // that changes the directory the run reads, or fans it out across a
    // workspace, names a different run, so it keeps ordinary review rather
    // than borrowing the narrow receipt the quiet spelling now takes.
    for command in [
        "npm --prefix ../other test",
        "npm -C ../other test",
        "npm --workspaces test",
        "npm --workspace web run lint",
        "pnpm -r test",
        "bun --filter web run test",
        "bun --bun run test",
        "pnpm --filter web test",
        "yarn --cwd ../other test",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_managers_own_verb_alias_takes_the_route_the_canonical_spelling_takes() {
    // npm's command table maps `run-script`, `rum` and `urn` onto `run`, and
    // `t` and `tst` onto `test`; pnpm carries `run-script`, `t` and `tst`.
    // Each alias starts exactly what the canonical spelling starts, so
    // reading only the canonical word left the alias under review while the
    // same run spelled plainly beside it was admitted.
    for command in [
        "npm run-script test",
        "npm rum test",
        "npm urn test",
        "npm run-script test:unit",
        "pnpm run-script test",
        "npm t",
        "npm tst",
        "pnpm t",
        "pnpm tst",
        "npm --silent t",
        "npm run-script --silent test",
    ] {
        assert_eq!(
            reason(command),
            Some("native_package_test_readonly_containment_required"),
            "{command}"
        );
    }
    for command in [
        "npm run-script lint",
        "npm urn typecheck",
        "pnpm run-script lint",
        "npm run-script --silent lint",
    ] {
        assert_eq!(
            reason(command),
            Some("native_node_tool_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_word_a_manager_does_not_alias_stays_a_script_name() {
    // yarn and bun carry none of these aliases and pass a bare word to the
    // manifest, so reading one as a verb would admit a script the line never
    // named. `npm run t` is the manifest's own `t` entry for the same reason:
    // the alias is a top-level command, not a script name.
    for command in [
        "yarn run-script test",
        "bun run-script test",
        "pnpm rum test",
        "pnpm urn test",
        "yarn t",
        "bun t",
    ] {
        assert_ne!(
            reason(command),
            Some("native_package_test_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn npm_reads_its_reporting_options_after_the_script_name_too() {
    // npm's own parser takes its configuration options anywhere on the line,
    // so a trailing one is npm's word rather than the script's. Measured
    // against npm 11.6.2, the test script's argv is empty for each of these
    // runs, yet reading the tail as a test argument left the quiet spelling
    // under review while the loud one beside it was admitted.
    for command in [
        "npm test --silent",
        "npm test -s",
        "npm test --loglevel=error",
        "npm test --loglevel error",
        "npm run test --silent",
        "npm --silent test -s",
        // npm hands the script only the words after `--`, so the tail that
        // follows the peeled option is still the script's own.
        "npm test --silent -- --coverage",
    ] {
        assert_eq!(
            reason(command),
            Some("native_package_test_readonly_containment_required"),
            "{command}"
        );
    }
    // pnpm, yarn and Bun pass the same word through to the script, where it
    // is the runner's option and not the manager's, so those spellings still
    // need the `--` that says so. An npm option that moves the run, and a
    // bare word, are not reporting options at either end of the line.
    for command in [
        "pnpm test --silent",
        "yarn test --silent",
        "bun run test --silent",
        "npm test --prefix ../other",
        "npm test --workspaces",
        "npm test extra",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}
