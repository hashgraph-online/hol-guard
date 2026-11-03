//! How a cucumber-js run reads: which lines stay inside the workspace the
//! runner was installed in, and which words reach past it.
use super::reason;

#[test]
fn a_relative_cucumber_entry_reads_as_the_project_runner() {
    for command in [
        "node node_modules/@cucumber/cucumber/bin/cucumber.js",
        "node ./node_modules/.bin/cucumber-js features",
        "node /work/app/node_modules/@cucumber/cucumber/bin/cucumber.js features/login.feature",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_cucumber_run_inside_its_workspace_is_contained() {
    // cucumber-js has no watch mode and no command verbs: its operands are
    // feature files, directories or `FILE:LINE` locations, and the options
    // that load anything name a workspace path or a module specifier, which
    // the shared screen already answers for.
    for command in [
        "npx cucumber-js",
        "cucumber-js",
        "npx cucumber-js features/login.feature",
        "npx cucumber-js features/login.feature:12",
        "npx cucumber-js --require features/support/world.js",
        "npx cucumber-js -r features/step_definitions",
        "npx cucumber-js --import features/support/hooks.ts",
        "npx cucumber-js --config cucumber.cjs --profile ci",
        "npx cucumber-js --tags @smoke --fail-fast",
        "npx cucumber-js --format progress-bar",
        "npx cucumber-js --parallel 4 --retry 2",
        "npx cucumber-js --dry-run",
        "bunx cucumber-js features",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_cucumber_word_that_leaves_the_workspace_keeps_its_review() {
    // `--publish` uploads the report to cucumber's hosted service, which no
    // path on the line names; everything else the runner loads is a path the
    // workspace screen reads.
    for command in [
        "npx cucumber-js --publish",
        "npx cucumber-js --publish=false",
        "npx cucumber-js features --publish",
        "npx cucumber-js /etc/features",
        "npx cucumber-js --require /etc/world.js",
        "npx cucumber-js --config ../../other/cucumber.cjs",
        "npx cucumber-js --import ~/.cucumber/hooks.js",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_cucumber_formatter_that_writes_a_file_keeps_its_review() {
    // `--format TYPE:TARGET` sends the formatter's output to the target
    // instead of the terminal, and the contained profile mounts the project
    // read-only, so the run would be admitted and then fail on the open.
    // The target is read off the word that carries it, so a short cluster
    // spells it no differently: `-df html:out.html` reaches the same check.
    for command in [
        "npx cucumber-js --format html:reports/cucumber.html",
        "npx cucumber-js --format=json:reports/cucumber.json",
        "npx cucumber-js -f junit:report.xml",
        "npx cucumber-js -fhtml:report.html",
        "npx cucumber-js -df html:report.html",
        "npx cucumber-js --format message:/dev/stdout",
        "npx cucumber-js --format html:/tmp/cucumber.html",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}
