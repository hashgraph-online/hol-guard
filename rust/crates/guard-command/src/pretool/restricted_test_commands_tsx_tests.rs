//! The route a tsx test run keeps, and the words that take it away.
use super::readonly_test_reason;

const TSX: &str = "native_vitest_readonly_containment_required";

fn reason(command: &str) -> Option<&'static str> {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    readonly_test_reason(&model, None)
}

#[test]
fn a_tsx_test_run_keeps_its_route_through_the_node_runner_flags() {
    // `tsx` hands its arguments to Node, so a workspace test file run through
    // it carries the runner's own flags ahead of the script. The script is
    // still the one the sink loads, so the flags cannot move the route.
    for command in [
        "npx tsx --test __tests__/media.test.ts",
        "npx tsx --test --test-only __tests__/media.test.ts",
        "npx --no-install tsx --test --test-timeout=30000 src/parse.test.ts",
        "tsx --test-concurrency=4 src/parse.test.ts",
    ] {
        assert_eq!(reason(command), Some(TSX), "{command}");
    }

    // A reporter names a module to load and a file to write, so a run that
    // asks for one is not this shape and keeps its review.
    for command in [
        "npx tsx --test-reporter=spec __tests__/media.test.ts",
        "npx tsx --test --test-reporter-destination=out.txt src/parse.test.ts",
    ] {
        assert_ne!(reason(command), Some(TSX), "{command}");
    }
}

#[test]
fn a_word_behind_the_first_spec_is_another_file_the_test_runner_loads() {
    // In test-runner mode Node reads every remaining word as a test file, so
    // several workspace specs are one run of the shape the sink plans.
    for command in [
        "npx tsx --test __tests__/media.test.ts __tests__/cdn.test.ts",
        "tsx --test --test-only src/parse.test.ts src/render.test.ts",
        // A word behind the first spec is a path the runner loads, and the
        // leaf name a project gives it is not the boundary -- the workspace
        // is. `node --test scripts/deploy.ts` is contained today, and so is
        // `node --test ../elsewhere/payload.test.mjs`, which this screen
        // still refuses, so reading the tail here stays tighter than the
        // sibling profile it mirrors.
        "tsx --test src/parse.test.ts scripts/deploy.ts",
    ] {
        assert_eq!(reason(command), Some(TSX), "{command}");
    }

    // The same position is not inert argv. A word Node would load from
    // outside the workspace, or an option the run carries into the runtime,
    // is not a path the sink can resolve, so it keeps its review instead of
    // riding in behind the first spec.
    for command in [
        "npx tsx --test __tests__/media.test.ts ../elsewhere/payload.test.mjs",
        "npx tsx --test __tests__/media.test.ts /tmp/payload.test.mjs",
        "tsx --test src/parse.test.ts --expose-gc",
    ] {
        assert_ne!(reason(command), Some(TSX), "{command}");
    }

    // Without the runner flags Node runs the single script it is named, and
    // the rest of the line is that script's own arguments.
    assert_eq!(reason("tsx src/parse.test.ts --expose-gc"), Some(TSX));
}
