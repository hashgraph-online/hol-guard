//! The entry words a local runner or tool run may name, including the link
//! every installer writes beside the file a package publishes.
use super::readonly_test_reason;

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
fn the_installer_link_reads_as_the_entry_it_points_at() {
    // Every installer writes `node_modules/.bin/<binary>` as a link to the
    // file the package publishes, so `./node_modules/.bin/vitest` and `node
    // node_modules/vitest/vitest.mjs` are one run spelled two ways. Reading
    // only the second sends the first to review while the direct spelling
    // beside it runs contained.
    for command in [
        "node node_modules/.bin/vitest run",
        "node ./node_modules/.bin/vitest run src",
        "node dashboard/node_modules/.bin/vitest run",
        "node node_modules/.bin/jest",
        "node ./node_modules/.bin/jest src",
        "node node_modules/.bin/mocha test/unit",
        "bun node_modules/.bin/vitest run",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
    for command in [
        "node node_modules/.bin/tsc --noEmit",
        "node ./node_modules/.bin/eslint src",
        "node node_modules/.bin/prettier --check .",
    ] {
        assert_eq!(
            reason(command),
            Some("native_node_tool_readonly_containment_required"),
            "{command}"
        );
    }
    assert_eq!(
        reason("node node_modules/.bin/vite build"),
        Some("native_node_build_output_containment_required")
    );
    // A link to a program no profile names, and a `.bin` directory that is
    // not an installer's, stay where they were.
    for command in [
        "node node_modules/.bin/rimraf dist",
        "node vendored/.bin/vitest run",
        "node node_modules/.bin/vitest watch",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}
