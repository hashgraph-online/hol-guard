//! `bun <dir>/node_modules/<package>/<entry>` starts an installed package's own
//! entrypoint, the same program `node <dir>/node_modules/<package>/<entry>`
//! starts. Bun reads a file operand as the script to run, so a path through
//! `node_modules` is never a package script name, an install verb or `bun x`.
//! The contained routes read it as the `node` spelling, and the contained-test
//! sink's own peel does the same (`crate::contained_run_prefix`), so it runs
//! the entrypoint on the project's Node image exactly as it runs
//! `bun x vite build`.

use crate::CanonicalCommandV1;
// A local file path with a `node_modules` component, as the contained-test
// sink's own peel reads it, so one shape decides both.
use crate::contained_run_prefix::installed_entry;

/// The command with each `bun <installed entrypoint>` segment spelled with
/// `node`, or `None` when no segment has that shape.
pub(super) fn node_spelling(model: &CanonicalCommandV1) -> Option<CanonicalCommandV1> {
    let started = |segment: &crate::CommandSegmentV1| {
        segment
            .executable
            .as_deref()
            .is_some_and(|executable| crate::program_basename(executable) == "bun")
            && segment
                .arguments
                .first()
                .is_some_and(|entry| installed_entry(entry))
    };
    if !model.segments.iter().any(started) {
        return None;
    }
    let mut spelled = model.clone();
    for segment in &mut spelled.segments {
        if started(segment) {
            segment.executable = Some("node".to_owned());
        }
    }
    Some(spelled)
}

#[cfg(test)]
mod tests {
    use super::node_spelling;

    fn model(command: &str) -> crate::CanonicalCommandV1 {
        crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap()
    }

    fn reason(command: &str) -> Option<&'static str> {
        let model = model(command);
        let spelled = node_spelling(&model);
        super::super::super::readonly_test_reason(spelled.as_ref().unwrap_or(&model), None)
    }

    #[test]
    fn an_installed_entrypoint_reads_as_its_node_run() {
        for (command, expected) in [
            (
                "bun dashboard/node_modules/vite/bin/vite.js build",
                "native_node_build_output_containment_required",
            ),
            (
                "bun /work/app/node_modules/vite/bin/vite.js build --root /work/tree/app",
                "native_node_build_output_containment_required",
            ),
            (
                "bun ./node_modules/vitest/vitest.mjs run",
                "native_vitest_readonly_containment_required",
            ),
            (
                "bun /work/app/node_modules/vitest/vitest.mjs run --root /work/tree/app",
                "native_vitest_readonly_containment_required",
            ),
            (
                "bun node_modules/eslint/bin/eslint.js src",
                "native_node_tool_readonly_containment_required",
            ),
        ] {
            let node = command.replacen("bun ", "node ", 1);
            assert_eq!(reason(command), Some(expected), "{command}");
            assert_eq!(reason(command), reason(&node), "{command}");
        }
    }

    #[test]
    fn other_bun_commands_keep_their_reading() {
        for command in [
            "bun install",
            "bun add left-pad",
            "bun x vite build",
            "bun run build",
            "bun test",
            "bun ./script.mjs",
            "bun src/report.ts",
            "bun https://example.com/node_modules/vite/bin/vite.js build",
            "bun --cwd node_modules/vite build",
            "bun node_modules/",
        ] {
            let model = model(command);
            assert!(node_spelling(&model).is_none(), "{command}");
        }
    }

    #[test]
    fn only_the_bun_segment_is_respelled() {
        let model = model("cd /work/tree/app && bun /work/app/node_modules/vitest/vitest.mjs run");
        let spelled = node_spelling(&model).unwrap();
        let names: Vec<_> = spelled
            .segments
            .iter()
            .map(|segment| segment.executable.as_deref())
            .collect();
        assert_eq!(names, [Some("cd"), Some("node")]);
        assert_eq!(spelled.segments[1].arguments, model.segments[1].arguments);
    }
}
