use super::{wrapper_plan, CONTAINED_WRAPPER_PLAN_UNSUPPORTED};
use crate::pretool::workspace_contained_tests::workspace;

const HOME: &str = "/Users/nobody";

/// A relative `cd` that stays inside the workspace is peeled only for a sink
/// with no workspace sandbox.
///
/// Everywhere else the sandbox runs that text whole, which is the stronger
/// route and is the one the Python peel left it to by refusing the shape. The
/// refusal is what the sink answers by running the command in its sandbox, so
/// both arms have to be exercised from one host; the resident picks the arm
/// for the host it shares with the sink.
#[test]
fn a_relative_cd_inside_the_workspace_is_peeled_only_without_a_sandbox() {
    let root = workspace("plan-relative-cd", true);
    std::fs::create_dir_all(root.join("sub")).expect("sub");
    let workspace_path = root.to_str().expect("workspace path");
    let command = "cd sub && pytest -q 2>&1 | head -40";

    let sandboxless = wrapper_plan(
        command,
        workspace_path,
        Some(workspace_path),
        Some(HOME),
        true,
    );
    let peeled = sandboxless.plan.expect("peeled where no sandbox runs it");
    assert_eq!(peeled.core, "pytest -q");
    assert_eq!(
        std::fs::canonicalize(&peeled.directory).expect("directory"),
        std::fs::canonicalize(root.join("sub")).expect("sub")
    );
    let output = peeled.output.expect("head filter");
    assert_eq!(
        (output.kind, output.count, output.merge_stderr),
        ("head", 40, true)
    );

    let sandboxed = wrapper_plan(
        command,
        workspace_path,
        Some(workspace_path),
        Some(HOME),
        false,
    );
    assert_eq!(sandboxed.plan, None);
    assert_eq!(sandboxed.refusal, Some(CONTAINED_WRAPPER_PLAN_UNSUPPORTED));
}

/// An absolute `cd` into the workspace does not depend on the sink's host:
/// the Python peel accepted it everywhere, so both arms answer alike.
#[test]
fn an_absolute_cd_into_the_workspace_is_peeled_on_every_host() {
    let root = workspace("plan-absolute-cd", true);
    std::fs::create_dir_all(root.join("sub")).expect("sub");
    let workspace_path = root.to_str().expect("workspace path");
    let command = format!("cd {} && pytest -q", root.join("sub").display());

    for peels_relative_inside in [true, false] {
        let answer = wrapper_plan(
            &command,
            workspace_path,
            Some(workspace_path),
            Some(HOME),
            peels_relative_inside,
        );
        let peeled = answer.plan.expect("absolute cd peels");
        assert_eq!(peeled.core, "pytest -q");
    }
}

/// A pipeline the parse cannot model is still a wrapped shape.
///
/// `xargs` runs a program this model does not read, so the whole command
/// parses uncertain and carries no segments. The Python peel lexed the text,
/// saw the pipe and raised for the filter, and the sink answered that by
/// running the command whole in its sandbox. A silent `None` would send it
/// down the sink's other routes instead.
#[test]
fn an_unmodeled_pipeline_is_refused_rather_than_left_alone() {
    let root = workspace("plan-unmodeled-pipe", true);
    let workspace_path = root.to_str().expect("workspace path");

    for peels_relative_inside in [true, false] {
        let answer = wrapper_plan(
            "pytest -q | xargs rm",
            workspace_path,
            Some(workspace_path),
            Some(HOME),
            peels_relative_inside,
        );
        assert_eq!(answer.plan, None);
        assert_eq!(answer.refusal, Some(CONTAINED_WRAPPER_PLAN_UNSUPPORTED));
    }
}
