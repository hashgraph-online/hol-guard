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
    // Spelled as a user types it: the fixture root is canonical, which on
    // Windows carries a `\\?\` prefix whose `?` the peel reads as a glob.
    let sub = crate::runtime_read_paths::strip_verbatim_prefix(root.join("sub"));
    let command = format!("cd {} && pytest -q", sub.display());

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

/// A quoted `cd` target reaches the plan without its quotes, so both sinks
/// answer it as they answer the same directory spelled plainly: an absolute
/// target peels, and a relative one inside the workspace is left whole to
/// the sandbox.
#[cfg(unix)]
#[test]
fn a_quoted_cd_target_is_planned_as_its_plain_spelling() {
    let root = workspace("plan-quoted-cd", true);
    std::fs::create_dir_all(root.join("my dir")).expect("my dir");
    let workspace_path = root.to_str().expect("workspace path");
    let directory = root.join("my dir");
    for quote in ['\'', '"'] {
        let absolute = format!("cd {quote}{}{quote} && pytest -q", directory.display());
        let peeled = wrapper_plan(
            &absolute,
            workspace_path,
            Some(workspace_path),
            Some(HOME),
            false,
        )
        .plan
        .expect("a quoted absolute cd peels");
        assert_eq!(peeled.core, "pytest -q");
        assert_eq!(
            std::fs::canonicalize(&peeled.directory).expect("directory"),
            std::fs::canonicalize(&directory).expect("my dir")
        );
        let relative = format!("cd {quote}my dir{quote} && pytest -q");
        let sandboxed = wrapper_plan(
            &relative,
            workspace_path,
            Some(workspace_path),
            Some(HOME),
            false,
        );
        assert_eq!(sandboxed.plan, None, "{relative}");
        assert_eq!(sandboxed.refusal, Some(CONTAINED_WRAPPER_PLAN_UNSUPPORTED));
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

/// A byte bound is a filter stage like a line bound, and carries its unit to
/// the sink.
///
/// `| head -c 1500` prints part of the core's output and reads nothing else,
/// so the core is peeled and the stage travels as `head -c 1500` rather than
/// leaving the whole pipeline for review.
#[test]
fn a_byte_bounded_head_is_peeled_as_a_filter_stage() {
    let root = workspace("plan-byte-head", true);
    let workspace_path = root.to_str().expect("workspace path");
    let command = "pytest -q 2>&1 | head -c 1500";

    let peeled = wrapper_plan(
        command,
        workspace_path,
        Some(workspace_path),
        Some(HOME),
        true,
    )
    .plan
    .expect("peeled byte bound");
    assert_eq!(peeled.core, "pytest -q");
    let output = peeled.output.expect("byte filter");
    assert_eq!((output.kind, output.merge_stderr), ("pipe", true));
    assert_eq!(
        output.stages,
        vec![vec!["head".to_owned(), "-c".to_owned(), "1500".to_owned()]]
    );
}

/// `pnpm -w` names the workspace root without spelling it, so the sink peels
/// it into that root the way native authority projects it
/// (`package_directory_flags.rs`). Were it left unpeeled, the sink would read
/// the manifest nearest the working directory while pnpm runs the root
/// package's script, and a subpackage's `build` would stand in for the root's.
#[test]
fn the_pnpm_workspace_root_flag_peels_into_the_root_it_names() {
    let root = workspace("plan-pnpm-workspace-root", true);
    std::fs::write(root.join("pnpm-workspace.yaml"), "packages:\n  - web\n").expect("workspace");
    std::fs::create_dir_all(root.join("web")).expect("web");
    let workspace_path = root.to_str().expect("workspace path");
    let web = root.join("web");

    for (command, core, cwd) in [
        ("pnpm -w run build", "pnpm run build", root.clone()),
        ("pnpm --workspace-root build", "pnpm build", root.clone()),
        // Climbing out of the package it was typed in is how pnpm finds the
        // root, and the root is still inside the workspace the sink runs in.
        ("pnpm -w run build", "pnpm run build", web.clone()),
    ] {
        let peeled = wrapper_plan(command, workspace_path, cwd.to_str(), Some(HOME), false)
            .plan
            .unwrap_or_else(|| panic!("{command} from {}", cwd.display()));
        assert_eq!(peeled.core, core, "{command}");
        assert_eq!(
            std::fs::canonicalize(&peeled.directory).expect("directory"),
            root,
            "{command}"
        );
    }
}

/// Without a workspace to name there is no root to peel into, and the flag is
/// read in its two exact pnpm spellings only: npm's `-w` takes a workspace
/// *name*, so reading it as this flag would drop a word the run depends on.
#[test]
fn other_workspace_root_spellings_are_left_whole_by_the_sink() {
    let root = workspace("plan-pnpm-workspace-other", true);
    let workspace_path = root.to_str().expect("workspace path");
    for command in [
        "pnpm -w run build",
        "pnpm -wx run build",
        "npm -w web run build",
        "yarn -w run build",
    ] {
        assert!(
            wrapper_plan(
                command,
                workspace_path,
                Some(workspace_path),
                Some(HOME),
                false
            )
            .plan
            .is_none(),
            "{command}"
        );
    }
}
