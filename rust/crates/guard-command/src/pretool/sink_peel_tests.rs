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
/// not peeled either: a quoted or expanded value is read by the shell, not by
/// the sink.
#[test]
fn an_assignment_the_sink_cannot_read_exactly_is_not_peeled() {
    let root = fixture("unreadable");
    for command in [
        "PORT=\"3000\" bun --cwd web run build",
        "PORT=$OTHER bun --cwd web run build",
        "3PORT=3000 bun --cwd web run build",
    ] {
        assert_eq!(peeled(command, &root), None, "{command}");
    }
}
