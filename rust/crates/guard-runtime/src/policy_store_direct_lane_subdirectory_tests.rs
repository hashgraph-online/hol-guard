use super::super::tests::{binding, fixture, push, write_current_ack, Fixture};
use super::super::{DirectLaneDefer, DIRECT_LANE_ACK_DIRECTORY, DIRECT_LANE_ACK_FILE_NAME};
use serde_json::json;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

const OVERLAYS: [&str; 2] = [".ai-plugin-scanner-guard.toml", ".hol-guard.toml"];

/// A bound lane whose settled workspaces are `bound`, each a directory under
/// the fixture's canonical root.
struct Lane {
    fixture: Fixture,
    root: PathBuf,
}

fn lane(label: &str, bound: &[&str]) -> Lane {
    let fixture = fixture(&format!("subdirectory-{label}"));
    let root = fs::canonicalize(&fixture.root).unwrap();
    let workspaces: Vec<String> = bound
        .iter()
        .map(|relative| {
            let directory = root.join(relative);
            fs::create_dir_all(&directory).unwrap();
            directory.to_str().unwrap().to_owned()
        })
        .collect();
    let mut direct_lane = binding(&fixture, &workspaces[0]);
    direct_lane["workspaces"] = json!(workspaces);
    push(&fixture, Some(direct_lane)).unwrap();
    write_current_ack(&fixture);
    Lane { fixture, root }
}

impl Lane {
    fn directory(&self, relative: &str) -> String {
        let directory = self.root.join(relative);
        fs::create_dir_all(&directory).unwrap();
        directory.to_str().unwrap().to_owned()
    }

    fn hook(&self, workspace: &str) -> Option<DirectLaneDefer> {
        self.fixture
            .store
            .admit_direct_hook_or_subdirectory(workspace)
            .err()
    }

    fn exact(&self, workspace: &str) -> Option<DirectLaneDefer> {
        self.fixture.store.admit_direct_hook(workspace).err()
    }
}

const UNKNOWN: Option<DirectLaneDefer> = Some(DirectLaneDefer::WorkspaceUnknown);

#[test]
fn a_bound_workspace_is_admitted_by_exact_match() {
    let lane = lane("exact", &["repo"]);
    let repo = lane.directory("repo");
    assert_eq!(lane.hook(&repo), None);
    assert_eq!(lane.exact(&repo), None);
}

#[test]
fn a_file_less_subdirectory_is_admitted_only_for_a_hook() {
    let lane = lane("file-less", &["repo"]);
    let nested = lane.directory("repo/src/deep");
    assert_eq!(lane.hook(&nested), None);
    assert_eq!(lane.hook(&lane.directory("repo/src")), None);
    // MCP relay admission keeps the exact bound set.
    assert_eq!(lane.exact(&nested), UNKNOWN);
}

#[test]
fn an_overlay_in_the_subdirectory_defers() {
    let lane = lane("overlay", &["repo"]);
    for (index, name) in OVERLAYS.iter().enumerate() {
        let file = lane.directory(&format!("repo/file-{index}"));
        fs::write(Path::new(&file).join(name), b"mode = \"observe\"\n").unwrap();
        assert_eq!(lane.hook(&file), UNKNOWN, "{name}");
        // A dangling link or a directory under the name is still present.
        let link = lane.directory(&format!("repo/link-{index}"));
        symlink(lane.root.join("absent"), Path::new(&link).join(name)).unwrap();
        assert_eq!(lane.hook(&link), UNKNOWN, "{name}");
        let directory = lane.directory(&format!("repo/dir-{index}"));
        fs::create_dir(Path::new(&directory).join(name)).unwrap();
        assert_eq!(lane.hook(&directory), UNKNOWN, "{name}");
    }
}

#[test]
fn an_overlay_in_an_intermediate_directory_is_not_read() {
    // The daemon reads only the subdirectory's own overlay files.
    let lane = lane("intermediate", &["repo"]);
    let middle = lane.directory("repo/middle");
    fs::write(
        Path::new(&middle).join(OVERLAYS[1]),
        b"mode = \"observe\"\n",
    )
    .unwrap();
    assert_eq!(lane.hook(&middle), UNKNOWN);
    assert_eq!(lane.hook(&lane.directory("repo/middle/leaf")), None);
}

#[test]
fn an_overlay_stat_error_other_than_not_found_defers() {
    let lane = lane("stat-error", &["repo"]);
    // A canonical regular file: each overlay `lstat` fails with ENOTDIR.
    let file = lane.root.join("repo/file.txt");
    fs::write(&file, b"x").unwrap();
    assert_eq!(lane.hook(file.to_str().unwrap()), UNKNOWN);
}

#[test]
fn a_subdirectory_that_is_not_its_own_realpath_defers() {
    let lane = lane("symlinked", &["repo"]);
    let target = lane.directory("repo/target");
    let inside = lane.root.join("repo/inside");
    symlink(&target, &inside).unwrap();
    assert_eq!(lane.hook(inside.to_str().unwrap()), UNKNOWN);
    // The hook resolves the link first; its target is admitted.
    assert_eq!(lane.hook(&target), None);
    let outside = lane.root.join("repo/outside");
    symlink(lane.directory("elsewhere"), &outside).unwrap();
    assert_eq!(lane.hook(outside.to_str().unwrap()), UNKNOWN);
    // The resolved target is file-less with no ancestor overlay.
    assert_eq!(lane.hook(&lane.directory("elsewhere")), None);
    // Strings that name a subdirectory without being canonical defer.
    let dotted = format!("{}/./target", lane.root.join("repo").to_str().unwrap());
    assert_eq!(lane.hook(&dotted), UNKNOWN);
    assert_eq!(lane.hook(&format!("{target}/")), UNKNOWN);
    assert_eq!(lane.hook(&format!("{target}/../target")), UNKNOWN);
    assert_eq!(lane.hook("repo/target"), UNKNOWN);
}

#[test]
fn descent_is_by_path_component_not_string_prefix() {
    let lane = lane("prefix", &["repo"]);
    // An overlay above both leaves only the settled descent to admit.
    fs::write(lane.root.join(OVERLAYS[1]), b"mode = \"observe\"\n").unwrap();
    assert_eq!(lane.hook(&lane.directory("repo/src")), None);
    assert_eq!(lane.hook(&lane.directory("repo2")), UNKNOWN);
    assert_eq!(lane.hook(&lane.directory("repo2/src")), UNKNOWN);
    assert_eq!(lane.hook(&lane.directory("rep")), UNKNOWN);
    assert_eq!(lane.hook(lane.root.to_str().unwrap()), UNKNOWN);
}

#[test]
fn nested_bound_roots_admit_their_subdirectories() {
    // The snapshot merges every settled workspace's overlay into one policy,
    // so any bound ancestor admits, as the daemon's `any` does.
    let lane = lane("nested", &["repo", "repo/inner"]);
    assert_eq!(lane.hook(&lane.directory("repo/inner/src")), None);
    assert_eq!(lane.hook(&lane.directory("repo/other")), None);
    assert_eq!(lane.hook(&lane.directory("repo/inner")), None);
}

#[test]
fn a_subdirectory_still_needs_the_ack_and_unchanged_inputs() {
    let lane = lane("lease", &["repo"]);
    let nested = lane.directory("repo/src");
    assert_eq!(lane.hook(&nested), None);
    let ack = lane
        .fixture
        .root
        .join(DIRECT_LANE_ACK_DIRECTORY)
        .join(DIRECT_LANE_ACK_FILE_NAME);
    fs::remove_file(ack).unwrap();
    assert_eq!(lane.hook(&nested), Some(DirectLaneDefer::AckMissing));
    write_current_ack(&lane.fixture);
    fs::write(&lane.fixture.input, b"mode = \"observe\"\n").unwrap();
    assert_eq!(lane.hook(&nested), Some(DirectLaneDefer::InputChanged));
}

#[test]
fn a_file_less_directory_without_an_ancestor_overlay_is_admitted() {
    // Its config is the home config, which the ACKed snapshot already holds.
    let lane = lane("unrelated", &["repo"]);
    let deep = lane.directory("other/project/src");
    assert_eq!(lane.hook(&deep), None);
    assert_eq!(lane.hook(&lane.directory("other")), None);
    // MCP relay admission keeps the exact bound set.
    assert_eq!(lane.exact(&deep), UNKNOWN);
}

#[test]
fn an_unsettled_ancestor_overlay_defers() {
    // Once it settles, the snapshot merges that overlay strictest-first.
    let lane = lane("ancestor", &["repo"]);
    for (index, name) in OVERLAYS.iter().enumerate() {
        let parent = lane.directory(&format!("file-{index}"));
        fs::write(Path::new(&parent).join(name), b"mode = \"observe\"\n").unwrap();
        assert_eq!(
            lane.hook(&lane.directory(&format!("file-{index}/a/b"))),
            UNKNOWN,
            "{name}"
        );
        // A dangling link under the name is still present.
        let linked = lane.directory(&format!("link-{index}"));
        symlink(lane.root.join("absent"), Path::new(&linked).join(name)).unwrap();
        assert_eq!(
            lane.hook(&lane.directory(&format!("link-{index}/a"))),
            UNKNOWN,
            "{name}"
        );
    }
    // A settled ancestor's overlay is already in the snapshot.
    fs::write(
        lane.root.join("repo").join(OVERLAYS[1]),
        b"mode = \"observe\"\n",
    )
    .unwrap();
    assert_eq!(lane.hook(&lane.directory("repo/src")), None);
}
