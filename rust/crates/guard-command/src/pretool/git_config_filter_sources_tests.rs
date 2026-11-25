use super::none_named;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn git_binary() -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|directory| directory.join(if cfg!(windows) { "git.exe" } else { "git" }))
        .find(|candidate| candidate.is_file())
        .unwrap()
}

/// A home whose global configuration defines the filters `git lfs install`
/// writes, and a repository with tracked files in nested folders.
struct Fixture {
    root: PathBuf,
    home: PathBuf,
    repository: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "guard-filter-sources-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let (home, repository) = (root.join("home"), root.join("repository"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(repository.join("src/nested")).unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tprocess = git-lfs filter-process\n",
        )
        .unwrap();
        let fixture = Self {
            root,
            home,
            repository,
        };
        fixture.git(&["init", "--quiet"]);
        fixture.write(".gitattributes", "*.json text eol=lf\n");
        fixture.write("README.md", "fixture\n");
        fixture.write("src/nested/app.rs", "fn main() {}\n");
        fixture.write("src/data.bin", "bytes\n");
        fixture.git(&["add", "."]);
        fixture
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.repository.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn git(&self, arguments: &[&str]) {
        assert!(Command::new(git_binary())
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", std::env::var_os("PATH").unwrap())
            .arg("-C")
            .arg(&self.repository)
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(arguments)
            .status()
            .unwrap()
            .success());
    }

    /// Git 2.42 and later report the attributes files they read.
    fn external_attribute_variables_supported(&self) -> bool {
        ["GIT_ATTR_GLOBAL", "GIT_ATTR_SYSTEM"]
            .iter()
            .all(|variable| {
                Command::new(git_binary())
                    .env_clear()
                    .env("HOME", &self.home)
                    .env("PATH", std::env::var_os("PATH").unwrap())
                    .arg("-C")
                    .arg(&self.repository)
                    .args(["var", variable])
                    .output()
                    .is_ok_and(|output| output.status.success())
            })
    }

    /// The quick check, run the way the filter proof runs Git.
    fn none_named(&self) -> bool {
        self.none_named_observed("", || {})
    }

    /// The quick check run from `folder` of the repository, with `before`
    /// run ahead of every Git query.
    fn none_named_observed(&self, folder: &str, before: impl Fn() + Sync) -> bool {
        let git = git_binary();
        let directory = self.repository.join(folder);
        let query = |arguments: &[&str], input: Option<Vec<u8>>, root: Option<&Path>| {
            assert!(input.is_none());
            before();
            let mut command = Command::new(&git);
            command
                .env_clear()
                .env("HOME", &self.home)
                .current_dir(&directory);
            if let Some(root) = root {
                command.arg("-C").arg(root);
            }
            let output = command.args(arguments).output().ok()?;
            output.status.success().then_some(output.stdout)
        };
        none_named(&query, Instant::now() + Duration::from_secs(10))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_global_filter_no_attributes_file_names_needs_no_per_path_check() {
    let fixture = Fixture::new("quiet");
    // Git before 2.42 does not expose both variables. The shortcut must
    // fall back on those hosts, not fail the suite.
    assert_eq!(
        fixture.none_named(),
        fixture.external_attribute_variables_supported()
    );
}

/// Git queries the quick check asks side by side.
const SIDE_BY_SIDE: usize = 5;

/// Runs the quick check from `folder` and returns its answer, the most Git
/// queries that were waiting at once, and how many were asked in all.
///
/// Each of the first [`SIDE_BY_SIDE`] queries holds until all of them have
/// started, so `most` reaches that count only when they really run at once,
/// however the threads are scheduled. Queried one after another, the first
/// gives up after the timeout and `most` stays at one.
fn observed(fixture: &Fixture, folder: &str) -> (bool, usize, usize) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    let (asked, waiting, most) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    let (started, all_started) = (Mutex::new(0usize), Condvar::new());
    let answer = fixture.none_named_observed(folder, || {
        asked.fetch_add(1, Ordering::SeqCst);
        let now = waiting.fetch_add(1, Ordering::SeqCst) + 1;
        most.fetch_max(now, Ordering::SeqCst);
        let mut count = started.lock().unwrap();
        *count += 1;
        all_started.notify_all();
        drop(
            all_started
                .wait_timeout_while(count, Duration::from_secs(10), |count| {
                    *count < SIDE_BY_SIDE
                })
                .unwrap(),
        );
        waiting.fetch_sub(1, Ordering::SeqCst);
    });
    (answer, most.into_inner(), asked.into_inner())
}

#[test]
fn the_independent_git_questions_are_asked_side_by_side() {
    // On a loaded machine every Git process takes a noticeable time to
    // start. Asked one after another, the location, configuration,
    // attributes-file and index questions used up a hook's budget in a large
    // checkout and sent a plain `git status` to review. The index listing
    // follows them once nothing has settled the answer.
    let fixture = Fixture::new("side-by-side");
    let supported = fixture.external_attribute_variables_supported();
    assert_eq!(
        observed(&fixture, ""),
        (
            supported,
            SIDE_BY_SIDE,
            SIDE_BY_SIDE + usize::from(supported)
        )
    );
}

#[test]
fn from_a_subfolder_the_index_is_listed_from_the_root() {
    // Below the root a listing holds only that folder's paths, so the check
    // must not read the rest of the work tree as untracked.
    let fixture = Fixture::new("subfolder");
    fixture.write("other/.gitattributes", "*.dat filter=lfs\n");
    fixture.write("other/blob.dat", "bytes\n");
    fixture.git(&["add", "."]);
    let (answer, most, asked) = observed(&fixture, "src");
    assert!(!answer);
    assert_eq!(most, SIDE_BY_SIDE);
    let supported = fixture.external_attribute_variables_supported();
    assert_eq!(asked, SIDE_BY_SIDE + usize::from(supported));
    // The same tree passes once the filter line is gone.
    fixture.write("other/.gitattributes", "*.dat binary\n");
    fixture.git(&["add", "."]);
    assert_eq!(
        observed(&fixture, "src"),
        (
            supported,
            SIDE_BY_SIDE,
            SIDE_BY_SIDE + usize::from(supported)
        )
    );
}

#[test]
fn a_filter_named_in_any_attributes_source_goes_to_the_full_check() {
    let nested = Fixture::new("nested");
    nested.write("src/.gitattributes", "*.bin filter=lfs diff=lfs\n");
    assert!(!nested.none_named());

    // A macro defined at the top and used below still names the filter.
    let macro_rule = Fixture::new("macro");
    macro_rule.write(
        ".gitattributes",
        "[attr]large FILTER=lfs\nsrc/*.bin large\n",
    );
    assert!(!macro_rule.none_named());

    let info = Fixture::new("info");
    info.write(".git/info/attributes", "*.bin filter=lfs\n");
    assert!(!info.none_named());

    let global = Fixture::new("global");
    std::fs::create_dir_all(global.home.join(".config/git")).unwrap();
    std::fs::write(
        global.home.join(".config/git/attributes"),
        "*.bin filter=lfs\n",
    )
    .unwrap();
    assert!(!global.none_named());
}

#[test]
fn sources_the_check_cannot_read_plainly_go_to_the_full_check() {
    // Attributes read out of a tree instead of the files.
    let tree = Fixture::new("tree");
    tree.git(&["config", "attr.tree", "HEAD"]);
    assert!(!tree.none_named());

    // A tracked attributes file missing from disk is read from the index.
    let missing = Fixture::new("missing");
    std::fs::remove_file(missing.repository.join(".gitattributes")).unwrap();
    assert!(!missing.none_named());

    // A gitlink sends status into another repository.
    let gitlink = Fixture::new("gitlink");
    gitlink.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        "160000,1111111111111111111111111111111111111111,module",
    ]);
    assert!(!gitlink.none_named());
}

#[cfg(unix)]
#[test]
fn a_linked_attributes_file_in_the_work_tree_goes_to_the_full_check() {
    let fixture = Fixture::new("linked");
    std::fs::write(fixture.root.join("elsewhere"), "*.bin filter=lfs\n").unwrap();
    std::os::unix::fs::symlink(
        fixture.root.join("elsewhere"),
        fixture.repository.join("src/.gitattributes"),
    )
    .unwrap();
    assert!(!fixture.none_named());
}

#[test]
fn the_full_check_still_finds_a_filter_the_quick_check_passed_on() {
    let fixture = Fixture::new("full");
    fixture.write("src/.gitattributes", "*.bin filter=lfs\n");
    let inspect = || {
        super::super::unused(
            &git_binary(),
            &[],
            &fixture.repository,
            &fixture.home,
            None,
            Instant::now() + Duration::from_secs(10),
            &[],
            true,
            true,
        )
    };
    assert_eq!(inspect(), Some(false));
    std::fs::remove_file(fixture.repository.join("src/.gitattributes")).unwrap();
    assert_eq!(inspect(), Some(true));
}

#[test]
fn a_custom_attributes_file_uses_the_full_proof() {
    // git var may lexically collapse a configured path that Git resolves
    // through a symlink before ".."; never rely on that path for an exemption.
    let custom = Fixture::new("custom-attributes");
    custom.git(&["config", "core.attributesFile", "../external/attrs"]);
    assert!(!custom.none_named());
}

#[test]
fn a_setting_that_settles_the_answer_never_lists_the_index() {
    // The full proof lists the index itself under the same deadline, so the
    // quick check must not spend that time on a listing it will not read.
    let tree = Fixture::new("settled-tree");
    tree.git(&["config", "attr.tree", "HEAD"]);
    assert_eq!(observed(&tree, ""), (false, SIDE_BY_SIDE, SIDE_BY_SIDE));
    let custom = Fixture::new("settled-custom");
    custom.git(&["config", "core.attributesFile", "../external/attrs"]);
    assert_eq!(observed(&custom, ""), (false, SIDE_BY_SIDE, SIDE_BY_SIDE));
}
