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

    /// The quick check, run the way the filter proof runs Git.
    fn none_named(&self) -> bool {
        let git = git_binary();
        let query = |arguments: &[&str], input: Option<Vec<u8>>, root: Option<&Path>| {
            assert!(input.is_none());
            let mut command = Command::new(&git);
            command
                .env_clear()
                .env("HOME", &self.home)
                .current_dir(&self.repository);
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
    assert!(fixture.none_named());
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
