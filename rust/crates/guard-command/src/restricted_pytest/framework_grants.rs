//! Exec grants for framework interpreters in a contained macOS profile.
use super::authority::framework_exec_roots;
use super::*;
use std::os::unix::fs::MetadataExt;

/// The binary a framework Python's `bin/python3.x` stub re-execs, relative to
/// its `Versions/<x>` root.
const FRAMEWORK_INTERPRETER: &str = "Resources/Python.app/Contents/MacOS/Python";

/// How the framework interpreters among `executables` may be executed.
pub(super) struct FrameworkGrants {
    /// Version roots granted as a subpath.
    pub(super) roots: Vec<PathBuf>,
    /// Re-exec targets granted by literal path, beside the executables
    /// themselves, for roots that cannot take a subpath grant.
    pub(super) interpreters: Vec<PathBuf>,
}

/// Split the framework version roots of `executables` by who can write them.
///
/// A subpath grant over a directory someone can write would let the run
/// execute whatever was put there, so a root is granted as a subpath only when
/// it lies outside every writable root of the profile, outside the workspace
/// even under a read-only profile, and is root-owned and closed to group and
/// other writes from `/` down. A root outside the profile's writes that fails
/// only the ownership test, such as a Homebrew or python.org framework, keeps
/// literal grants: its executables, and the interpreter its stub re-execs,
/// which is no more exposed than the stub already granted. A root the run can
/// write gets nothing beyond the literal grant of its executables.
pub(super) fn framework_grants(
    executables: &[PathBuf],
    workspace: &Path,
    writes: &[PathBuf],
    sealed: impl Fn(&Path) -> bool,
) -> FrameworkGrants {
    let mut grants = FrameworkGrants {
        roots: vec![],
        interpreters: vec![],
    };
    for root in framework_exec_roots(executables) {
        if overlaps(&root, workspace) || writes.iter().any(|write| overlaps(&root, write)) {
            continue;
        }
        if sealed(&root) {
            grants.roots.push(root);
            continue;
        }
        let interpreter = root.join(FRAMEWORK_INTERPRETER);
        if interpreter.is_file() {
            grants.interpreters.push(interpreter);
        }
    }
    grants
}

/// Every directory from `/` down to `root` is root-owned and closed to group
/// and other writes.
pub(super) fn sealed_on_disk(root: &Path) -> bool {
    root.ancestors().all(|directory| {
        std::fs::metadata(directory)
            .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
    })
}

/// Whether either path holds the other, so a grant over one reaches the other.
fn overlaps(left: &Path, right: &Path) -> bool {
    path_is_within(left, right) || path_is_within(right, left)
}

#[cfg(test)]
mod tests {
    use super::{framework_grants, sealed_on_disk, FRAMEWORK_INTERPRETER};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn framework(root: &Path, name: &str) -> PathBuf {
        let version = root.join(name).join("Versions/A");
        fs::create_dir_all(version.join("bin")).unwrap();
        fs::write(version.join("bin/tool"), b"x").unwrap();
        let interpreter = version.join(FRAMEWORK_INTERPRETER);
        fs::create_dir_all(interpreter.parent().unwrap()).unwrap();
        fs::write(interpreter, b"x").unwrap();
        version
    }

    fn base(label: &str) -> PathBuf {
        std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("guard-framework-{label}-{}", std::process::id()))
    }

    #[test]
    fn a_framework_the_run_can_write_keeps_a_literal_grant() {
        let base = base("writable");
        let workspace = base.join("workspace");
        let output = base.join("output");
        let sealed = base.join("sealed");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&output).unwrap();
        fs::create_dir_all(&sealed).unwrap();
        let inside = framework(&workspace, "Foo.framework");
        let written = framework(&output, "Bar.framework");
        let toolchain = framework(&sealed, "Python.framework");

        let executables = vec![
            inside.join("bin/tool"),
            written.join("bin/tool"),
            toolchain.join("bin/tool"),
        ];
        let grants = framework_grants(&executables, &workspace, &[output.clone()], |_| true);

        assert_eq!(grants.roots, vec![toolchain]);
        assert!(grants.interpreters.is_empty());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_framework_another_account_can_write_grants_only_its_interpreter() {
        let base = base("unsealed");
        let workspace = base.join("workspace");
        let user_owned = base.join("Cellar");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&user_owned).unwrap();
        let toolchain = framework(&user_owned, "Python.framework");

        let executables = vec![toolchain.join("bin/tool")];
        let grants = framework_grants(&executables, &workspace, &[], sealed_on_disk);

        assert!(grants.roots.is_empty());
        assert_eq!(
            grants.interpreters,
            vec![toolchain.join(FRAMEWORK_INTERPRETER)]
        );
        fs::remove_dir_all(&base).unwrap();
    }
}
