use super::installed_program;
use crate::pretool::PathContext;
use std::path::Path;

/// The fixture's own root, removed when the test ends.
struct Fixture(tempfile::TempDir);

impl std::ops::Deref for Fixture {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.0.path()
    }
}

/// macOS keeps the per-user temporary directory under `/private/var`, a
/// system root the location screen refuses, so POSIX fixtures live under
/// `/tmp` on every platform.
#[cfg(unix)]
fn fixture_parent() -> std::path::PathBuf {
    std::path::PathBuf::from("/tmp")
}

#[cfg(not(unix))]
fn fixture_parent() -> std::path::PathBuf {
    std::env::temp_dir()
}

fn root(name: &str) -> Fixture {
    let holder = tempfile::Builder::new()
        .prefix(&format!("installed-program-{name}-"))
        .tempdir_in(fixture_parent())
        .unwrap();
    std::fs::create_dir_all(holder.path().join("project/.git")).unwrap();
    Fixture(holder)
}

/// An installed program's own launcher entry, the way an unpacked SDK writes
/// one: a link in the installation's `bin` to the file it shipped.
#[cfg(unix)]
fn installed(root: &Path, directory: &str, name: &str, target: &str) {
    let binaries = root.join(directory);
    std::fs::create_dir_all(&binaries).unwrap();
    let shipped = root.join(target);
    std::fs::create_dir_all(shipped.parent().unwrap()).unwrap();
    write_program(&shipped);
    std::os::unix::fs::symlink(&shipped, binaries.join(name)).unwrap();
}

fn write_program(path: &Path) {
    std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn proven(root: &Path, executable: &str) -> bool {
    spelled(root, &format!("{executable} get pods"), true)
}

/// The proof as the command itself spells it, so a quoted `~` is read the way
/// the shell reads it rather than the way the model records the word.
fn spelled(root: &Path, command: &str, shell_home_matches: bool) -> bool {
    spelled_from(root, &root.join("project"), command, shell_home_matches)
}

fn spelled_from(home: &Path, cwd: &Path, command: &str, shell_home_matches: bool) -> bool {
    let home = home.to_str().unwrap().to_owned();
    let cwd = cwd.to_str().unwrap().to_owned();
    let model = crate::parse_command(
        &serde_json::from_value(serde_json::json!({
            "command": command,
            "dialect": "posix",
            "transport": "shell_string",
            "provenance": "pre-tool-generic",
        }))
        .unwrap(),
    )
    .unwrap();
    let segment = model.segments.first().unwrap();
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    installed_program(
        segment,
        executable,
        PathContext {
            home_dir: Some(&home),
            cwd: Some(&cwd),
            shell_home_matches,
            ..Default::default()
        },
    )
}

#[cfg(unix)]
#[test]
fn an_installations_own_launcher_entry_is_proven() {
    let root = root("sdk");
    installed(&root, "sdk/bin", "kubectl", "sdk/platform/kubectl");
    assert!(proven(&root, "~/sdk/bin/kubectl"));
    assert!(proven(
        &root,
        root.join("sdk/bin/kubectl").to_str().unwrap()
    ));
}

/// The agent writes the checkout it is working in, so a `bin` there is a
/// directory it can fill rather than an installation.
#[cfg(unix)]
#[test]
fn a_launcher_directory_inside_the_checkout_is_not_an_installation() {
    let root = root("worktree");
    installed(
        &root,
        "project/vendor/bin",
        "kubectl",
        "project/vendor/kubectl",
    );
    assert!(!proven(&root, "vendor/bin/kubectl"));
}

/// The entry is a link into the version the installer unpacked, and that link
/// keeps the program's name. A link that renames another program into it says
/// nothing about what would run.
#[cfg(unix)]
#[test]
fn an_entry_that_renames_another_program_keeps_its_review() {
    let root = root("rename");
    installed(&root, "sdk/bin", "kubectl", "sdk/platform/sh");
    assert!(!proven(&root, "~/sdk/bin/kubectl"));
}

/// Only a launcher directory counts, not any directory that happens to hold a
/// file of the program's name.
#[cfg(unix)]
#[test]
fn a_directory_that_is_not_a_launcher_directory_is_not_one() {
    let root = root("libexec");
    installed(&root, "sdk/libexec", "kubectl", "sdk/platform/kubectl");
    assert!(!proven(&root, "~/sdk/libexec/kubectl"));
}

/// A file the shell would not execute is not the program the basename names.
#[test]
fn a_file_the_shell_could_not_run_is_not_the_program() {
    let root = root("plain");
    let binaries = root.join("sdk/bin");
    std::fs::create_dir_all(&binaries).unwrap();
    std::fs::write(binaries.join("kubectl"), "notes\n").unwrap();
    assert!(!proven(&root, "~/sdk/bin/kubectl"));
}

/// Nothing downstream reads the word again, so a spelling whose meaning
/// depends on where the shell starts is not resolved here.
#[cfg(unix)]
#[test]
fn a_parent_component_is_not_a_spelling_this_rule_proves() {
    let root = root("parent");
    installed(&root, "sdk/bin", "kubectl", "sdk/platform/kubectl");
    assert!(!proven(&root, "~/sdk/bin/../bin/kubectl"));
}

#[cfg(unix)]
#[test]
fn a_name_the_installation_does_not_hold_is_not_proven() {
    let root = root("absent");
    installed(&root, "sdk/bin", "kubectl", "sdk/platform/kubectl");
    assert!(!proven(&root, "~/sdk/bin/kubelet"));
}

/// The home spelling is the shell's own word, so it is proved only where the
/// shell expands it to the declared home. A quoted or escaped `~` is a
/// literal relative name the shell looks for under the working directory,
/// which the agent writes; a HOME the context cannot vouch for names some
/// other directory altogether.
#[cfg(unix)]
#[test]
fn a_home_spelling_is_proven_only_where_the_shell_expands_it() {
    let root = root("home-spelling");
    installed(&root, "sdk/bin", "kubectl", "sdk/platform/kubectl");
    assert!(spelled(&root, "~/sdk/bin/kubectl get pods", true));
    assert!(!spelled(&root, "~/sdk/bin/kubectl get pods", false));
    for command in [
        "\"~/sdk/bin/kubectl\" get pods",
        "'~/sdk/bin/kubectl' get pods",
        "~\"/sdk/bin/kubectl\" get pods",
        "\\~/sdk/bin/kubectl get pods",
    ] {
        assert!(!spelled(&root, command, true), "{command}");
    }
    // The absolute spelling carries no `~` for a quote to hold back, so it is
    // unchanged by either reading.
    let absolute = format!("{} get pods", root.join("sdk/bin/kubectl").display());
    assert!(spelled(&root, &absolute, true));
    assert!(spelled(&root, &absolute, false));
}

/// A prefix above home that the home owner installed into, the way Homebrew
/// owns `/opt/homebrew/bin`, names the same file the bare word finds on `PATH`.
/// Any other user who can add a name to the prefix or to a folder above it
/// could plant the program, so those keep their review.
#[cfg(unix)]
#[test]
fn a_prefix_the_home_owner_installed_into_above_home_is_proven() {
    use std::os::unix::fs::PermissionsExt;
    let root = root("prefix");
    let home = root.join("home");
    let cwd = home.join("project");
    std::fs::create_dir_all(cwd.join(".git")).unwrap();
    let mode = |path: &str, bits: u32| {
        std::fs::set_permissions(root.join(path), std::fs::Permissions::from_mode(bits)).unwrap();
    };
    let proven = |path: &str| {
        let command = format!("{} --version", root.join(path).display());
        spelled_from(&home, &cwd, &command, true)
    };
    installed(&root, "opt/brew/bin", "gh", "opt/brew/Cellar/gh/2.0/bin/gh");
    assert!(proven("opt/brew/bin/gh"));

    installed(
        &root,
        "opt/brew/bin",
        "python3",
        "opt/brew/Cellar/python/3.14/bin/python3.14",
    );
    assert!(
        proven("opt/brew/bin/python3"),
        "a link to the versioned file"
    );
    installed(
        &root,
        "opt/brew/bin",
        "python",
        "opt/brew/Cellar/python/3.14/bin/python3.14",
    );
    assert!(
        !proven("opt/brew/bin/python"),
        "a suffix that is not a version"
    );
    installed(
        &root,
        "opt/brew/bin",
        "gdu",
        "opt/brew/Cellar/gdu/1.0/bin/gh",
    );
    assert!(
        !proven("opt/brew/bin/gdu"),
        "a link that renames another program"
    );

    mode("opt/brew/bin", 0o777);
    assert!(!proven("opt/brew/bin/gh"), "a world-writable prefix");
    mode("opt/brew/bin", 0o1777);
    assert!(!proven("opt/brew/bin/gh"), "a sticky world-writable prefix");
    mode("opt/brew/bin", 0o755);
    mode("opt", 0o777);
    assert!(
        !proven("opt/brew/bin/gh"),
        "a world-writable folder above it"
    );
    mode("opt", 0o755);
    assert!(proven("opt/brew/bin/gh"));
}
