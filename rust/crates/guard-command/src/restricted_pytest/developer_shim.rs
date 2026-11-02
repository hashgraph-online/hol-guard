//! `/usr/bin` developer-tool shims resolved to the binary they forward to.
//!
//! macOS ships `/usr/bin/python3` and its siblings as small shims. Each one
//! asks `xcode-select` for the active developer directory and re-executes the
//! real tool inside it. Outside a sandbox that lookup is cheap, because the
//! answer is already cached.
//!
//! Inside a contained run it is not. The shim stats `/var/select/developer_dir`
//! and gets `EPERM` rather than `ENOENT`, which it treats as fatal instead of
//! falling back to its default, so ordinary work such as `python3 script.py`
//! failed with exit 1. Granting the link does not fix it either: the shim then
//! runs `xcrun`, which has no cache it may write, so it spawns `xcodebuild` and
//! loads Xcode's IDE plug-ins — all to answer a question the host can answer
//! before the sandbox is composed.
//!
//! So the plan resolves the shim itself. The concrete interpreter is what the
//! contained run execs, the profile grants that binary's own runtime root
//! through `runtime_roots`, and `xcode-select` never runs inside containment.
use super::toolchains::{developer_dir, selected_developer_dir};
use super::*;
use std::os::unix::fs::MetadataExt;

/// Where macOS keeps the shims. A tool found anywhere else is already the real
/// binary and is left alone.
const SHIM_DIRECTORY: &str = "/usr/bin";

/// The tool the selected developer directory holds under this name, when
/// `executable` is a shim that forwards into it.
///
/// `None` leaves the caller with the path it had: the executable is not a
/// `/usr/bin` shim, no sealed developer directory is selected, or that
/// directory holds no tool of that name. The result is canonical and checked
/// to be a regular executable file inside the developer directory, so the
/// directory cannot redirect a contained run to a path outside itself.
pub(super) fn forwarded_tool(executable: &Path) -> Option<PathBuf> {
    if executable.parent() != Some(Path::new(SHIM_DIRECTORY)) {
        return None;
    }
    let developer = selected_developer_dir()?;
    let resolved = developer
        .join("usr/bin")
        .join(executable.file_name()?)
        .canonicalize()
        .ok()?;
    if !path_is_within(&resolved, &developer) {
        return None;
    }
    let metadata = resolved.metadata().ok()?;
    (metadata.is_file() && metadata.mode() & 0o111 != 0).then_some(resolved)
}

/// Whether `path` is a tool inside the selected developer directory.
///
/// `TRUSTED_EXECUTABLE_ROOTS` holds the system prefixes a contained run may
/// exec, and the developer directory is not one of them: it is wherever
/// `xcode-select` points. It earns the same standing here because
/// [`selected_developer_dir`] accepts it only when it is root-owned and not
/// writable by others, which is the bar the toolchain roots are held to.
pub(super) fn is_developer_tool(path: &Path) -> bool {
    selected_developer_dir().is_some_and(|developer| path_is_within(path, &developer))
}

/// Whether `path` names a location inside the selected developer directory,
/// without following any link `path` itself is.
///
/// A symlink chain is checked one hop at a time, so each hop has to stand on
/// its own spelling. [`is_developer_tool`] follows the rest of the chain, which
/// would admit a writable intermediate link because of where it currently
/// points.
pub(super) fn is_in_developer_dir_lexically(path: &Path) -> bool {
    selected_developer_dir().is_some_and(|developer| path_is_within_lexically(path, &developer))
}

/// Put the selected developer directory's `usr/bin` on the sandbox `PATH`
/// just ahead of `/usr/bin`.
///
/// Otherwise a bare `python3` or `git` reaches the shim inside the sandbox,
/// and the shim's lookup there runs `xcrun`, which spawns `xcodebuild`. That
/// process cannot reach the services it wants, and its complaints land in
/// the command's own output. With the developer tools ahead of the shims the
/// shell finds the binary the shim forwards to, which is what
/// [`forwarded_tool`] answers on the other routes; the developer directory is
/// an executable root. An entry the session lists ahead of `/usr/bin` keeps
/// its place, so whatever the session finds before it still comes first.
pub(super) fn developer_tools_ahead_of_shims(entries: &mut Vec<String>) {
    let Some(tools) = sandbox_developer_tools() else {
        return;
    };
    let text = tools.to_string_lossy().into_owned();
    if text.contains(':') {
        return;
    }
    let Some(shims) = entries.iter().position(|entry| entry == SHIM_DIRECTORY) else {
        return;
    };
    match entries.iter().position(|entry| *entry == text) {
        Some(at) if at < shims => {}
        Some(at) => {
            entries.remove(at);
            entries.insert(shims, text);
        }
        None => entries.insert(shims, text),
    }
}

/// The file a bare `program` runs inside the sandbox when the session found
/// it at `canonical`: the tool a `/usr/bin` shim forwards to, because the
/// sandbox `PATH` holds the developer tools ahead of the shims. A path the
/// command spells out runs as spelled.
pub(super) fn sandbox_launched(program: &str, canonical: PathBuf) -> PathBuf {
    if program.contains('/') || sandbox_developer_tools().is_none() {
        return canonical;
    }
    forwarded_tool(&canonical).unwrap_or(canonical)
}

/// The selected developer directory's `usr/bin`, when the sandbox executes
/// from that directory. A developer directory kept anywhere but the sealed
/// prefixes `developer_dir` accepts is no executable root, so its tools stay
/// off the sandbox `PATH` and the shims keep answering for them.
fn sandbox_developer_tools() -> Option<PathBuf> {
    developer_dir()?;
    let tools = selected_developer_dir()?.join("usr/bin");
    tools.is_dir().then_some(tools)
}

#[cfg(test)]
mod tests {
    use super::{
        developer_tools_ahead_of_shims, forwarded_tool, is_developer_tool,
        is_in_developer_dir_lexically, path_is_within_any, sandbox_developer_tools,
        sandbox_launched,
    };
    use std::path::Path;

    #[test]
    fn a_tool_outside_the_shim_directory_keeps_its_path() {
        assert!(forwarded_tool(Path::new("/bin/ls")).is_none());
        assert!(forwarded_tool(Path::new("/opt/homebrew/bin/python3")).is_none());
        assert!(forwarded_tool(Path::new("python3")).is_none());
    }

    #[test]
    fn a_name_the_developer_directory_does_not_hold_resolves_to_nothing() {
        assert!(forwarded_tool(Path::new("/usr/bin/hol-guard-absent-tool")).is_none());
    }

    #[test]
    fn a_resolved_shim_is_an_executable_inside_the_developer_directory() {
        let Some(resolved) = forwarded_tool(Path::new("/usr/bin/python3")) else {
            // No sealed developer directory on this host: nothing to resolve,
            // and the shim keeps the path it had.
            return;
        };
        assert!(resolved.is_absolute());
        assert!(resolved.is_file());
        assert!(is_developer_tool(&resolved));
    }

    #[test]
    fn an_ordinary_system_path_is_not_a_developer_tool() {
        assert!(!is_developer_tool(Path::new("/bin/ls")));
    }

    /// A link outside the developer directory does not count as inside it
    /// because it currently points there: the chain check reads each hop as
    /// spelled, and the link can be repointed after approval.
    #[test]
    fn a_link_into_the_developer_directory_is_not_inside_it() {
        let Some(resolved) = forwarded_tool(Path::new("/usr/bin/python3")) else {
            return;
        };
        assert!(is_in_developer_dir_lexically(&resolved));
        let outside = tempfile::tempdir().unwrap();
        let link = outside.path().join("python3");
        std::os::unix::fs::symlink(&resolved, &link).unwrap();
        assert!(is_developer_tool(&link));
        assert!(!is_in_developer_dir_lexically(&link));
    }

    /// The shim resolution moved `/usr/bin/python3` into the developer
    /// directory, which is not a trusted root, so the gate that admits a
    /// contained interpreter has to make the same exemption the executable
    /// check makes. Without it this host's `python3 -m pytest` is refused at
    /// plan time and never reaches containment.
    #[test]
    fn a_shimmed_interpreter_is_admitted_for_a_contained_pytest_run() {
        let Some(resolved) = forwarded_tool(Path::new("/usr/bin/python3")) else {
            // No sealed developer directory on this host, so `/usr/bin/python3`
            // stays under a trusted root and this gate was never in question.
            return;
        };
        assert!(!path_is_within_any(
            &resolved,
            &super::super::TRUSTED_EXECUTABLE_ROOTS
        ));
        let workspace = std::env::temp_dir().canonicalize().unwrap();
        let command = vec![
            "/usr/bin/python3".to_owned(),
            "-m".to_owned(),
            "pytest".to_owned(),
        ];
        let (launch, executable) = super::super::validation::resolve_pytest_executable(
            &command, &workspace, &workspace, "/usr/bin",
        )
        .expect("a shimmed system interpreter is a valid contained pytest launcher");
        assert_eq!(executable, resolved);
        assert!(launch.ends_with("python3"));
        // The runner execs `plan.command`, so the shim must not survive into
        // it: the lookup it would make is the one resolution answered here.
        assert_eq!(
            super::super::authority::launched_path(&launch, &executable),
            resolved
        );
    }

    /// A launcher that forwards nowhere keeps its own path, so a virtual
    /// environment still execs its `bin/python` and keeps that prefix.
    #[test]
    fn a_launcher_that_is_not_a_shim_stays_in_the_command() {
        let launch = Path::new("/bin/ls");
        let executable = Path::new("/usr/bin/true");
        assert_eq!(
            super::super::authority::launched_path(launch, executable),
            launch
        );
    }

    /// The developer tools directory as the sandbox `PATH` spells it, when
    /// this host selects one.
    fn developer_tools() -> Option<String> {
        sandbox_developer_tools().map(|tools| tools.to_string_lossy().into_owned())
    }

    fn owned(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    #[test]
    fn developer_tools_go_just_ahead_of_the_shims() {
        let Some(tools) = developer_tools() else {
            return;
        };
        let mut entries = owned(&["/opt/homebrew/bin", "/usr/bin", "/bin"]);
        developer_tools_ahead_of_shims(&mut entries);
        assert_eq!(
            entries,
            owned(&["/opt/homebrew/bin", &tools, "/usr/bin", "/bin"])
        );
        // Placing them twice changes nothing.
        developer_tools_ahead_of_shims(&mut entries);
        assert_eq!(
            entries,
            owned(&["/opt/homebrew/bin", &tools, "/usr/bin", "/bin"])
        );
    }

    #[test]
    fn developer_tools_listed_behind_the_shims_move_ahead_of_them() {
        let Some(tools) = developer_tools() else {
            return;
        };
        let mut entries = owned(&["/usr/bin", "/opt/tools", &tools, "/bin"]);
        developer_tools_ahead_of_shims(&mut entries);
        assert_eq!(entries, owned(&[&tools, "/usr/bin", "/opt/tools", "/bin"]));
    }

    #[test]
    fn developer_tools_the_session_lists_earlier_keep_their_place() {
        // Moving them behind `/opt/homebrew/bin` would let a Homebrew `git`
        // answer inside the sandbox for the developer `git` the session ran.
        let Some(tools) = developer_tools() else {
            return;
        };
        let session = owned(&[&tools, "/opt/homebrew/bin", "/usr/bin", "/bin"]);
        let mut entries = session.clone();
        developer_tools_ahead_of_shims(&mut entries);
        assert_eq!(entries, session);
    }

    #[test]
    fn a_bare_shim_name_launches_the_tool_it_forwards_to() {
        let Some(resolved) = forwarded_tool(Path::new("/usr/bin/python3")) else {
            return;
        };
        if sandbox_developer_tools().is_none() {
            return;
        }
        let shim = Path::new("/usr/bin/python3").to_path_buf();
        assert_eq!(sandbox_launched("python3", shim.clone()), resolved);
        // A spelled-out shim path runs the shim itself.
        assert_eq!(sandbox_launched("/usr/bin/python3", shim.clone()), shim);
        let ls = Path::new("/bin/ls").to_path_buf();
        assert_eq!(sandbox_launched("ls", ls.clone()), ls);
    }
}
