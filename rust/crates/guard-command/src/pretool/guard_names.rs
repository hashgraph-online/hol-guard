//! Which arguments name Guard's own state, programs or installation for the
//! fixed floor that no extension Allow settles.
//!
//! Git and the shell's directory changes take repository paths, refs and
//! remote URLs. A checkout called `hol-guard-pr-12`, a pathspec such as
//! `scripts/hol-guard.wxs` or a remote `https://host/org/hol-guard.git` is the
//! user's work, not Guard. For those programs an argument names Guard only
//! when it reaches Guard's state directory, an installed Guard program or the
//! desktop application. Other programs keep the plain name screen.

/// Programs whose arguments are judged by [`names_guard_location`].
const LOCATION_PROGRAMS: &[&str] = &["git", "cd", "pushd"];

/// Executable and package names Guard installs.
const GUARD_PROGRAMS: &[&str] = &[
    "hol-guard",
    "plugin-guard",
    "hol-guard-runtime",
    "hol-guard-core",
    "hol_guard",
];

/// Directories an installed program lives in. A Guard program name directly
/// below one of them is Guard's installation rather than a checkout.
const INSTALL_PARENTS: &[&str] = &[
    "bin",
    "sbin",
    "scripts",
    "venvs",
    "tools",
    "site-packages",
    "dist-packages",
    "cellar",
    "opt",
    "programs",
    "program files",
    "program files (x86)",
    "applications",
    // Guard's system state and bundled runtime: `/etc/hol-guard`,
    // `/var/lib/hol-guard`, `lib/hol-guard-core/hol-guard`.
    "etc",
    "lib",
    "share",
    "hol-guard-core",
];

/// Folder names the desktop application and its state use, which count as
/// Guard only below one of [`APP_PARENTS`] or as the `.app` bundle.
const APP_NAMES: &[&str] = &["hol guard", "hol guard state"];

/// Directories the desktop application or its state are installed in.
const APP_PARENTS: &[&str] = &[
    "applications",
    "program files",
    "program files (x86)",
    "programs",
    "programdata",
    "application support",
    "local",
    "roaming",
    "opt",
];

/// Suffixes an installed program or application carries on some platforms.
const PROGRAM_SUFFIXES: &[&str] = &[".exe", ".cmd", ".bat", ".ps1", ".app"];

/// Whether `program`'s arguments are judged by where they point rather than
/// by the plain name screen.
pub(super) fn judged_by_location(segment: &crate::CommandSegmentV1) -> bool {
    LOCATION_PROGRAMS.contains(&crate::command_compatibility::basename(segment).as_str())
}

/// Where the steps before a segment may have left the shell's directory.
///
/// A `cd` can fail, or run in a pipeline stage or subshell, and leave the
/// shell where it was, so every directory a change could have reached is
/// kept, not only the last one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Moved {
    /// Each absolute directory an earlier change could have entered.
    pub(super) bases: Vec<String>,
    /// Whether some change went where the text does not say: a relative
    /// target from the starting directory, `cd -`, `popd` or a variable.
    pub(super) unknown: bool,
}

/// The most candidate directories [`moved_by`] keeps.
const MAX_BASES: usize = 16;

impl Moved {
    fn add(&mut self, base: String) {
        if !self.bases.contains(&base) {
            self.bases.push(base);
        }
    }
}

/// The directories `segments` may leave the shell in, from their `cd` and
/// `pushd` arguments alone. No change leaves the default: the shell stayed.
pub(super) fn moved_by(segments: &[crate::CommandSegmentV1]) -> Moved {
    let mut moved = Moved::default();
    for segment in segments {
        let program = crate::command_compatibility::basename(segment);
        if !matches!(program.as_str(), "cd" | "pushd" | "popd") {
            continue;
        }
        let target = match (program.as_str(), segment.arguments.as_slice()) {
            ("popd", _) => None,
            (_, [target]) if !target.starts_with('-') && !target.contains('$') => {
                Some(target.to_ascii_lowercase().replace('\\', "/"))
            }
            _ => None,
        };
        match target {
            Some(target) if !relative(&target) => moved.add(target),
            Some(target) => {
                // From the starting directory, which the text does not name,
                // the target lands somewhere unknown.
                let joined: Vec<String> = moved
                    .bases
                    .iter()
                    .map(|base| format!("{base}/{target}"))
                    .collect();
                for base in joined {
                    moved.add(base);
                }
                moved.unknown = true;
            }
            None => moved.unknown = true,
        }
        // Each relative change can double the candidates. Past the bound the
        // oldest are dropped and the rest of the way counts as unknown.
        if moved.bases.len() > MAX_BASES {
            let excess = moved.bases.len() - MAX_BASES;
            moved.bases.drain(..excess);
            moved.unknown = true;
        }
    }
    moved
}

/// Whether a path, ref or remote argument reaches Guard's state directory,
/// an installed Guard program or the desktop application.
///
/// Text with whitespace, or a leading `!`, is shell text a Git alias or
/// option could run, so it keeps the plain name screen. After an earlier
/// `cd`, a relative path is judged in every directory the shell may be in;
/// when one of them is unknown, a relative path that names a Guard program
/// counts as Guard.
pub(super) fn names_guard_location(argument: &str, moved: &Moved) -> bool {
    let lowered = argument.to_ascii_lowercase().replace('\\', "/");
    if names_guard_state(&lowered) {
        return true;
    }
    // `--work-tree=bin/hol-guard` is judged by the path after the `=`.
    let lowered = match lowered.split_once('=') {
        Some((option, value)) if option.starts_with('-') => value.to_owned(),
        _ => lowered,
    };
    if remote_url(&lowered) {
        return false;
    }
    let components = components(&lowered);
    if components.contains(&"hol guard.app")
        || components
            .windows(2)
            .any(|pair| APP_PARENTS.contains(&pair[0]) && APP_NAMES.contains(&pair[1]))
    {
        return true;
    }
    if relative(&lowered) {
        if moved
            .bases
            .iter()
            .any(|base| names_guard_location(&format!("{base}/{lowered}"), &Moved::default()))
        {
            return true;
        }
        if moved.unknown && components.iter().any(|component| guard_program(component)) {
            return true;
        }
    }
    if lowered.starts_with('!') || lowered.chars().any(char::is_whitespace) {
        return ["hol-guard", "plugin-guard"]
            .iter()
            .any(|needle| lowered.contains(needle));
    }
    components
        .windows(2)
        .any(|pair| INSTALL_PARENTS.contains(&pair[0]) && guard_program(pair[1]))
}

/// The path's components with `.` dropped and each `..` folded into the
/// component before it, so `venvs/x/../hol-guard` is `venvs/hol-guard`.
fn components(lowered: &str) -> Vec<&str> {
    let mut components: Vec<&str> = Vec::new();
    for component in lowered.split('/').map(str::trim) {
        match component {
            "" | "." => {}
            ".." if components.last().is_some_and(|last| *last != "..") => {
                components.pop();
            }
            _ => components.push(component),
        }
    }
    components
}

fn guard_program(component: &str) -> bool {
    let stem = PROGRAM_SUFFIXES
        .iter()
        .find_map(|suffix| component.strip_suffix(suffix))
        .unwrap_or(component);
    GUARD_PROGRAMS.contains(&stem)
}

/// A path that resolves against the current directory.
fn relative(lowered: &str) -> bool {
    !lowered.starts_with(['/', '~', '$'])
        && lowered.as_bytes().get(1).is_none_or(|byte| *byte != b':')
}

/// Whether text names Guard's state directory or the variable that moves it.
/// Holds for every argument, whatever reads it.
pub(super) fn names_guard_state(argument: &str) -> bool {
    let lowered = argument.to_ascii_lowercase().replace('\\', "/");
    [".hol-guard", ".plugin-guard", "hol_guard_home"]
        .iter()
        .any(|needle| lowered.contains(needle))
}

/// A network remote: `https://`, `ssh://` or `git://` URL, or the scp-like
/// `user@host:path` form. A `file://` URL and a bare path are local.
fn remote_url(lowered: &str) -> bool {
    if let Some((scheme, rest)) = lowered.split_once("://") {
        return matches!(
            scheme,
            "http" | "https" | "ssh" | "git" | "git+ssh" | "ssh+git"
        ) && rest.split('/').next().is_some_and(|host| !host.is_empty());
    }
    let Some((host, _)) = lowered.split_once(':') else {
        return false;
    };
    // `C:/x` is a drive and `./a:b` a path; a remote host has a dot or a user.
    !host.is_empty()
        && !host.contains('/')
        && (host.contains('@') || host.contains('.'))
        && !host.starts_with('.')
        && !host.starts_with('-')
}

/// The values `gh api` sends with `-f`/`--raw-field`. A raw field is a
/// string in the request, never a file Guard's host reads, so only the state
/// screen applies to it. A field that follows a flag which could take it as
/// that flag's value does not count.
pub(super) fn github_api_raw_fields(segment: &crate::CommandSegmentV1) -> Vec<&String> {
    let arguments = &segment.arguments;
    let mut values = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if argument == "--" {
            break;
        }
        // `-fbody=x` and `-f=body=x` attach the field to the flag.
        if argument.starts_with("--raw-field=")
            || (argument.len() > 2 && argument.starts_with("-f") && !argument.starts_with("--"))
        {
            if index == 0 || !super::takes_next_value(&arguments[index - 1], false) {
                values.push(argument);
            }
            continue;
        }
        if index == 0 || !matches!(arguments[index - 1].as_str(), "-f" | "--raw-field") {
            continue;
        }
        if index >= 2 && super::takes_next_value(&arguments[index - 2], false) {
            continue;
        }
        values.push(argument);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkouts_pathspecs_and_remotes_named_after_guard_are_not_guard() {
        for argument in [
            "/home/u/projects/hol-guard-pr-12",
            "/home/u/projects/org/hol-guard",
            "../hol-guard",
            "hol-guard",
            "scripts/win/hol-guard.wxs",
            "/tmp/x/hol-guard-contrast",
            "https://github.com/someone/hol-guard.git",
            "git@github.com:someone/hol-guard.git",
            "ssh://git@github.com/someone/hol-guard.git",
            "C:\\Users\\u\\src\\hol-guard",
            "origin/fix/hol-guard-names",
            "/work/HOL Guard",
            "--work-tree=../hol-guard",
        ] {
            assert!(
                !names_guard_location(argument, &Moved::default()),
                "{argument}"
            );
        }
    }

    #[test]
    fn guard_state_programs_and_installs_are_guard() {
        for argument in [
            "~/.hol-guard",
            "/home/u/.hol-guard/guard.db",
            "$HOL_GUARD_HOME/x",
            "~/.local/pipx/venvs/hol-guard",
            "/home/u/.local/share/uv/tools/hol-guard/bin",
            "~/.local/bin/hol-guard",
            "/opt/homebrew/Cellar/hol-guard",
            "C:\\Program Files\\HOL Guard\\hol-guard.exe",
            "/Applications/HOL Guard.app",
            "/usr/local/bin/plugin-guard",
            "venv/lib/python3.12/site-packages/hol_guard",
            "file:///home/u/.hol-guard",
            "!hol-guard hooks remove",
            "hol-guard uninstall",
            "/etc/hol-guard",
            "/var/lib/hol-guard/managed-policy-cache.json",
            "C:\\ProgramData\\HOL Guard\\managed-policy.json",
            "/Library/Application Support/HOL Guard State",
            "/opt/hol-guard/lib/hol-guard-core/hol-guard",
            "--work-tree=bin/hol-guard",
            "--git-dir=/var/lib/hol-guard/.git",
        ] {
            assert!(
                names_guard_location(argument, &Moved::default()),
                "{argument}"
            );
        }
    }

    #[test]
    fn a_relative_path_after_a_directory_change_is_judged_where_it_resolves() {
        let to = |bases: &[&str]| Moved {
            bases: bases.iter().map(|base| (*base).to_owned()).collect(),
            unknown: false,
        };
        let venvs = to(&["/home/u/.local/pipx/venvs"]);
        let projects = to(&["/home/u/projects"]);
        assert!(names_guard_location("hol-guard", &venvs));
        assert!(names_guard_location("./hol-guard/bin", &venvs));
        assert!(!names_guard_location("hol-guard", &projects));
        assert!(!names_guard_location("hol-guard-pr-12", &venvs));
        let sibling = to(&["/home/u/.local/pipx/venvs/other"]);
        assert!(names_guard_location("../hol-guard", &sibling));
        // `cd venvs; cd /missing; git -C hol-guard ...` runs in `venvs` when
        // the second change fails.
        let failed = to(&["/home/u/.local/pipx/venvs", "/missing"]);
        assert!(names_guard_location("hol-guard", &failed));
        let unknown = Moved {
            bases: Vec::new(),
            unknown: true,
        };
        for argument in ["hol-guard", "./hol-guard/bin", "hol-guard-core"] {
            assert!(names_guard_location(argument, &unknown), "{argument}");
        }
        for argument in ["hol-guard-pr-12", "/home/u/projects/hol-guard"] {
            assert!(!names_guard_location(argument, &unknown), "{argument}");
        }
        // A long run of relative changes stays bounded and still judges a
        // Guard program name.
        let changes: String = (0..40).map(|step| format!("; cd d{step}")).collect();
        let command = format!("cd /home/u/.local/pipx/venvs{changes}");
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command,
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap();
        let long = moved_by(&model.segments);
        assert!(long.bases.len() <= MAX_BASES && long.unknown);
        assert!(names_guard_location("hol-guard", &long));
    }

    #[test]
    fn only_network_remotes_are_remote() {
        assert!(remote_url("https://github.com/o/r.git"));
        assert!(remote_url("git@github.com:o/r.git"));
        assert!(!remote_url("file:///tmp/r"));
        assert!(!remote_url("c:/users/u"));
        assert!(!remote_url("./a:b"));
        assert!(!remote_url("https:///x"));
        assert!(!remote_url("refs/heads/main:refs/heads/x"));
    }
}
