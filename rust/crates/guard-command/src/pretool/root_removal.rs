//! Recursive forced removal of a root: the filesystem root, a top-level or
//! system directory, a home directory, or a direct child of a home.
//!
//! Removing a deeper path, such as a build directory inside a project, is not
//! this hard floor; the ordinary review decides it and an approval applies.

use super::executable_basename;

const SYSTEM_DIRECTORIES: [&str; 15] = [
    "applications",
    "bin",
    "boot",
    "dev",
    "etc",
    "lib",
    "library",
    "opt",
    "private",
    "proc",
    "sbin",
    "sys",
    "system",
    "usr",
    "var",
];

/// Whether any command in `lowered` (lowercase text with `/` separators)
/// runs `rm -rf` on a root, including a relative target such as `*` or `.`
/// after a `cd` into one.
pub(super) fn removes_a_root(lowered: &str) -> bool {
    let mut cwd: Option<String> = None;
    lowered
        .replace("${home}", "$home")
        .split([';', '|', '&', '\n', '(', ')', '`'])
        .any(|segment| segment_removes_a_root(segment, &mut cwd))
}

/// Whether `target` names a path from the root or a home rather than from
/// the working directory.
fn is_anchored(target: &str) -> bool {
    target.starts_with(['/', '~'])
        || target.starts_with("$home")
        || matches!(target.as_bytes(), [letter, b':', ..] if letter.is_ascii_alphabetic())
}

/// The directory a `cd` or `pushd` in `words` moves to, joined to the one a
/// previous `cd` set; `None` once it is unknown.
fn changed_directory(words: &[String], cwd: Option<&str>) -> Option<String> {
    let target = words[1..]
        .iter()
        .find(|word| !word.starts_with('-') || word.as_str() == "-");
    match target.map(String::as_str) {
        None => Some("~".to_owned()),
        Some("-") => None,
        Some(target) if is_anchored(target) => Some(target.to_owned()),
        Some(target) => cwd.map(|directory| format!("{directory}/{target}")),
    }
}

fn segment_removes_a_root(segment: &str, cwd: &mut Option<String>) -> bool {
    let words: Vec<String> = segment
        .split_ascii_whitespace()
        .map(|word| word.replace(['"', '\''], ""))
        .collect();
    if words
        .first()
        .is_some_and(|word| matches!(executable_basename(word), "cd" | "pushd"))
    {
        *cwd = changed_directory(&words, cwd.as_deref());
        return false;
    }
    let Some(start) = words
        .iter()
        .position(|word| executable_basename(word) == "rm")
    else {
        return false;
    };
    let (mut recursive, mut force, mut options_ended) = (false, false, false);
    let mut targets = Vec::new();
    for word in &words[start + 1..] {
        if options_ended || !word.starts_with('-') || word == "-" {
            targets.push(word.as_str());
        } else if word == "--" {
            options_ended = true;
        } else if let Some(long) = word.strip_prefix("--") {
            recursive |= !long.is_empty() && "recursive".starts_with(long);
            force |= !long.is_empty() && "force".starts_with(long);
        } else {
            recursive |= word.contains('r');
            force |= word.contains('f');
        }
    }
    recursive
        && force
        && targets.into_iter().any(|target| match cwd.as_deref() {
            Some(directory) if !is_anchored(target) => {
                is_root_target(&format!("{directory}/{target}"))
            }
            _ => is_root_target(target),
        })
}

/// `~`, `$home`, `~user`, `/`, `/usr`, `/users/name`, `~/documents` or a
/// glob over one of them.
fn is_root_target(target: &str) -> bool {
    let (home, rest) = if let Some(rest) = target.strip_prefix('~') {
        if !rest.is_empty() && !rest.starts_with('/') {
            // `~user` names another home directory.
            return true;
        }
        (true, rest)
    } else if let Some(rest) = target.strip_prefix("$home") {
        if !rest.is_empty() && !rest.starts_with('/') {
            // A longer variable name, such as `$homework`.
            return false;
        }
        (true, rest)
    } else {
        let rest = match target.as_bytes() {
            [letter, b':', ..] if letter.is_ascii_alphabetic() => &target[2..],
            _ => target,
        };
        if !rest.starts_with('/') {
            return false;
        }
        (false, rest)
    };
    let mut components: Vec<&str> = Vec::new();
    for component in rest.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            // A glob removes everything at its level, as its parent would.
            glob if glob.contains(['*', '?', '[']) => break,
            name => components.push(name),
        }
    }
    let depth = components.len();
    if home {
        return depth <= 1;
    }
    match components.first() {
        None => true,
        Some(&"users" | &"home") => depth <= 3,
        Some(&"root") => depth <= 2,
        Some(top) if SYSTEM_DIRECTORIES.contains(top) => depth <= 2,
        Some(_) => depth <= 1,
    }
}

#[cfg(test)]
mod tests {
    use super::removes_a_root;

    #[test]
    fn roots_homes_and_system_directories_are_roots() {
        for command in [
            "rm -rf /",
            "rm -rf /*",
            "rm -fr -- /",
            "rm -r -f /",
            "rm --recursive --force /",
            "rm -rf --no-preserve-root /",
            "sudo rm -rf /usr",
            "rm -rf /usr/local",
            "rm -rf /tmp",
            "rm -rf ~",
            "rm -rf ~/",
            "rm -rf ~/*",
            "rm -rf ~/documents",
            "rm -rf ~other",
            "rm -rf $home",
            "rm -rf \"$home\"/",
            "rm -rf ${home}/projects",
            "rm -rf /users/someone",
            "rm -rf /users/someone/projects",
            "rm -rf /home/someone/*",
            "rm -rf /root/.ssh",
            "rm -rf /users/someone/projects/app/../..",
            "rm -rf c:/",
            "rm -rf c:/windows",
            "bash -c 'cd /tmp; rm -rf /'",
            "rm -rf build && rm -rf /etc",
            "cd / && rm -rf *",
            "cd ~; rm -rf .",
            "cd /usr; rm -rf -- *",
            "cd; rm -rf ./*",
            "cd /users/someone/projects && rm -rf ../..",
            "cd /usr && cd local && rm -rf *",
        ] {
            assert!(removes_a_root(command), "{command}");
        }
    }

    #[test]
    fn paths_inside_a_project_are_not_roots() {
        for command in [
            "rm -rf /users/someone/projects/app/node_modules",
            "rm -rf /home/someone/work/app/dist",
            "rm -rf ~/projects/app/build",
            "rm -rf $home/projects/app/.cache",
            "rm -rf /tmp/build-output",
            "rm -rf /private/tmp/scratch",
            "rm -rf node_modules",
            "rm -rf ./dist /users/someone/projects/app/coverage",
            "rm -rf build && cat /etc/hosts",
            "rm -rf build; ls /",
            "rm -f /",
            "rm -r ~/projects",
            "rm -rf $homework",
            "echo rm -rf",
            "cd ~/projects/app && rm -rf build",
            "cd /users/someone/projects/app && rm -rf node_modules dist",
            "cd build && rm -rf *",
            "cd - && rm -rf *",
        ] {
            assert!(!removes_a_root(command), "{command}");
        }
    }
}
