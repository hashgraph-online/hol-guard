//! `pathlib.PureWindowsPath` and `ntpath` as Python 3.12 spells them.
//!
//! The shim code renders paths into generated files and JSON, so the exact
//! spelling matters: separators are backslashes, `.` and empty segments are
//! dropped, drives and UNC shares keep their case, and `str(Path)` of an empty
//! path is `.`. These functions are pure string operations and run on every
//! platform; only [`super::pyfs`] decides when to use them (a request whose
//! facts say `os.name == "nt"`).

const SEP: char = '\\';

/// `ntpath.splitroot`: `(drive, root, rest)`.
pub(crate) fn splitroot(path: &str) -> (String, String, String) {
    let chars: Vec<char> = path.chars().collect();
    let norm: Vec<char> = chars
        .iter()
        .map(|ch| if *ch == '/' { SEP } else { *ch })
        .collect();
    let slice = |from: usize, to: usize| -> String {
        chars[from.min(chars.len())..to.min(chars.len())]
            .iter()
            .collect()
    };
    if norm.first() == Some(&SEP) {
        if norm.get(1) == Some(&SEP) {
            let normp: String = norm.iter().collect();
            let unc_prefix = "\\\\?\\UNC\\";
            let start = if normp.chars().take(8).collect::<String>().to_uppercase() == unc_prefix {
                8
            } else {
                2
            };
            let Some(index) = find_sep(&norm, start) else {
                return (path.to_owned(), String::new(), String::new());
            };
            let Some(index2) = find_sep(&norm, index + 1) else {
                return (path.to_owned(), String::new(), String::new());
            };
            return (
                slice(0, index2),
                slice(index2, index2 + 1),
                slice(index2 + 1, chars.len()),
            );
        }
        return (String::new(), slice(0, 1), slice(1, chars.len()));
    }
    if norm.get(1) == Some(&':') {
        if norm.get(2) == Some(&SEP) {
            return (slice(0, 2), slice(2, 3), slice(3, chars.len()));
        }
        return (slice(0, 2), String::new(), slice(2, chars.len()));
    }
    (String::new(), String::new(), path.to_owned())
}

fn find_sep(chars: &[char], start: usize) -> Option<usize> {
    (start..chars.len()).find(|index| chars[*index] == SEP)
}

/// `ntpath.join(path, child)`.
pub(crate) fn nt_join(path: &str, child: &str) -> String {
    let (mut result_drive, mut result_root, mut result_path) = splitroot(path);
    let (p_drive, p_root, p_path) = splitroot(child);
    if !p_root.is_empty() {
        if !p_drive.is_empty() || result_drive.is_empty() {
            result_drive = p_drive;
        }
        result_root = p_root;
        result_path = p_path;
    } else if !p_drive.is_empty() && p_drive != result_drive {
        if p_drive.to_lowercase() != result_drive.to_lowercase() {
            return format!("{p_drive}{p_root}{p_path}");
        }
        result_drive = p_drive;
        append_relative(&mut result_path, &p_path);
    } else {
        append_relative(&mut result_path, &p_path);
    }
    let last_is_separator_or_colon = result_drive
        .chars()
        .last()
        .is_some_and(|ch| ch == ':' || ch == '\\' || ch == '/');
    if !result_path.is_empty()
        && result_root.is_empty()
        && !result_drive.is_empty()
        && !last_is_separator_or_colon
    {
        return format!("{result_drive}{SEP}{result_path}");
    }
    format!("{result_drive}{result_root}{result_path}")
}

fn append_relative(result_path: &mut String, p_path: &str) {
    if result_path
        .chars()
        .last()
        .is_some_and(|ch| ch != '\\' && ch != '/')
    {
        result_path.push(SEP);
    }
    result_path.push_str(p_path);
}

/// `ntpath.normpath`.
pub(crate) fn nt_normpath(path: &str) -> String {
    let replaced = path.replace('/', "\\");
    let (drive, root, rest) = splitroot(&replaced);
    let prefix = format!("{drive}{root}");
    let mut comps: Vec<String> = rest.split(SEP).map(str::to_owned).collect();
    let mut index = 0;
    while index < comps.len() {
        if comps[index].is_empty() || comps[index] == "." {
            comps.remove(index);
        } else if comps[index] == ".." {
            if index > 0 && comps[index - 1] != ".." {
                comps.drain(index - 1..=index);
                index -= 1;
            } else if index == 0 && !root.is_empty() {
                comps.remove(index);
            } else {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    if prefix.is_empty() && comps.is_empty() {
        comps.push(".".to_owned());
    }
    format!("{prefix}{}", comps.join("\\"))
}

/// Parsed form of a `PureWindowsPath`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WinPath {
    pub drive: String,
    pub root: String,
    pub tail: Vec<String>,
}

impl WinPath {
    pub(crate) fn new(text: &str) -> Self {
        if text.is_empty() {
            return Self {
                drive: String::new(),
                root: String::new(),
                tail: Vec::new(),
            };
        }
        let replaced = text.replace('/', "\\");
        let (drive, mut root, rest) = splitroot(&replaced);
        if root.is_empty() && drive.starts_with(SEP) && !drive.ends_with(SEP) {
            let drive_parts: Vec<&str> = drive.split(SEP).collect();
            let device = drive_parts.get(2).is_some_and(|part| "?.".contains(part));
            if (drive_parts.len() == 4 && !device) || drive_parts.len() == 6 {
                root = "\\".to_owned();
            }
        }
        let tail = rest
            .split(SEP)
            .filter(|part| !part.is_empty() && *part != ".")
            .map(str::to_owned)
            .collect();
        Self { drive, root, tail }
    }

    pub(crate) fn join(&self, child: &str) -> Self {
        Self::new(&nt_join(&self.to_string(), child))
    }

    pub(crate) fn name(&self) -> String {
        self.tail.last().cloned().unwrap_or_default()
    }

    pub(crate) fn parent(&self) -> Self {
        if self.tail.is_empty() {
            return self.clone();
        }
        Self {
            drive: self.drive.clone(),
            root: self.root.clone(),
            tail: self.tail[..self.tail.len() - 1].to_vec(),
        }
    }

    /// `PurePath.is_absolute` for the Windows flavour: a drive and a root.
    pub(crate) fn is_absolute(&self) -> bool {
        !self.drive.is_empty() && !self.root.is_empty()
    }
}

impl std::fmt::Display for WinPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.drive.is_empty() || !self.root.is_empty() {
            return write!(f, "{}{}{}", self.drive, self.root, self.tail.join("\\"));
        }
        let mut parts: Vec<&str> = self.tail.iter().map(String::as_str).collect();
        if parts
            .first()
            .is_some_and(|first| !splitroot(first).0.is_empty())
        {
            parts.insert(0, ".");
        }
        if parts.is_empty() {
            return f.write_str(".");
        }
        f.write_str(&parts.join("\\"))
    }
}

/// `ntpath.split`: `(head, tail)` split at the last separator.
pub(crate) fn nt_split(path: &str) -> (String, String) {
    let (drive, root, rest) = splitroot(path);
    let body = format!("{root}{rest}");
    let chars: Vec<char> = body.chars().collect();
    let is_sep = |ch: char| ch == '/' || ch == SEP;
    let mut index = chars.len();
    while index > 0 && !is_sep(chars[index - 1]) {
        index -= 1;
    }
    let head: String = chars[..index].iter().collect();
    let tail: String = chars[index..].iter().collect();
    let stripped = head.trim_end_matches(is_sep);
    let head = if stripped.is_empty() {
        head.as_str()
    } else {
        stripped
    };
    (format!("{drive}{head}"), tail)
}

/// `ntpath.normcase`: lower-case with backslashes.
pub(crate) fn nt_normcase(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

/// Whether `path` is `root` or below it, as `Path.relative_to` decides on
/// Windows (case-insensitive, segment-wise).
pub(crate) fn nt_is_within(path: &str, root: &str) -> bool {
    let child = WinPath::new(path);
    let base = WinPath::new(root);
    if nt_normcase(&child.drive) != nt_normcase(&base.drive) || child.root != base.root {
        return false;
    }
    if base.tail.len() > child.tail.len() {
        return false;
    }
    base.tail
        .iter()
        .zip(&child.tail)
        .all(|(left, right)| left.to_lowercase() == right.to_lowercase())
}

#[cfg(test)]
mod tests;
