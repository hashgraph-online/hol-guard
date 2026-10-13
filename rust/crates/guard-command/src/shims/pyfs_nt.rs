//! The Windows (`ntpath`) halves of the pathlib/os/shutil behaviours in `pyfs`.

use std::fs;

use super::winpath::{nt_join, nt_normcase, nt_normpath, nt_split, splitroot, WinPath};
use super::{ShimFacts, ShimResult};

impl ShimFacts {
    /// `ntpath.abspath` as `GetFullPathNameW` resolves it: a drive-relative
    /// path on another drive than the working directory, such as `C:tools`,
    /// resolves against that drive's current directory (`=C:`), else its root.
    pub(super) fn nt_abspath(&self, path: &str) -> String {
        let (drive, root, _) = splitroot(path);
        let (cwd_drive, _, _) = splitroot(&self.cwd);
        let base =
            if !drive.is_empty() && root.is_empty() && !drive.eq_ignore_ascii_case(&cwd_drive) {
                self.environ
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(&format!("={drive}")))
                    .map_or_else(|| format!("{drive}\\"), |(_, value)| value.clone())
            } else {
                self.cwd.clone()
            };
        nt_normpath(&nt_join(&base, path))
    }

    /// `NeedCurrentDirectoryForExePath`: true unless
    /// `NoDefaultCurrentDirectoryInExePath` is set; Windows environment names
    /// are case-insensitive.
    fn nt_searches_current_dir(&self) -> bool {
        !self
            .environ
            .keys()
            .any(|key| key.eq_ignore_ascii_case("NoDefaultCurrentDirectoryInExePath"))
    }

    /// `ntpath.expanduser` home: `USERPROFILE`, else `HOMEDRIVE` + `HOMEPATH`;
    /// `None` when neither is set (the path then stays unexpanded).
    pub(super) fn nt_user_home(&self) -> Option<String> {
        if let Some(profile) = self.environ.get("USERPROFILE") {
            return Some(profile.clone());
        }
        let homepath = self.environ.get("HOMEPATH")?;
        let drive = self.environ.get("HOMEDRIVE").map_or("", String::as_str);
        Some(nt_join(drive, homepath))
    }

    /// `ntpath.expanduser`: `~name` names a sibling of the current user's home
    /// unless it is `USERNAME`; anything unknown is returned unchanged.
    pub(super) fn expanduser_os_nt(&self, path: &str) -> String {
        if !path.starts_with('~') {
            return path.to_owned();
        }
        let end = path
            .char_indices()
            .skip(1)
            .find(|(_, ch)| *ch == '/' || *ch == '\\')
            .map_or(path.len(), |(index, _)| index);
        let Some(userhome) = self.nt_user_home() else {
            return path.to_owned();
        };
        let target = &path[1..end];
        let userhome = if target.is_empty() {
            userhome
        } else {
            let current = self.environ.get("USERNAME").map(String::as_str);
            if current == Some(target) {
                userhome
            } else if current != Some(nt_split(&userhome).1.as_str()) {
                return path.to_owned();
            } else {
                nt_join(&nt_split(&userhome).0, target)
            }
        };
        format!("{userhome}{}", &path[end..])
    }

    /// `Path.expanduser()` on Windows: only the first segment is expanded;
    /// an unresolvable `~...` raises `RuntimeError`.
    pub(super) fn expanduser_nt(&self, path: &str) -> ShimResult<String> {
        let parsed = WinPath::new(path);
        let first = parsed.tail.first().cloned().unwrap_or_default();
        if !parsed.drive.is_empty() || !parsed.root.is_empty() || !first.starts_with('~') {
            return Ok(parsed.to_string());
        }
        let homedir = self.expanduser_os_nt(&first);
        if homedir.starts_with('~') {
            return Err("Could not determine home directory.".to_owned());
        }
        let home = WinPath::new(&homedir);
        let mut tail = home.tail.clone();
        tail.extend(parsed.tail.iter().skip(1).cloned());
        Ok(WinPath {
            drive: home.drive,
            root: home.root,
            tail,
        }
        .to_string())
    }

    /// `ntpath.realpath(strict=False)`: normalise, resolve the longest existing
    /// prefix through the filesystem and keep the rest as spelled.
    pub(super) fn resolve_nt(&self, path: &str) -> String {
        let absolute = self.nt_abspath(path);
        let parsed = WinPath::new(&absolute);
        let mut existing = parsed.clone();
        let mut remainder: Vec<String> = Vec::new();
        loop {
            if let Ok(real) = fs::canonicalize(existing.to_string()) {
                let mut base = strip_verbatim_prefix(&real.to_string_lossy());
                for part in remainder.iter().rev() {
                    base = nt_join(&base, part);
                }
                return WinPath::new(&base).to_string();
            }
            let Some(last) = existing.tail.pop() else {
                return WinPath::new(&absolute).to_string();
            };
            remainder.push(last);
        }
    }

    /// Python 3.12 `shutil.which` on Windows: PATHEXT candidates, the current
    /// directory first, `os.path.normcase` de-duplication.
    pub(super) fn which_nt(&self, command: &str, search_path: &str) -> Option<String> {
        let (dirname, cmd) = nt_split(command);
        let directories: Vec<String> = if dirname.is_empty() {
            if search_path.is_empty() {
                return None;
            }
            let mut listed: Vec<String> = search_path.split(';').map(str::to_owned).collect();
            if self.nt_searches_current_dir() {
                listed.insert(0, ".".to_owned());
            }
            listed
        } else {
            vec![dirname]
        };
        let pathext = self
            .environ
            .get("PATHEXT")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC".to_owned());
        let extensions: Vec<String> = pathext
            .split(';')
            .filter(|ext| !ext.is_empty())
            .map(|ext| ext.trim_end_matches('.').to_owned())
            .collect();
        let mut files: Vec<String> = extensions.iter().map(|ext| format!("{cmd}{ext}")).collect();
        let upper = cmd.to_uppercase();
        if extensions
            .iter()
            .any(|ext| upper.ends_with(&ext.to_uppercase()))
        {
            files.insert(0, cmd.clone());
        }
        let mut seen: Vec<String> = Vec::new();
        for directory in directories {
            let normalized = nt_normcase(&directory);
            if seen.contains(&normalized) {
                continue;
            }
            seen.push(normalized);
            for name in &files {
                let candidate = nt_join(&directory, name);
                if self.exists(&candidate)
                    && self.access_executable(&candidate)
                    && !self.is_dir(&candidate)
                {
                    return Some(candidate);
                }
            }
        }
        None
    }
}

/// Drop the `\\?\` (and `\\?\UNC\`) prefix `GetFinalPathNameByHandle` adds.
fn strip_verbatim_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("\\\\?\\UNC\\") {
        return format!("\\\\{rest}");
    }
    path.strip_prefix("\\\\?\\").unwrap_or(path).to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::ShimFacts;

    fn facts(cwd: &str, environ: &[(&str, &str)]) -> ShimFacts {
        ShimFacts {
            environ: environ
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
            home: String::new(),
            cwd: cwd.to_owned(),
            executable: String::new(),
            frozen: false,
            frozen_cli: String::new(),
            trusted_frozen_cli_paths: Vec::new(),
            python_version: (3, 12),
            import_root: String::new(),
            argv0: None,
            windows: true,
            sqlite_connect_timeout_seconds: 30.0,
            now: String::new(),
            shim_dir_transient: None,
        }
    }

    #[test]
    fn drive_relative_path_on_another_drive_uses_that_drive() {
        let plain = facts("D:\\work", &[]);
        assert_eq!(plain.nt_abspath("C:tools"), "C:\\tools");
        assert_eq!(plain.nt_abspath("d:bin"), "d:\\work\\bin");
        assert_eq!(plain.nt_abspath("bin"), "D:\\work\\bin");
        let per_drive = facts("D:\\work", &[("=C:", "C:\\Users\\dev")]);
        assert_eq!(per_drive.nt_abspath("C:tools"), "C:\\Users\\dev\\tools");
    }

    #[test]
    fn current_directory_opt_out_ignores_key_case() {
        assert!(facts("C:\\work", &[]).nt_searches_current_dir());
        for key in [
            "NoDefaultCurrentDirectoryInExePath",
            "NODEFAULTCURRENTDIRECTORYINEXEPATH",
        ] {
            assert!(!facts("C:\\work", &[(key, "1")]).nt_searches_current_dir());
        }
    }
}
