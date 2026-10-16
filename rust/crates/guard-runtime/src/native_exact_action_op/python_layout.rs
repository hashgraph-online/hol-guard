//! Where an interpreter's `site` module looks for startup code: its standard
//! library, its site directories (or a virtual environment's), and the user
//! site. An installation the proof cannot place keeps the launch once-only.

use serde_json::Value;

use super::super::super::fs_path;
use super::super::super::reasons::{Proof, MUTABLE_LAUNCHER};

const MAX_ENTRIES: usize = 256;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Where an interpreter's `site` module looks.
pub(super) struct Layout {
    /// Standard-library directories, ahead of every site directory.
    pub(super) library: Vec<String>,
    /// Site directories in the order `site` adds them.
    pub(super) site: Vec<String>,
}

/// Directories below `parent` whose names start with `prefix`.
fn entries_with_prefix(parent: &str, prefix: &str) -> Proof<Vec<String>> {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for entry in entries {
        let name = entry.map_err(|_| MUTABLE_LAUNCHER)?.file_name();
        let name = name.into_string().map_err(|_| MUTABLE_LAUNCHER)?;
        if name.starts_with(prefix) {
            found.push(fs_path::join(parent, &name));
        }
        if found.len() > MAX_ENTRIES {
            return Err(MUTABLE_LAUNCHER);
        }
    }
    found.sort();
    Ok(found)
}

/// The installation prefix: the nearest ancestor of `start` holding a
/// `lib/python3.*/os.py` standard library, as CPython's path search finds it.
fn prefix_from(start: &str) -> Proof<Option<String>> {
    let mut directory = fs_path::norm(start);
    loop {
        for library in entries_with_prefix(&fs_path::join(&directory, "lib"), "python3")? {
            if fs_path::is_file(&fs_path::join(&library, "os.py")) {
                return Ok(Some(directory));
            }
        }
        let parent = fs_path::parent(&directory);
        if parent == directory {
            return Ok(None);
        }
        directory = parent;
    }
}

/// `key = value` settings of a virtual environment's `pyvenv.cfg`.
fn venv_setting(config: &str, key: &str) -> Option<String> {
    config.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case(key)
            .then(|| value.trim().to_owned())
    })
}

impl Layout {
    pub(super) fn of(executable: &Value, user_site: bool, home: Option<&str>) -> Proof<Self> {
        let text = |key: &str| executable.get(key).and_then(Value::as_str);
        if text("file_format") != Some("native") {
            return Err(MUTABLE_LAUNCHER);
        }
        let launch = text("launch_path")
            .filter(|path| fs_path::is_abs(path))
            .ok_or(MUTABLE_LAUNCHER)?;
        let real = text("path")
            .filter(|path| fs_path::is_abs(path))
            .ok_or(MUTABLE_LAUNCHER)?;
        // `pyvenv.cfg` beside the launched (not resolved) interpreter, or one
        // directory up, makes a virtual environment.
        let bin = fs_path::parent(launch);
        let venv = [bin.clone(), fs_path::parent(&bin)]
            .into_iter()
            .find(|directory| fs_path::is_file(&fs_path::join(directory, "pyvenv.cfg")));
        let (prefix, include_base) = match &venv {
            Some(venv) => {
                let config =
                    fs_path::read_bounded(&fs_path::join(venv, "pyvenv.cfg"), MAX_CONFIG_BYTES)
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .ok_or(MUTABLE_LAUNCHER)?;
                let base = venv_setting(&config, "home")
                    .filter(|path| fs_path::is_abs(path))
                    .ok_or(MUTABLE_LAUNCHER)?;
                let mut prefix = None;
                if let Some(base_real) =
                    fs_path::resolve_strict(&fs_path::join(&base, &fs_path::name(launch)))
                {
                    prefix = prefix_from(&fs_path::parent(&base_real))?;
                }
                if prefix.is_none() {
                    prefix = prefix_from(&base)?;
                }
                let include = venv_setting(&config, "include-system-site-packages")
                    .is_some_and(|value| value.eq_ignore_ascii_case("true"));
                (prefix, include)
            }
            None => (prefix_from(&fs_path::parent(real))?, true),
        };
        let prefix = prefix.ok_or(MUTABLE_LAUNCHER)?;
        let mut layout = Layout {
            library: Vec::new(),
            site: Vec::new(),
        };
        for lib in ["lib", "lib64"] {
            for library in entries_with_prefix(&fs_path::join(&prefix, lib), "python3")? {
                if fs_path::name(&library).ends_with(".zip") {
                    // A zipped standard library is searched before the site directories.
                    return Err(MUTABLE_LAUNCHER);
                }
                layout.library.push(fs_path::join(&library, "lib-dynload"));
                layout.library.push(library);
            }
        }
        if let Some(venv) = &venv {
            for lib in ["lib", "lib64"] {
                for library in entries_with_prefix(&fs_path::join(venv, lib), "python3")? {
                    layout.site.push(fs_path::join(&library, "site-packages"));
                }
            }
        }
        if include_base {
            let mut roots = vec![prefix.clone()];
            if prefix == "/usr" {
                roots.push("/usr/local".to_owned());
            }
            for root in roots {
                for lib in ["lib", "lib64"] {
                    for library in entries_with_prefix(&fs_path::join(&root, lib), "python3")? {
                        layout.site.push(fs_path::join(&library, "site-packages"));
                        layout.site.push(fs_path::join(&library, "dist-packages"));
                    }
                }
            }
            if prefix.contains(".framework/") {
                for version in entries_with_prefix("/Library/Python", "3")? {
                    layout.site.push(fs_path::join(&version, "site-packages"));
                }
            }
        }
        if user_site && include_base {
            let home = home
                .filter(|path| fs_path::is_abs(path))
                .ok_or(MUTABLE_LAUNCHER)?;
            for library in entries_with_prefix(&fs_path::join(home, ".local/lib"), "python3")? {
                layout.site.push(fs_path::join(&library, "site-packages"));
            }
            for version in entries_with_prefix(&fs_path::join(home, "Library/Python"), "3")? {
                layout
                    .site
                    .push(fs_path::join(&version, "lib/python/site-packages"));
            }
        }
        layout
            .library
            .retain(|directory| fs_path::is_dir(directory));
        layout.site.retain(|directory| fs_path::is_dir(directory));
        layout.site.dedup();
        Ok(layout)
    }
}
