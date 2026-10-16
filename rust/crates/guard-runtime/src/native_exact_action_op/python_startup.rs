//! The code Python's `site` module runs before a script: each `.pth` file in
//! a site directory (its `import` lines run, its other lines extend the
//! module path), the modules those lines import, and any `sitecustomize` or
//! `usercustomize` the module path holds. An interpreter whose standard
//! library the proof cannot place keeps the launch once-only.

use std::io::Read;

use regex::Captures;
use serde_json::Value;

use super::super::fs_path;
use super::super::python_modules::{REFUSED_MODULES, STANDARD_MODULES};
use super::super::python_source::{readable, scan};
use super::super::reasons::{Proof, MUTABLE_LAUNCHER};
use super::{Graph, COMPILED_SUFFIXES};
use layout::Layout;
use shim::{literal, literal_import, references, top, uses, SHIMMED, SHIMS};

/// A site directory can hold thousands of installed packages.
const MAX_SITE_LISTING: usize = 65_536;
const MAX_STARTUP_FILES: usize = 256;
const CUSTOMIZE: [&str; 2] = ["sitecustomize", "usercustomize"];

/// Whether the import system runs the cached bytecode at `pyc` in place of a
/// source with `source` metadata. A hash-based file is bound whether or not
/// Python checks its hash; a timestamp file only when it records the
/// source's modification second and size. Python skips a file it cannot read.
pub(super) fn runs_in_place(source: &std::fs::Metadata, pyc: &str) -> bool {
    let mut header = [0u8; 16];
    if std::fs::File::open(pyc)
        .and_then(|mut file| file.read_exact(&mut header))
        .is_err()
    {
        return false;
    }
    let word = |at: usize| {
        u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
    };
    // Python reads bit 0 as hash-based and ignores bit 1 otherwise.
    match word(4) {
        0 | 2 => {
            let Some(seconds) = source
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            else {
                return true;
            };
            word(8) == seconds.as_secs() as u32 && word(12) == source.len() as u32
        }
        1 | 3 => true,
        _ => false,
    }
}

impl Graph<'_> {
    fn bind_startup(&mut self, path: &str) -> Proof<Vec<u8>> {
        let (digest, bytes) = self.digest(path)?;
        self.startup.insert(path.to_owned(), digest);
        if path.ends_with(".py") {
            self.add_bytecode(path)?;
        }
        if self.startup.len() > MAX_STARTUP_FILES {
            return Err(MUTABLE_LAUNCHER);
        }
        Ok(bytes)
    }

    /// Bind a startup source and what it imports from `sites`, as the graph
    /// binds a script's modules. Source the scan cannot read, that writes
    /// files, or that imports code the proof cannot bind keeps the launch
    /// once-only.
    fn bind_source(&mut self, sites: &[String], path: &str, shim: bool) -> Proof<()> {
        if self.startup.contains_key(path) {
            return Ok(());
        }
        let bytes = self.bind_startup(path)?;
        let text = String::from_utf8(bytes).map_err(|_| MUTABLE_LAUNCHER)?;
        let text = text.trim_start_matches('\u{feff}');
        let imports = if shim {
            let found = shim::shim(text).ok_or(MUTABLE_LAUNCHER)?;
            self.shim_loaders.push((path.to_owned(), found.loaders));
            self.startup_code.push((path.to_owned(), found.code));
            found.imports
        } else {
            let scanned = scan(text).ok_or(MUTABLE_LAUNCHER)?;
            if scanned.writes {
                return Err(MUTABLE_LAUNCHER);
            }
            self.startup_replaces = self.startup_replaces.join(scanned.replaces);
            let code = readable(text).ok_or(MUTABLE_LAUNCHER)?;
            self.startup_code.push((path.to_owned(), references(&code)));
            scanned.imports
        };
        for import in &imports {
            if import.level == 0 {
                // A shim finds the packages it redirects through `importlib`.
                if !(shim && top(&import.module) == "importlib") {
                    self.bind_import(sites, &import.module, &import.names)?;
                }
                continue;
            }
            let mut directory = fs_path::parent(path);
            for _ in 1..import.level {
                directory = fs_path::parent(&directory);
            }
            if !sites
                .iter()
                .any(|site| fs_path::is_inside(&directory, site))
            {
                return Err(MUTABLE_LAUNCHER);
            }
            let parts: Vec<&str> = import
                .module
                .split('.')
                .filter(|part| !part.is_empty())
                .collect();
            self.bind_parts(sites, directory, &parts, &import.names, shim)?;
        }
        Ok(())
    }

    /// Bind an absolute import: a standard module by name, or the module in
    /// the first site directory that holds it.
    fn bind_import(&mut self, sites: &[String], module: &str, names: &[String]) -> Proof<()> {
        let name = top(module);
        if REFUSED_MODULES.contains(&name) {
            return Err(MUTABLE_LAUNCHER);
        }
        if STANDARD_MODULES.contains(&name) {
            return Ok(());
        }
        let parts: Vec<&str> = module.split('.').collect();
        for site in sites {
            if self.find(site, name)?.is_some() {
                return self.bind_parts(sites, site.clone(), &parts, names, SHIMS.contains(&name));
            }
        }
        Err(MUTABLE_LAUNCHER)
    }

    /// Bind the `__init__.py` of each package `parts` walks through below
    /// `directory`, the module it ends at, and any submodule a `from` import
    /// takes by name.
    fn bind_parts(
        &mut self,
        sites: &[String],
        mut directory: String,
        parts: &[&str],
        names: &[String],
        shim: bool,
    ) -> Proof<()> {
        for (index, part) in parts.iter().enumerate() {
            let source = self.find(&directory, part)?.ok_or(MUTABLE_LAUNCHER)?;
            self.bind_source(sites, &source, shim)?;
            if fs_path::name(&source) != "__init__.py" {
                return if index + 1 == parts.len() {
                    Ok(())
                } else {
                    Err(MUTABLE_LAUNCHER)
                };
            }
            directory = fs_path::parent(&source);
        }
        for name in names {
            if let Some(source) = self.find(&directory, name)? {
                self.bind_source(sites, &source, shim)?;
            }
        }
        Ok(())
    }

    /// Bind a `.pth` file and what its lines run; returns the directories its
    /// other lines add to the module path.
    fn add_pth(&mut self, sites: &[String], path: &str) -> Proof<Vec<String>> {
        if !fs_path::is_file(path) {
            return Ok(Vec::new());
        }
        let bytes = self.bind_startup(path)?;
        let text = String::from_utf8(bytes).map_err(|_| MUTABLE_LAUNCHER)?;
        let text = text.trim_start_matches('\u{feff}');
        if text.replace("\r\n", "\n").contains('\r') {
            return Err(MUTABLE_LAUNCHER);
        }
        let site = fs_path::parent(path);
        let mut added = Vec::new();
        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            if line.starts_with("import ") || line.starts_with("import\t") {
                let mut named = Vec::new();
                let rewritten = literal_import().replace_all(line, |captures: &Captures| {
                    named.push(literal(captures));
                    "_imported_"
                });
                let scanned = scan(&rewritten).ok_or(MUTABLE_LAUNCHER)?;
                if scanned.writes {
                    return Err(MUTABLE_LAUNCHER);
                }
                self.startup_replaces = self.startup_replaces.join(scanned.replaces);
                let code = readable(&rewritten).ok_or(MUTABLE_LAUNCHER)?;
                self.startup_code.push((path.to_owned(), references(&code)));
                for name in named {
                    self.bind_import(sites, &name, &[])?;
                }
                for import in &scanned.imports {
                    if import.level > 0 {
                        return Err(MUTABLE_LAUNCHER);
                    }
                    self.bind_import(sites, &import.module, &import.names)?;
                }
                continue;
            }
            let directory = fs_path::join(&site, line.trim_end());
            if fs_path::is_dir(&directory) {
                added.push(directory);
            }
        }
        Ok(added)
    }

    /// Bind a `sitecustomize` or `usercustomize` source in `directory`; any
    /// other form of either keeps the launch once-only.
    fn add_customize(&mut self, sites: &[String], directory: &str) -> Proof<()> {
        let found: Vec<String> = self
            .listing_within(directory, MAX_SITE_LISTING)?
            .iter()
            .filter(|entry| {
                CUSTOMIZE.iter().any(|name| {
                    entry.as_str() == *name
                        || entry
                            .strip_prefix(name)
                            .is_some_and(|rest| rest.starts_with('.'))
                })
            })
            .cloned()
            .collect();
        for entry in found {
            let path = fs_path::join(directory, &entry);
            let source = CUSTOMIZE
                .iter()
                .any(|name| entry.strip_suffix(".py") == Some(name));
            if !source || !fs_path::is_file(&path) {
                return Err(MUTABLE_LAUNCHER);
            }
            self.bind_source(sites, &path, false)?;
        }
        Ok(())
    }

    /// Bind the code `site` runs before the script, and refuse a standard
    /// name a site directory also holds: the interpreter loads that copy
    /// when its own library lacks the module.
    pub(super) fn add_startup(&mut self, executable: &Value, user_site: bool) -> Proof<()> {
        let layout = Layout::of(executable, user_site, self.ctx.home)?;
        let mut path_directories = layout.site.clone();
        for site in &layout.site {
            self.listing_within(site, MAX_SITE_LISTING)?;
        }
        for site in &layout.site {
            let pth: Vec<String> = self
                .listing_within(site, MAX_SITE_LISTING)?
                .iter()
                .filter(|entry| entry.ends_with(".pth"))
                .cloned()
                .collect();
            for entry in pth {
                let added = self.add_pth(&layout.site, &fs_path::join(site, &entry))?;
                path_directories.extend(added);
            }
        }
        for directory in layout.library.iter().chain(&path_directories) {
            self.add_customize(&path_directories, directory)?;
        }
        if self.startup_replaces.writes() {
            return Err(MUTABLE_LAUNCHER);
        }
        // Only the shim itself may call a function that loads a package.
        let called = self.shim_loaders.iter().any(|(path, loaders)| {
            self.startup_code
                .iter()
                .any(|(other, code)| other != path && loaders.iter().any(|name| uses(code, name)))
        });
        if called {
            return Err(MUTABLE_LAUNCHER);
        }
        // A shim redirects these packages, so a local copy is not what runs.
        let shimmed = self.startup.keys().any(|path| {
            SHIMS.iter().any(|shim| {
                path.ends_with(&format!("/{shim}.py")) || path.contains(&format!("/{shim}/"))
            })
        });
        if shimmed
            && self.modules.keys().any(|path| {
                SHIMMED.iter().any(|name| {
                    path.ends_with(&format!("/{name}.py")) || path.contains(&format!("/{name}/"))
                })
            })
        {
            return Err(MUTABLE_LAUNCHER);
        }
        let standard: Vec<String> = self.standard.iter().cloned().collect();
        for directory in &path_directories {
            let entries = self.listing_within(directory, MAX_SITE_LISTING)?;
            let shadowed = standard.iter().any(|name| {
                entries.iter().any(|entry| {
                    entry == name
                        || entry
                            .strip_prefix(name.as_str())
                            .and_then(|rest| rest.strip_prefix('.'))
                            .is_some_and(|rest| {
                                rest == "py"
                                    || COMPILED_SUFFIXES
                                        .contains(&rest.rsplit('.').next().unwrap_or_default())
                            })
                })
            });
            if shadowed {
                return Err(MUTABLE_LAUNCHER);
            }
        }
        Ok(())
    }
}

#[path = "python_layout.rs"]
mod layout;
#[path = "python_shim.rs"]
mod shim;
