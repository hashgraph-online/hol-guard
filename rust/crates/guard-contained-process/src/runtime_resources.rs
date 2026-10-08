//! Native, handle-bound capture of installed interpreter resources. Discovery
//! reads installation metadata; it never runs the foreign interpreter.
use crate::bound_fs::{self, Directory, Identity};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

const MAX_FILES: usize = 20_000;
const MAX_ENTRIES: usize = 50_000;
const MAX_BYTES: usize = 256 * 1024 * 1024;

pub struct ResourceFile {
    pub destination: PathBuf,
    pub source: PathBuf,
    pub bytes: Vec<u8>,
    pub digest: String,
}
enum Binding {
    File {
        identity: Identity,
        pin: Option<File>,
    },
    Link {
        identity: Identity,
        target: PathBuf,
    },
    Directory {
        identity: Identity,
        entries: Vec<OsString>,
    },
}
pub struct SourceBinding {
    directory: Arc<Directory>,
    name: PathBuf,
    binding: Binding,
}
impl SourceBinding {
    pub fn capture(path: &Path, expected: &Identity) -> io::Result<Self> {
        let directory = Arc::new(Directory::open(
            path.parent().ok_or_else(bound_fs::changed)?,
        )?);
        let name = PathBuf::from(path.file_name().ok_or_else(bound_fs::changed)?);
        let file = directory.open_installed_file(&name)?;
        if bound_fs::identity(&file)? != *expected {
            return Err(bound_fs::changed());
        }
        Ok(Self {
            directory,
            name,
            binding: Binding::File {
                identity: expected.clone(),
                pin: Some(file),
            },
        })
    }
    pub fn verify(&self) -> io::Result<()> {
        self.directory.verify()?;
        match &self.binding {
            Binding::File { identity, pin } => {
                if pin
                    .as_ref()
                    .is_some_and(|file| bound_fs::identity(file).ok().as_ref() != Some(identity))
                    || bound_fs::identity(&self.directory.open_installed_file(&self.name)?)?
                        != *identity
                {
                    return Err(bound_fs::changed());
                }
            }
            Binding::Link { identity, target } => {
                let (current_target, current_identity) = self.directory.read_link(&self.name)?;
                if current_target != *target || current_identity != *identity {
                    return Err(bound_fs::changed());
                }
            }
            Binding::Directory { identity, entries } => {
                let current = self.directory.directory(&self.name)?;
                if bound_fs::identity(current.handle())? != *identity
                    || self.directory.entries(&self.name, MAX_ENTRIES)? != *entries
                {
                    return Err(bound_fs::changed());
                }
            }
        }
        Ok(())
    }
}

pub struct Resources {
    pub files: Vec<ResourceFile>,
    pub directories: Vec<PathBuf>,
    pub bindings: Vec<SourceBinding>,
    pub python_version: Option<String>,
    pub total_bytes: usize,
}
impl Resources {
    pub fn verify(&self) -> io::Result<()> {
        for binding in &self.bindings {
            binding.verify()?;
        }
        Ok(())
    }
}
fn check(deadline: Instant, cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "runtime capture deadline",
        ))
    } else {
        Ok(())
    }
}
fn protected(path: &Path) -> bool {
    secret(path)
        || path.components().any(|part| {
            [".guard", ".hol-guard", "__pycache__"].contains(
                &part
                    .as_os_str()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .as_str(),
            )
        })
}
pub(crate) fn secret(path: &Path) -> bool {
    path.components().any(|part| {
        let name = part.as_os_str().to_string_lossy().to_ascii_lowercase();
        name.starts_with(".env")
            || [
                ".git",
                ".ssh",
                ".aws",
                ".azure",
                ".config",
                ".docker",
                ".gnupg",
                ".kube",
                ".codex",
                ".claude",
                ".cursor",
                "credentials",
                ".netrc",
                "id_rsa",
                "id_ed25519",
                "id_ecdsa",
            ]
            .contains(&name.as_str())
            || [".pem", ".key", ".p12", ".pfx"]
                .iter()
                .any(|suffix| name.ends_with(suffix))
    })
}
fn normalized(path: &Path) -> io::Result<PathBuf> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => result.push(prefix.as_os_str()),
            Component::RootDir => result.push(component.as_os_str()),
            Component::Normal(name) => result.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    return Err(bound_fs::changed());
                }
            }
        }
    }
    if !result.is_absolute() {
        return Err(bound_fs::changed());
    }
    Ok(result)
}

/// Resolve every installation symlink through a held parent. The bindings are
/// retained alongside the copied bytes so retargeting a selector invalidates it.
pub fn resolve(path: &Path) -> io::Result<(PathBuf, Vec<SourceBinding>)> {
    resolve_impl(path, None)
}
pub fn resolve_without_control(
    path: &Path,
    guard_home: &Path,
) -> io::Result<(PathBuf, Vec<SourceBinding>)> {
    resolve_impl(path, Some(guard_home))
}
fn resolve_impl(
    path: &Path,
    guard_home: Option<&Path>,
) -> io::Result<(PathBuf, Vec<SourceBinding>)> {
    let mut path = normalized(path)?;
    let mut bindings = Vec::new();
    for _ in 0..64 {
        if guard_home.is_some_and(|home| path.starts_with(home) || secret(&path)) {
            return Err(bound_fs::changed());
        }
        let mut current = PathBuf::new();
        let components: Vec<_> = path.components().collect();
        let mut expanded = false;
        for (index, component) in components.iter().enumerate() {
            if !matches!(component, Component::Normal(_)) {
                current.push(component.as_os_str());
                continue;
            }
            let directory = Arc::new(Directory::open(&current)?);
            let name = PathBuf::from(component.as_os_str());
            let metadata = directory.metadata(&name)?;
            if metadata.file_type().is_symlink() {
                let (target, identity) = directory.read_link(&name)?;
                let mut replacement = if target.is_absolute() {
                    target.clone()
                } else {
                    current.join(&target)
                };
                for remaining in &components[index + 1..] {
                    replacement.push(remaining.as_os_str());
                }
                bindings.push(SourceBinding {
                    directory,
                    name,
                    binding: Binding::Link { identity, target },
                });
                path = normalized(&replacement)?;
                expanded = true;
                break;
            }
            current.push(component.as_os_str());
        }
        if !expanded {
            for binding in &bindings {
                binding.verify()?;
            }
            return Ok((path, bindings));
        }
    }
    Err(bound_fs::changed())
}

struct Capture<'a> {
    files: BTreeMap<PathBuf, ResourceFile>,
    directories: BTreeSet<PathBuf>,
    bindings: Vec<SourceBinding>,
    total: usize,
    entries: usize,
    deadline: Instant,
    cancel: &'a AtomicBool,
    approved: Vec<PathBuf>,
    active: BTreeSet<PathBuf>,
    link_directories: BTreeMap<PathBuf, Arc<Directory>>,
    excluded: &'a Path,
}
impl Capture<'_> {
    fn links(&mut self, links: Vec<SourceBinding>) {
        for mut binding in links {
            let path = binding.directory.path().to_path_buf();
            binding.directory = self
                .link_directories
                .entry(path)
                .or_insert_with(|| binding.directory.clone())
                .clone();
            self.bindings.push(binding);
        }
    }
    fn tree(&mut self, requested: &Path, destination: &Path, omit_sites: bool) -> io::Result<()> {
        check(self.deadline, self.cancel)?;
        let (root, links) = resolve(requested)?;
        if root.starts_with(self.excluded)
            || !self
                .approved
                .iter()
                .any(|approved| root.starts_with(approved))
            || protected(&root)
        {
            return Err(bound_fs::changed());
        }
        if !self.active.insert(root.clone()) || self.active.len() > 64 {
            return Err(bound_fs::changed());
        }
        self.links(links);
        let directory = Arc::new(Directory::open(&root)?);
        let mut pending = vec![(PathBuf::from("."), destination.to_path_buf())];
        while let Some((relative, destination)) = pending.pop() {
            check(self.deadline, self.cancel)?;
            self.directories.insert(destination.clone());
            let current = directory.directory(&relative)?;
            let identity = bound_fs::identity(current.handle())?;
            let names = directory.entries(&relative, MAX_ENTRIES.saturating_sub(self.entries))?;
            self.entries = self
                .entries
                .checked_add(names.len())
                .ok_or_else(bound_fs::changed)?;
            if self.entries > MAX_ENTRIES {
                return Err(bound_fs::changed());
            }
            self.bindings.push(SourceBinding {
                directory: directory.clone(),
                name: relative.clone(),
                binding: Binding::Directory {
                    identity,
                    entries: names.clone(),
                },
            });
            for name in names {
                check(self.deadline, self.cancel)?;
                let source = if relative == Path::new(".") {
                    PathBuf::from(&name)
                } else {
                    relative.join(&name)
                };
                if protected(&source)
                    || (omit_sites
                        && ["site-packages", "dist-packages"]
                            .contains(&name.to_string_lossy().as_ref()))
                {
                    continue;
                }
                let target = destination.join(&name);
                let metadata = directory.metadata(&source)?;
                if metadata.file_type().is_symlink() {
                    let (resolved, links) = resolve(&root.join(&source))?;
                    let sitecustomize = name == "sitecustomize.py"
                        && resolved
                            == PathBuf::from(format!(
                                "/etc/{}/sitecustomize.py",
                                destination
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                            ));
                    if resolved.starts_with(self.excluded)
                        || protected(&resolved)
                        || (!sitecustomize
                            && !self
                                .approved
                                .iter()
                                .any(|approved| resolved.starts_with(approved)))
                    {
                        return Err(bound_fs::changed());
                    }
                    self.links(links);
                    let resolved_parent = Arc::new(Directory::open(
                        resolved.parent().ok_or_else(bound_fs::changed)?,
                    )?);
                    let resolved_name =
                        PathBuf::from(resolved.file_name().ok_or_else(bound_fs::changed)?);
                    let metadata = resolved_parent.metadata(&resolved_name)?;
                    if metadata.is_dir() {
                        if current.path().starts_with(&resolved) {
                            return Err(bound_fs::changed());
                        }
                        self.tree(&resolved, &target, omit_sites)?;
                    } else if metadata.is_file() {
                        self.leaf(resolved_parent, &resolved_name, target, resolved)?;
                    } else {
                        return Err(bound_fs::changed());
                    }
                } else if metadata.is_dir() {
                    pending.push((source, target));
                } else if metadata.is_file() {
                    self.leaf(directory.clone(), &source, target, root.join(&source))?;
                } else {
                    return Err(bound_fs::changed());
                }
            }
        }
        self.active.remove(&root);
        Ok(())
    }
    fn leaf(
        &mut self,
        directory: Arc<Directory>,
        name: &Path,
        destination: PathBuf,
        source: PathBuf,
    ) -> io::Result<()> {
        if source.starts_with(self.excluded) || protected(&source) {
            return Err(bound_fs::changed());
        }
        if self.files.contains_key(&destination) {
            return Ok(());
        }
        if self.files.len() >= MAX_FILES {
            return Err(bound_fs::changed());
        }
        let read = directory.read_installed(name, MAX_BYTES.saturating_sub(self.total))?;
        self.total = self
            .total
            .checked_add(read.bytes.len())
            .ok_or_else(bound_fs::changed)?;
        if self.total > MAX_BYTES {
            return Err(bound_fs::changed());
        }
        let native = read.bytes.starts_with(b"\x7fELF")
            || read.bytes.starts_with(b"MZ")
            || read.bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
            || read.bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
            || read.bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbf]);
        let pin = if native {
            Some(directory.open_installed_file(name)?)
        } else {
            None
        };
        if pin
            .as_ref()
            .is_some_and(|file| bound_fs::identity(file).ok().as_ref() != Some(&read.identity))
        {
            return Err(bound_fs::changed());
        }
        self.bindings.push(SourceBinding {
            directory,
            name: name.to_path_buf(),
            binding: Binding::File {
                identity: read.identity,
                pin,
            },
        });
        self.files.insert(
            destination.clone(),
            ResourceFile {
                destination,
                source,
                bytes: read.bytes,
                digest: read.digest,
            },
        );
        Ok(())
    }
}

#[path = "runtime_resources/python.rs"]
mod python_capture;
pub use python_capture::python;
