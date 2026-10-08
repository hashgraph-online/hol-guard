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
        if root.starts_with(&self.excluded)
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
                    if resolved.starts_with(&self.excluded)
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
        if source.starts_with(&self.excluded) || protected(&source) {
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
fn version_name(name: &str) -> Option<String> {
    let value = name
        .strip_prefix("pythonw")
        .or_else(|| name.strip_prefix("python"))?;
    let value = value.strip_suffix(".exe").unwrap_or(value);
    let mut parts = value.split('.');
    if parts.next()? != "3" {
        return None;
    }
    let minor = parts.next()?;
    if minor.is_empty()
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
        || parts.next().is_some()
    {
        return None;
    }
    Some(format!("3.{minor}"))
}

fn capture(
    executable: &Path,
    guard_home: &Path,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<Resources> {
    check(deadline, cancel)?;
    let requested_name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(bound_fs::changed)?;
    if !requested_name.to_ascii_lowercase().starts_with("python") {
        return Ok(Resources {
            files: Vec::new(),
            directories: Vec::new(),
            bindings: Vec::new(),
            python_version: None,
            total_bytes: 0,
        });
    }
    let (canonical, mut bindings) = resolve(executable)?;
    let (guard_home, _) = resolve(guard_home)?;
    if canonical.starts_with(&guard_home) || executable.starts_with(&guard_home) {
        return Err(bound_fs::changed());
    }
    let bin = canonical.parent().ok_or_else(bound_fs::changed)?;
    let base = if bin
        .file_name()
        .is_some_and(|name| name == "bin" || name == "Scripts")
    {
        bin.parent().ok_or_else(bound_fs::changed)?
    } else {
        bin
    };
    if base.parent().is_none() || protected(base) {
        return Err(bound_fs::changed());
    }
    let requested_bin = executable.parent().ok_or_else(bound_fs::changed)?;
    let requested_base = if requested_bin
        .file_name()
        .is_some_and(|name| name == "bin" || name == "Scripts")
    {
        requested_bin.parent().ok_or_else(bound_fs::changed)?
    } else {
        requested_bin
    };
    let version = version_name(
        canonical
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(""),
    )
    .or_else(|| version_name(requested_name));
    let version = if version.is_some() {
        version
    } else {
        crate::runtime_files::python_version(&canonical)?
    };
    let version = if let Some(version) = version {
        version
    } else {
        let lib = Directory::open(&base.join("lib"))?;
        let versions: Vec<_> = lib
            .entries(Path::new("."), MAX_ENTRIES)?
            .into_iter()
            .filter_map(|name| version_name(&name.to_string_lossy()))
            .collect();
        if versions.len() != 1 {
            return Err(bound_fs::changed());
        }
        versions[0].clone()
    };
    let stdlib = base.join("lib").join(format!("python{version}"));
    let stdlib = match resolve(&stdlib) {
        Ok((path, links)) => {
            bindings.extend(links);
            path
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            #[cfg(windows)]
            {
                base.join("Lib")
            }
            #[cfg(not(windows))]
            {
                return Err(error);
            }
        }
        Err(error) => return Err(error),
    };
    let mut approved = vec![
        base.join("lib"),
        base.join("lib64"),
        base.join("Lib"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/local/lib"),
    ];
    if let Some(framework) = base.ancestors().find(|path| {
        path.file_name()
            .is_some_and(|name| name == "Python.framework")
    }) {
        if let Some(distribution) = framework
            .parent()
            .filter(|path| path.file_name().is_some_and(|name| name == "Frameworks"))
            .and_then(Path::parent)
        {
            if distribution.file_name().is_some_and(|name| {
                name.as_encoded_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_digit)
            }) {
                approved.push(distribution.join("lib"));
            }
        }
    }
    if protected(&stdlib)
        || stdlib.starts_with(&guard_home)
        || !approved.iter().any(|root| stdlib.starts_with(root))
    {
        return Err(bound_fs::changed());
    }
    let mut include_system = true;
    let mut venv = false;
    let config = requested_base.join("pyvenv.cfg");
    match bound_fs::open_regular(&config) {
        Ok(mut file) => {
            let read = bound_fs::read_file(&mut file, 64 * 1024)?;
            bindings.push(SourceBinding::capture(&config, &read.identity)?);
            let text = std::str::from_utf8(&read.bytes).map_err(io::Error::other)?;
            let mut fields = BTreeMap::new();
            for line in text
                .lines()
                .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            {
                let (key, value) = line.split_once('=').ok_or_else(bound_fs::changed)?;
                if fields
                    .insert(key.trim().to_ascii_lowercase(), value.trim().to_owned())
                    .is_some()
                {
                    return Err(bound_fs::changed());
                }
            }
            let home = fields.get("home").ok_or_else(bound_fs::changed)?;
            let (home, links) = resolve(Path::new(home))?;
            bindings.extend(links);
            if home != bin {
                return Err(bound_fs::changed());
            }
            if let Some(selector) = fields.get("executable") {
                let (selected, links) = resolve(Path::new(selector))?;
                bindings.extend(links);
                if selected != canonical {
                    return Err(bound_fs::changed());
                }
            }
            include_system = match fields
                .get("include-system-site-packages")
                .map(|value| value.to_ascii_lowercase())
                .as_deref()
            {
                Some("true") => true,
                Some("false") | None => false,
                _ => return Err(bound_fs::changed()),
            };
            if fields.get("version").is_some_and(|value| {
                !value.starts_with(&format!("{version}.")) && value != &version
            }) {
                return Err(bound_fs::changed());
            }
            venv = true;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let (requested_root, links) = resolve(requested_base)?;
    bindings.extend(links);
    approved.extend([
        requested_root.join("lib"),
        requested_root.join("lib64"),
        requested_root.join("Lib"),
    ]);
    let mut capture = Capture {
        files: BTreeMap::new(),
        directories: BTreeSet::new(),
        bindings,
        total: 0,
        entries: 0,
        deadline,
        cancel,
        approved,
        active: BTreeSet::new(),
        link_directories: BTreeMap::new(),
        excluded: &guard_home,
    };
    let target = if cfg!(windows) {
        PathBuf::from("python/Lib")
    } else {
        PathBuf::from("python/lib").join(format!("python{version}"))
    };
    capture.tree(&stdlib, &target, true)?;
    let site = target.join("site-packages");
    let site_roots = if venv {
        vec![
            requested_root
                .join("lib")
                .join(format!("python{version}"))
                .join("site-packages"),
            requested_root
                .join("lib64")
                .join(format!("python{version}"))
                .join("site-packages"),
            requested_root.join("Lib/site-packages"),
        ]
    } else {
        Vec::new()
    };
    let mut roots = site_roots;
    if include_system {
        roots.extend([
            stdlib.join("site-packages"),
            base.join("lib/python3/dist-packages"),
        ]);
    }
    let mut captured_roots = BTreeSet::new();
    for root in roots {
        match resolve(&root) {
            Ok((resolved, links)) => {
                capture.links(links);
                if captured_roots.insert(resolved.clone()) {
                    capture.tree(&resolved, &site, false)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    for binding in &capture.bindings {
        check(deadline, cancel)?;
        binding.verify()?;
    }
    Ok(Resources {
        files: capture.files.into_values().collect(),
        directories: capture.directories.into_iter().collect(),
        bindings: capture.bindings,
        python_version: Some(version),
        total_bytes: capture.total,
    })
}

pub fn python(
    origin: &Path,
    selected: &Path,
    guard_home: &Path,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<Resources> {
    check(deadline, cancel)?;
    let (image, selectors) = resolve_without_control(origin, guard_home)?;
    let (selected, selected_selectors) = resolve_without_control(selected, guard_home)?;
    if image != selected {
        return Err(bound_fs::changed());
    }
    let mut resources = capture(origin, guard_home, deadline, cancel)?;
    resources.bindings.extend(selectors);
    resources.bindings.extend(selected_selectors);
    resources.verify()?;
    Ok(resources)
}
