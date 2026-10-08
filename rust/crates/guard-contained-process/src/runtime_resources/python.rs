use super::*;

#[path = "venv.rs"]
mod venv_config;

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
    let requested_bin = executable.parent().ok_or_else(bound_fs::changed)?;
    let requested_base = installation_root(requested_bin)?;
    let (requested_root, links) = resolve(requested_base)?;
    bindings.extend(links);
    let config = venv_config::read(&requested_root, &guard_home, &mut bindings)?;
    let base_image = match &config {
        Some(config) => config.base_image(executable, &canonical, &guard_home, &mut bindings)?,
        None => canonical.clone(),
    };
    let base = installation_root(base_image.parent().ok_or_else(bound_fs::changed)?)?;
    if base.parent().is_none() || protected(base) || base.starts_with(&guard_home) {
        return Err(bound_fs::changed());
    }
    let version = version_name(
        base_image
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(""),
    )
    .or_else(|| version_name(requested_name));
    let version = if version.is_some() {
        version
    } else {
        crate::runtime_files::python_version(&base_image)?
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
    let include_system = config.as_ref().is_none_or(|config| config.include_system);
    let venv = config.is_some();
    if let Some(config) = &config {
        config.validate_version(&version)?;
    }
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

fn installation_root(bin: &Path) -> io::Result<&Path> {
    if bin
        .file_name()
        .is_some_and(|name| name == "bin" || name == "Scripts")
    {
        bin.parent().ok_or_else(bound_fs::changed)
    } else {
        Ok(bin)
    }
}

#[cfg(test)]
#[path = "python_tests.rs"]
mod tests;
