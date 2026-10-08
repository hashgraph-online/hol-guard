use super::*;

pub(super) struct Config {
    home: PathBuf,
    version: Option<String>,
    pub(super) include_system: bool,
}

pub(super) fn read(
    root: &Path,
    guard_home: &Path,
    bindings: &mut Vec<SourceBinding>,
) -> io::Result<Option<Config>> {
    if root.starts_with(guard_home) || protected(root) {
        return Err(bound_fs::changed());
    }
    let path = root.join("pyvenv.cfg");
    let mut file = match bound_fs::open_regular(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let read = bound_fs::read_file(&mut file, 64 * 1024)?;
    bindings.push(SourceBinding::capture(&path, &read.identity)?);
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
    let (home, links) = resolve_without_control(
        Path::new(fields.get("home").ok_or_else(bound_fs::changed)?),
        guard_home,
    )?;
    bindings.extend(links);
    let include_system = match fields
        .get("include-system-site-packages")
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("true") => true,
        Some("false") | None => false,
        _ => return Err(bound_fs::changed()),
    };
    // CPython uses `home` for base-prefix discovery. `executable` records the
    // creator's sys.executable and can itself be another venv; it is not a
    // requirement that the requested venv image resolve to that path.
    Ok(Some(Config {
        home,
        version: fields.remove("version"),
        include_system,
    }))
}

impl Config {
    pub(super) fn validate_version(&self, version: &str) -> io::Result<()> {
        if self
            .version
            .as_ref()
            .is_some_and(|value| value != version && !value.starts_with(&format!("{version}.")))
        {
            return Err(bound_fs::changed());
        }
        Ok(())
    }

    pub(super) fn base_image(
        &self,
        requested: &Path,
        canonical: &Path,
        guard_home: &Path,
        bindings: &mut Vec<SourceBinding>,
    ) -> io::Result<PathBuf> {
        // The canonical image is authoritative. An unversioned alias in
        // `home` may belong to a different Python installation.
        let mut names = vec![canonical
            .file_name()
            .ok_or_else(bound_fs::changed)?
            .to_os_string()];
        let requested_name = requested.file_name().ok_or_else(bound_fs::changed)?;
        if !names.iter().any(|value| value == requested_name) {
            names.push(requested_name.to_os_string());
        }
        if let Some(version) = &self.version {
            let major_minor = version.split('.').take(2).collect::<Vec<_>>().join(".");
            if version_name(&format!("python{major_minor}")).is_none() {
                return Err(bound_fs::changed());
            }
            let extension = if cfg!(windows) { ".exe" } else { "" };
            names.push(OsString::from(format!("python{major_minor}{extension}")));
        }
        for name in names {
            let (image, links) = match resolve_without_control(&self.home.join(name), guard_home) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let mut original = bound_fs::open_executable(&image)?;
            let read = bound_fs::read_executable(&mut original, MAX_BYTES)?;
            #[cfg(unix)]
            if image != canonical {
                let mut selected = bound_fs::open_executable(canonical)?;
                if bound_fs::digest_executable(&mut selected, MAX_BYTES)? != read.digest {
                    continue;
                }
            }
            bindings.extend(links);
            bindings.push(SourceBinding::capture(&image, &read.identity)?);
            return Ok(image);
        }
        Err(bound_fs::changed())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn base_image_prefers_canonical_and_skips_other_version_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let home = root.join("base/bin");
        let venv = root.join("venv/bin");
        let guard = root.join("guard");
        for directory in [&home, &venv, &guard] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let requested = venv.join("python");
        let selected = home.join("python3.11");
        std::fs::write(&selected, b"selected interpreter").unwrap();
        std::fs::write(home.join("python"), b"another interpreter").unwrap();
        std::fs::write(&requested, b"selected interpreter").unwrap();
        let config = Config {
            home: home.clone(),
            version: Some("3.11.9".into()),
            include_system: false,
        };
        // Symlink venvs supply the canonical installation path; copied venvs
        // must skip the mismatched alias and reach the versioned candidate.
        for canonical in [&selected, &requested] {
            let mut bindings = Vec::new();
            assert_eq!(
                config
                    .base_image(&requested, canonical, &guard, &mut bindings)
                    .unwrap(),
                selected
            );
            for binding in bindings {
                binding.verify().unwrap();
            }
        }
        std::fs::write(&selected, b"also a different interpreter").unwrap();
        assert!(config
            .base_image(&requested, &requested, &guard, &mut Vec::new())
            .is_err());
    }
}
