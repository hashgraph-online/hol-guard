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
        let mut names = vec![requested
            .file_name()
            .ok_or_else(bound_fs::changed)?
            .to_os_string()];
        if let Some(name) = canonical.file_name() {
            if !names.iter().any(|value| value == name) {
                names.push(name.to_os_string());
            }
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
                    return Err(bound_fs::changed());
                }
            }
            bindings.extend(links);
            bindings.push(SourceBinding::capture(&image, &read.identity)?);
            return Ok(image);
        }
        Err(bound_fs::changed())
    }
}
