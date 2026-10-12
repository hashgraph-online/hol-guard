use super::*;

impl Directory {
    /// Private staged output only. This does not publish into a live workspace.
    /// An already authorized output leaf is written through its verified handle,
    /// so LPAC needs no directory-create/delete grant.
    pub fn write_existing(
        &self,
        path: &Path,
        expected: (&Identity, &str),
        bytes: &[u8],
    ) -> io::Result<()> {
        relative_components(path)?;
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        let mut file = unsafe {
            File::from_raw_fd(checked_fd(libc::openat(
                parent.file.as_raw_fd(),
                cstr(name)?.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            ))?)
        };
        #[cfg(windows)]
        let mut file = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(parent.path.join(name))?
        };
        let before = read_file(&mut file, 16 * 1024 * 1024)?;
        let path_matches = || -> io::Result<bool> {
            #[cfg(unix)]
            {
                Ok(identity(&parent.open_file(Path::new(name))?)?.same_object(expected.0))
            }
            #[cfg(windows)]
            {
                // Attribute-only identity queries share the held writer's
                // access without releasing its write/delete exclusion.
                let (file_id, _) =
                    guard_runtime_windows_process::regular_file_id(&parent.path.join(name), false)?;
                Ok(file_id == expected.0.file_id)
            }
        };
        if before.identity != *expected.0 || before.digest != expected.1 || !path_matches()? {
            return Err(changed());
        }
        parent.verify()?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()?;
        if !identity(&file)?.same_object(expected.0) || !path_matches()? {
            return Err(changed());
        }
        parent.verify()
    }

    pub fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        relative_components(path)?;
        if path == Path::new(".") {
            self.verify()?;
            return self.handle().metadata();
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent)?;
        let metadata =
            fs::symlink_metadata(parent.path.join(path.file_name().ok_or_else(changed)?))?;
        parent.verify()?;
        Ok(metadata)
    }

    pub fn entries(&self, path: &Path, remaining: usize) -> io::Result<Vec<OsString>> {
        let directory = self.directory(path)?;
        let mut names = Vec::new();
        #[cfg(unix)]
        {
            let raw = checked_fd(unsafe { libc::dup(directory.file.as_raw_fd()) })?;
            let stream = unsafe { libc::fdopendir(raw) };
            if stream.is_null() {
                unsafe {
                    libc::close(raw);
                }
                return Err(io::Error::last_os_error());
            }
            struct Stream(*mut libc::DIR);
            impl Drop for Stream {
                fn drop(&mut self) {
                    unsafe {
                        libc::closedir(self.0);
                    }
                }
            }
            let stream = Stream(stream);
            loop {
                set_errno(0);
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    let error = errno();
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(error));
                    }
                    break;
                }
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                if names.len() >= remaining {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory entry budget exceeded",
                    ));
                }
                names.push(OsString::from_vec(name.to_vec()));
            }
        }
        #[cfg(windows)]
        {
            // All ancestry handles deny delete sharing, so this pathname still
            // names the held directory throughout enumeration.
            for entry in fs::read_dir(directory.path())? {
                if names.len() >= remaining {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory entry budget exceeded",
                    ));
                }
                names.push(entry?.file_name());
            }
        }
        directory.verify()?;
        names.sort();
        Ok(names)
    }

    pub fn mkdir_all(&self, path: &Path) -> io::Result<()> {
        let mut relative = PathBuf::new();
        for part in relative_components(path)? {
            let directory = self.directory(if relative.as_os_str().is_empty() {
                Path::new(".")
            } else {
                &relative
            })?;
            #[cfg(unix)]
            {
                let status = unsafe {
                    libc::mkdirat(directory.file.as_raw_fd(), cstr(&part)?.as_ptr(), 0o700)
                };
                if status != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(windows)]
            match fs::create_dir(directory.path.join(&part)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            relative.push(part);
            self.directory(&relative)?;
        }
        self.verify()
    }

    /// A new leaf is never opened through a symlink or an existing pathname.
    pub fn create(&self, path: &Path, bytes: &[u8], executable: bool) -> io::Result<()> {
        #[cfg(not(unix))]
        let _ = executable;
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        let mut file = unsafe {
            File::from_raw_fd(checked_fd(libc::openat(
                parent.file.as_raw_fd(),
                cstr(name)?.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                if executable { 0o500 } else { 0o600 },
            ))?)
        };
        #[cfg(windows)]
        let mut file = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(0x0020_0000)
                .open(parent.path.join(name))?
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        // The new name is only durable once its directory entry is flushed.
        #[cfg(unix)]
        if unsafe { libc::fsync(parent.file.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        parent.verify()?;
        Ok(())
    }

    /// Transactional publication validates the displaced target. An exchange
    /// failure may briefly expose output bytes; raced user objects are retained
    /// in a private recovery directory, never removed by recursive cleanup.
    /// Retention is best-effort on Unix against a same-user writer that renames
    /// an object onto a recovery name between its identity check and the
    /// unlink, because POSIX cannot unlink by identity.
    pub fn atomic_replace(
        &self,
        path: &Path,
        expected: Option<(&Identity, &str)>,
        bytes: &[u8],
    ) -> io::Result<()> {
        promotion::replace(self, path, expected, bytes)
    }
    pub fn atomic_remove(&self, path: &Path, expected: (&Identity, &str)) -> io::Result<()> {
        promotion::remove(self, path, expected)
    }

    pub fn atomic_remove_directory(&self, path: &Path, expected: &Identity) -> io::Result<()> {
        promotion::remove_directory(self, path, expected)
    }

    /// Cleanup is restricted to this held private tree. Displaced user objects
    /// are retained by the conditional native removal primitives on a race.
    pub fn remove_tree(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            let mode = self.handle().metadata()?.mode() & 0o7777;
            if mode & 0o700 != 0o700
                && unsafe {
                    libc::fchmod(self.handle().as_raw_fd(), (mode | 0o700) as libc::mode_t)
                } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        for name in self.entries(Path::new("."), 50_000)? {
            let path = Path::new(&name);
            let metadata = self.metadata(path)?;
            if metadata.file_type().is_symlink() {
                return Err(changed());
            }
            if metadata.is_dir() {
                let child = self.directory(path)?;
                let expected = identity(child.handle())?;
                child.remove_tree()?;
                drop(child);
                self.atomic_remove_directory(path, &expected)?;
            } else if metadata.is_file() {
                let file = self.read_installed(path, 256 * 1024 * 1024)?;
                self.atomic_remove(path, (&file.identity, &file.digest))?;
            } else {
                return Err(changed());
            }
        }
        Ok(())
    }

    pub fn unlink(&self, path: &Path, directory: bool) -> io::Result<()> {
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        {
            let result = unsafe {
                libc::unlinkat(
                    parent.file.as_raw_fd(),
                    cstr(name)?.as_ptr(),
                    if directory { libc::AT_REMOVEDIR } else { 0 },
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(windows)]
        if directory {
            fs::remove_dir(parent.path.join(name))?;
        } else {
            fs::remove_file(parent.path.join(name))?;
        }
        parent.verify()
    }
}
