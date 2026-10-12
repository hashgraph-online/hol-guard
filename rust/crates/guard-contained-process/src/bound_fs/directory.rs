use super::*;

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        let canonical = {
            let canonical = fs::canonicalize(path)?;
            if canonical != path {
                return Err(changed());
            }
            canonical
        };
        #[cfg(unix)]
        {
            let mut file = unsafe {
                File::from_raw_fd(checked_fd(libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                ))?)
            };
            for part in path.components() {
                if let Component::Normal(part) = part {
                    let name = cstr(part)?;
                    let fd = checked_fd(unsafe {
                        libc::openat(
                            file.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    })?;
                    file = unsafe { File::from_raw_fd(fd) };
                }
            }
            Ok(Self {
                path: canonical,
                file,
            })
        }
        #[cfg(windows)]
        {
            let binding = guard_runtime_windows_process::bind_readonly_directory(path)?;
            Ok(Self {
                path: binding.path().to_path_buf(),
                binding,
            })
        }
        #[cfg(not(any(unix, windows)))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no bound filesystem",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn handle(&self) -> &File {
        #[cfg(unix)]
        return &self.file;
        #[cfg(windows)]
        return self.binding.handle();
    }

    pub fn verify(&self) -> io::Result<()> {
        let current = Self::open(&self.path)?;
        let expected = identity(self.handle())?;
        let actual = identity(current.handle())?;
        #[cfg(unix)]
        if (expected.device, expected.inode) != (actual.device, actual.inode) {
            return Err(changed());
        }
        #[cfg(windows)]
        if expected.file_id != actual.file_id {
            return Err(changed());
        }
        Ok(())
    }

    pub fn directory(&self, path: &Path) -> io::Result<Self> {
        let components = relative_components(path)?;
        self.verify()?;
        #[cfg(unix)]
        {
            let mut file = unsafe {
                File::from_raw_fd(checked_fd(libc::openat(
                    self.file.as_raw_fd(),
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                ))?)
            };
            for part in components {
                let name = cstr(&part)?;
                file = unsafe {
                    File::from_raw_fd(checked_fd(libc::openat(
                        file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    ))?)
                };
            }
            let directory = Self {
                path: if path == Path::new(".") {
                    self.path.clone()
                } else {
                    self.path.join(path)
                },
                file,
            };
            directory.verify()?;
            Ok(directory)
        }
        #[cfg(windows)]
        {
            let _ = components;
            Self::open(&self.path.join(path))
        }
    }

    pub fn open_file(&self, path: &Path) -> io::Result<File> {
        let parts = relative_components(path)?;
        let name = parts.last().ok_or_else(changed)?;
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let parent = if parent.as_os_str().is_empty() {
            self.directory(Path::new("."))?
        } else {
            self.directory(parent)?
        };
        #[cfg(unix)]
        let file = unsafe {
            File::from_raw_fd(checked_fd(libc::openat(
                parent.file.as_raw_fd(),
                cstr(name)?.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            ))?)
        };
        #[cfg(windows)]
        let file = guard_runtime_windows_process::open_bound_regular_file(&parent.path.join(name))?;
        regular(&file, false)?;
        Ok(file)
    }
    /// Installation resources may be hardlinked by a package manager. They are
    /// never used as writable workspace authority.
    pub fn open_installed_file(&self, path: &Path) -> io::Result<File> {
        relative_components(path)?;
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        let file = unsafe {
            File::from_raw_fd(checked_fd(libc::openat(
                parent.file.as_raw_fd(),
                cstr(name)?.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            ))?)
        };
        #[cfg(windows)]
        let file =
            guard_runtime_windows_process::open_bound_executable_file(&parent.path.join(name))?;
        regular(&file, true)?;
        parent.verify()?;
        Ok(file)
    }

    pub fn read_installed(&self, path: &Path, max_bytes: usize) -> io::Result<ReadFile> {
        let mut file = self.open_installed_file(path)?;
        let read = read_executable(&mut file, max_bytes)?;
        if identity(&self.open_installed_file(path)?)? != read.identity {
            return Err(changed());
        }
        self.verify()?;
        Ok(read)
    }

    pub fn read_link(&self, path: &Path) -> io::Result<(PathBuf, Identity)> {
        relative_components(path)?;
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        {
            #[cfg(target_os = "linux")]
            let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            #[cfg(target_os = "macos")]
            let flags = libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC;
            let file = unsafe {
                File::from_raw_fd(checked_fd(libc::openat(
                    parent.file.as_raw_fd(),
                    cstr(name)?.as_ptr(),
                    flags,
                ))?)
            };
            if !file.metadata()?.file_type().is_symlink() {
                return Err(changed());
            }
            let before = identity(&file)?;
            let mut bytes = [0u8; 4097];
            let count = unsafe {
                libc::readlinkat(
                    parent.file.as_raw_fd(),
                    cstr(name)?.as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if count <= 0 || count as usize >= bytes.len() {
                return Err(changed());
            }
            let current = unsafe {
                File::from_raw_fd(checked_fd(libc::openat(
                    parent.file.as_raw_fd(),
                    cstr(name)?.as_ptr(),
                    flags,
                ))?)
            };
            if identity(&current)? != before || identity(&file)? != before {
                return Err(changed());
            }
            parent.verify()?;
            Ok((
                PathBuf::from(OsString::from_vec(bytes[..count as usize].to_vec())),
                before,
            ))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0220_0000)
                .open(parent.path.join(name))?;
            let before = identity(&file)?;
            let target = fs::read_link(parent.path.join(name))?;
            if identity(&file)? != before {
                return Err(changed());
            }
            parent.verify()?;
            Ok((target, before))
        }
    }

    pub fn read(&self, path: &Path, max_bytes: usize) -> io::Result<ReadFile> {
        let mut file = self.open_file(path)?;
        let read = read_file(&mut file, max_bytes)?;
        let current = self.open_file(path)?;
        if identity(&current)? != read.identity {
            return Err(changed());
        }
        self.verify()?;
        Ok(read)
    }
}
