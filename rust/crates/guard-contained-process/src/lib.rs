//! Handle-bound process launch shared by contained execution and native Git inspection.
//!
//! This crate is the narrow FFI boundary. Callers own policy; this crate owns
//! executable/cwd identity, inherited descriptors, deadlines, output, kill and reap.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

pub mod bound_fs;
#[cfg(unix)]
pub mod bound_output;
#[cfg(unix)]
pub mod deferred_output;
#[cfg(target_os = "macos")]
pub mod host_owner;
pub mod probe;
pub use probe::main as probe_main;
#[cfg(target_os = "macos")]
mod macos_code_image;
pub mod runtime_files;
pub mod runtime_resources;
#[cfg(unix)]
mod source_launch;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use source_launch::SourceLaunchGate;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub fn supplementary_groups() -> io::Result<Vec<libc::gid_t>> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut groups = vec![0; count as usize];
    if count == 0 {
        return Ok(groups);
    }
    let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if actual < 0 {
        return Err(io::Error::last_os_error());
    }
    groups.truncate(actual as usize);
    Ok(groups)
}

#[derive(Debug)]
pub struct CapturedOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub output_limited: bool,
    pub completion: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    pub cpu_seconds: u64,
    pub memory_bytes: u64,
    pub file_bytes: u64,
    pub open_files: u64,
    pub processes: u64,
}

/// Filesystem policy is applied in the child before it can execute caller code.
#[derive(Default)]
pub struct Isolation {
    pub seatbelt: Option<String>,
    pub completion_report: bool,
    pub resources: Option<ResourceLimits>,
    pub output_per_stream: bool,
    pub node_virtual_address_space: bool,
    #[cfg(unix)]
    pub inherited_files: Vec<File>,
    #[cfg(unix)]
    pub deferred_outputs: Vec<deferred_output::DeferredOutput>,
    #[cfg(unix)]
    pub creation_mask: Option<u32>,
    #[cfg(windows)]
    pub app_container: Option<windows::AppContainer>,
    #[cfg(windows)]
    pub job_limits: Option<guard_runtime_windows_process::ResourceLimits>,
}

/// Inspection and launch use this same opened file and directory, never a
/// second PATH lookup. The byte digest belongs to the pinned executable.
pub struct PinnedCommand {
    #[cfg(unix)]
    executable: File,
    executable_path: PathBuf,
    source: File,
    source_identity: bound_fs::Identity,
    #[cfg(target_os = "macos")]
    source_directory: std::sync::Arc<bound_fs::Directory>,
    #[cfg(not(target_os = "macos"))]
    source_directory: bound_fs::Directory,
    selectors: Vec<runtime_resources::SourceBinding>,
    cwd: bound_fs::Directory,
    pub executable_digest: String,
    argument_zero: OsString,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    #[cfg(target_os = "macos")]
    image: unix::PinnedImage,
}

impl PinnedCommand {
    pub fn new(
        executable: &Path,
        args: &[&OsStr],
        cwd: &Path,
        env: &[(OsString, OsString)],
    ) -> io::Result<Self> {
        Self::new_with_image_root(executable, args, cwd, env, None)
    }

    /// Contained callers supply their trusted private runtime root. Generic
    /// callers still receive a dedicated, read-only private named image on macOS.
    pub fn new_with_image_root(
        executable: &Path,
        args: &[&OsStr],
        cwd: &Path,
        env: &[(OsString, OsString)],
        image_root: Option<&Path>,
    ) -> io::Result<Self> {
        let (executable_path, selectors) = runtime_resources::resolve(executable)?;
        let source_directory =
            bound_fs::Directory::open(executable_path.parent().ok_or_else(bound_fs::changed)?)?;
        #[cfg(target_os = "macos")]
        let source_directory = std::sync::Arc::new(source_directory);
        let mut source = bound_fs::open_executable(&executable_path)?;
        let digest = bound_fs::digest_executable(&mut source, 256 * 1024 * 1024)?;
        let source_identity = bound_fs::identity(&source)?;
        #[cfg(target_os = "linux")]
        let executable_file = unix::seal_executable(source.try_clone()?, &digest)?;
        #[cfg(target_os = "macos")]
        let image = unix::seal_executable(
            source.try_clone()?,
            &digest,
            image_root,
            source_directory.clone(),
        )?;
        #[cfg(target_os = "macos")]
        let executable_file = image.file.try_clone()?;
        #[cfg(not(target_os = "macos"))]
        let _ = image_root;
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
        let executable_file = source.try_clone()?;
        let argument_zero = executable_path.as_os_str().to_os_string();
        Ok(Self {
            #[cfg(unix)]
            executable: executable_file,
            executable_path,
            source,
            source_identity,
            source_directory,
            cwd: bound_fs::Directory::open(cwd)?,
            executable_digest: digest,
            selectors,
            argument_zero,
            arguments: args.iter().map(|arg| (*arg).to_os_string()).collect(),
            environment: env.to_vec(),
            #[cfg(target_os = "macos")]
            image,
        })
    }

    pub fn executable_handle(&self) -> &File {
        &self.source
    }
    pub fn executable_metadata(&self) -> io::Result<std::fs::Metadata> {
        self.source.metadata()
    }
    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }
    pub fn effective_executable_path(&self) -> &Path {
        #[cfg(target_os = "macos")]
        {
            &self.image.path
        }
        #[cfg(not(target_os = "macos"))]
        {
            &self.executable_path
        }
    }
    pub fn cwd(&self) -> &Path {
        self.cwd.path()
    }

    /// Set exact arguments and environment without resolving the executable
    /// or working directory again. The held image and all bindings survive.
    pub fn with_invocation(
        mut self,
        arguments: &[&OsStr],
        environment: &[(OsString, OsString)],
    ) -> io::Result<Self> {
        self.verify_bindings()?;
        self.arguments = arguments
            .iter()
            .map(|argument| argument.to_os_string())
            .collect();
        self.environment = environment.to_vec();
        Ok(self)
    }

    /// Preserve a reviewed invocation spelling as argv[0] while retaining the
    /// already pinned executable, cwd and runtime-resource bindings.
    pub fn with_invocation_argv0(
        mut self,
        argument_zero: &OsStr,
        arguments: &[&OsStr],
        environment: &[(OsString, OsString)],
    ) -> io::Result<Self> {
        if argument_zero.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.verify_bindings()?;
        self.argument_zero = argument_zero.to_os_string();
        self.arguments = arguments
            .iter()
            .map(|argument| argument.to_os_string())
            .collect();
        self.environment = environment.to_vec();
        Ok(self)
    }

    /// Validate the private macOS image snapshot used by hardened launch.
    /// The original source path may have changed after capture; cwd and the
    /// private image's exact digest and signature remain mandatory.
    #[cfg(target_os = "macos")]
    pub fn verify_hardened_image(&self) -> io::Result<()> {
        self.hardened_binding().map(drop)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn hardened_binding(&self) -> io::Result<macos_code_image::Binding> {
        self.cwd.verify()?;
        self.image.hardened_binding(&self.executable_digest)
    }

    pub(crate) fn verify_bindings(&self) -> io::Result<()> {
        self.source_directory.verify()?;
        self.cwd.verify()?;
        for selector in &self.selectors {
            selector.verify()?;
        }
        if bound_fs::identity(&self.source)? != self.source_identity {
            return Err(bound_fs::changed());
        }
        let current = bound_fs::open_executable(&self.executable_path)?;
        if bound_fs::identity(&current)? != self.source_identity {
            return Err(bound_fs::changed());
        }
        Ok(())
    }

    /// On Unix, the host must retain exclusive child-wait custody throughout
    /// capture: no wildcard reaper or concurrent SIGCHLD disposition changes.
    /// Autoreaping is rejected before launch; ECHILD revokes this owner's
    /// numerical signal authority. Those checks cannot close a concurrent
    /// foreign reaper's PID-reuse race.
    pub fn capture(
        self,
        input: &[u8],
        cap: usize,
        deadline: Instant,
        cancel: &AtomicBool,
        isolation: Isolation,
    ) -> io::Result<CapturedOutput> {
        if cap == 0 || input.len() > 256 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid process I/O budget",
            ));
        }
        #[cfg(unix)]
        return unix::capture(
            self,
            input,
            cap,
            deadline,
            cancel,
            isolation,
            unix::CaptureMode::Standard(None),
        );
        #[cfg(windows)]
        return windows::capture(self, input, cap, deadline, cancel, isolation);
        #[cfg(not(any(unix, windows)))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no handle-bound process kernel",
        ))
    }

    /// Launch a signed macOS executable only after the kernel has suspended
    /// the exact CodeDirectory reviewed from this pinned image. The sandbox is
    /// mandatory and the signature must enable hardened runtime without any
    /// entitlements.
    #[cfg(target_os = "macos")]
    pub fn capture_hardened_image(
        self,
        input: &[u8],
        cap: usize,
        deadline: Instant,
        cancel: &AtomicBool,
        isolation: Isolation,
    ) -> io::Result<CapturedOutput> {
        if cap == 0
            || input.len() > 256 * 1024 * 1024
            || isolation.seatbelt.is_none()
            || !isolation.deferred_outputs.is_empty()
            || isolation.creation_mask.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid hardened process isolation",
            ));
        }
        unix::capture(
            self,
            input,
            cap,
            deadline,
            cancel,
            isolation,
            unix::CaptureMode::Hardened,
        )
    }
}

/// Linux data mounts consume these sealed descriptors, never live source paths.
#[cfg(target_os = "linux")]
pub fn sealed_file(source: File, expected: &str) -> io::Result<File> {
    unix::seal_executable(source, expected)
}

#[cfg(target_os = "linux")]
pub fn sealed_bytes(bytes: &[u8], expected: &str) -> io::Result<File> {
    unix::seal_bytes(bytes, expected)
}

#[cfg(unix)]
pub fn process_ceiling(additional: u64) -> io::Result<u64> {
    unix::process_ceiling(additional)
}

#[cfg(windows)]
pub use windows::readonly::{run_readonly_snapshot, BuildRun, ReadonlySnapshotRun};
#[cfg(windows)]
pub use windows::AppContainer;

#[cfg(all(test, target_os = "macos"))]
mod macos_hardened_image_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests;
