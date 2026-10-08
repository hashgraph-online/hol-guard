//! Containment primitives for `archive-inspect`: admission lease, resource
//! limits, platform sandbox application, and the capability probes that prove
//! denial before untrusted archive bytes are parsed. Everything here runs on
//! the worker side of the transport boundary; orchestration lives in
//! `archive_inspect`.

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
use fs2::FileExt;
use guard_archive::ArchiveOutcome;

#[cfg(unix)]
/// Lease file inside the caller-declared Guard home. Exactly one archive
/// inspector may hold it at a time across client processes and runtime
/// generations; contenders get a bounded `overloaded` result, never a queue.
const ARCHIVE_LEASE_NAME: &str = "archive-inspect.lock";

/// In-process seatbelt profile for the archive worker. The `sandbox-exec`
/// wrapper the caller applies can only deny `network*` — a profile applied
/// before `execvp` cannot deny `process-exec` without preventing the launch
/// itself — so the full denial set is applied here, after start, and then
/// proven by the capability probes below.
#[cfg(target_os = "macos")]
const ARCHIVE_SEATBELT_PROFILE: &str = "(version 1) (allow default) (deny network*) \
     (deny file-write*) (deny process-exec) (deny process-fork)";

/// Uniform lease-admission failure: caller-visible detail stays out of the
/// sandboxed path so a hostile `state_dir` learns nothing from error text.
#[cfg(unix)]
fn lease_error() -> ArchiveOutcome {
    ArchiveOutcome::incomplete(
        "external_archive_inspection_incomplete",
        "External archive inspection lease could not be established.",
        None,
    )
}

/// Take the native one-inspector lease for this request's Guard home. The
/// worker — not the caller — owns admission, so direct CLI invocations and
/// adapter callers contend on the same kernel lease. `Ok(None)` means a peer
/// already holds it: the result is `overloaded`, not a queued wait.
///
/// The lease leaf is opened with `O_NOFOLLOW` and re-verified on the opened
/// descriptor: a symlinked or hardlinked `archive-inspect.lock` would alias
/// an unrelated writable inode, letting a hostile `state_dir` redirect the
/// lock onto a victim file.
#[cfg(unix)]
pub(crate) fn acquire_archive_lease(
    state_dir: &str,
) -> Result<Option<(File, PathBuf)>, ArchiveOutcome> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let canonical = match std::fs::canonicalize(state_dir) {
        Ok(path) if path.is_dir() => path,
        _ => return Err(lease_error()),
    };
    let lease_path = canonical.join(ARCHIVE_LEASE_NAME);
    match std::fs::symlink_metadata(&lease_path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.nlink() > 1 =>
        {
            return Err(lease_error());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(lease_error()),
    }
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&lease_path)
    {
        Ok(file) => file,
        Err(_) => return Err(lease_error()),
    };
    // Close the check-to-open race on the opened descriptor itself: O_NOFOLLOW
    // already refuses a swapped-in symlink, and a swapped-in hardlink aliases
    // a foreign inode, so the lease must be a single-name regular file.
    match file.metadata() {
        Ok(metadata) if metadata.file_type().is_file() && metadata.nlink() <= 1 => {}
        _ => return Err(lease_error()),
    }
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some((file, lease_path))),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(_) => Err(lease_error()),
    }
}

/// Probe that writes are actually denied: opening the already-held lease
/// file for writing must fail under seccomp (openat flagged) and seatbelt
/// (file-write*). A successful open means no sandbox is active. Only a
/// permission denial is proof — an unrelated failure (fd exhaustion, the
/// lease disappearing) cannot distinguish sandbox from environment, so the
/// probe fails closed and the caller reports containment unavailable.
#[cfg(unix)]
pub(crate) fn write_capability_denied(lease_path: &Path) -> bool {
    matches!(
        OpenOptions::new().write(true).open(lease_path),
        Err(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied
    )
}

/// Probe that child creation is actually denied: under seccomp `clone`
/// fails, under seatbelt `process-exec`/`process-fork` deny `posix_spawn`.
/// The probe binary must exist — a `NotFound` would masquerade as a sandbox
/// denial — and stock macOS ships only `/usr/bin/true`, so both candidates
/// are tried. Only a permission error proves denial; `EMFILE`/`EAGAIN`-class
/// spawn failures say nothing about the sandbox, so they fail closed like a
/// missing probe target. A spawned child means containment is absent and is
/// reaped immediately.
#[cfg(unix)]
pub(crate) fn spawn_capability_denied() -> bool {
    for probe in ["/usr/bin/true", "/bin/true"] {
        if !Path::new(probe).is_file() {
            continue;
        }
        return match std::process::Command::new(probe)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Err(ref error) => error.kind() == std::io::ErrorKind::PermissionDenied,
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                false
            }
        };
    }
    false
}

/// Probe that outbound network is actually denied before parsing untrusted
/// bytes. Under seccomp the socket call itself fails; under seatbelt the
/// socket is created but connect is denied. Anything else means the worker
/// has unmediated network and must refuse to inspect.
#[cfg(unix)]
pub(crate) fn network_capability_denied() -> bool {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, SockaddrIn};
    use std::os::fd::AsRawFd;

    let descriptor = match socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    ) {
        Ok(descriptor) => descriptor,
        // Only EPERM/EACCES prove the sandbox cut the call. Resource errors
        // like EMFILE would fake denial without any sandbox, so they fail
        // closed as "not denied".
        Err(nix::errno::Errno::EPERM) | Err(nix::errno::Errno::EACCES) => return true,
        Err(_) => return false,
    };
    let loopback = SockaddrIn::new(127, 0, 0, 1, 9);
    matches!(
        connect(descriptor.as_raw_fd(), &loopback),
        Err(nix::errno::Errno::EPERM) | Err(nix::errno::Errno::EACCES)
    )
}

/// Capability denial: on Linux a seccomp deny-list removes the socket and
/// process families outright; on macOS the worker applies its own seatbelt
/// profile in-process — the `sandbox-exec` wrapper cannot deny exec without
/// blocking the launch, so the stricter profile must land after start.
/// Other Unix targets have no containment layer to verify, so inspection is
/// unavailable.
#[cfg(unix)]
pub(crate) fn apply_capability_deny() -> bool {
    #[cfg(target_os = "linux")]
    {
        apply_seccomp_deny_list().is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        guard_seatbelt::apply(ARCHIVE_SEATBELT_PROFILE)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

pub(crate) fn sandbox_unavailable() -> ArchiveOutcome {
    ArchiveOutcome::incomplete(
        "external_archive_sandbox_unavailable",
        "External archive resource sandbox is unavailable on this platform.",
        None,
    )
}

/// `_child_limits` port: CPU, file-descriptor, and address-space bounds that
/// must all be established before parsing untrusted bytes. Returns false when
/// any required limit cannot be applied — the caller fails closed.
#[cfg(unix)]
pub(crate) fn apply_child_limits(timeout_ms: u64, max_memory_bytes: u64) -> bool {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};

    let cpu_seconds = timeout_ms.div_ceil(1000).max(1);
    let cpu_ok = match getrlimit(Resource::RLIMIT_CPU) {
        Ok((_soft, hard)) => {
            let limit = if hard == u64::MAX {
                cpu_seconds
            } else {
                cpu_seconds.min(hard)
            };
            limit > 0
                && setrlimit(
                    Resource::RLIMIT_CPU,
                    limit,
                    if hard == u64::MAX { u64::MAX } else { hard },
                )
                .is_ok()
        }
        Err(_) => false,
    };
    let files_ok = match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok((_soft, hard)) => {
            let limit = if hard == u64::MAX {
                32
            } else {
                32u64.min(hard)
            };
            limit >= 8 && setrlimit(Resource::RLIMIT_NOFILE, limit, hard).is_ok()
        }
        Err(_) => false,
    };
    let memory_ok = apply_address_space_limit(max_memory_bytes);
    cpu_ok && files_ok && memory_ok
}

#[cfg(unix)]
fn apply_address_space_limit(max_memory_bytes: u64) -> bool {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};

    let current_virtual = current_virtual_size_bytes().unwrap_or(0);
    // Darwin materializes shared-cache submaps and allocator reservations on
    // demand after measurement, so the kernel's map accounting can exceed the
    // sampled task vsize by hundreds of MB. A fixed slack keeps the ceiling
    // enforceable for real growth without aborting ordinary allocations.
    #[cfg(target_os = "macos")]
    let slack_bytes = 512 * 1024 * 1024u64;
    #[cfg(not(target_os = "macos"))]
    let slack_bytes = 0u64;
    let memory_limit = current_virtual
        .saturating_add(max_memory_bytes)
        .saturating_add(slack_bytes);
    match getrlimit(Resource::RLIMIT_AS) {
        Ok((_soft, hard)) => {
            let applied = if hard == u64::MAX {
                memory_limit
            } else {
                memory_limit.min(hard)
            };
            if applied <= current_virtual {
                return false;
            }
            if setrlimit(Resource::RLIMIT_AS, applied, applied).is_err() {
                return false;
            }
            match getrlimit(Resource::RLIMIT_AS) {
                Ok((soft, hard)) => current_virtual < soft && soft <= applied && hard == soft,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// Force lazy allocator regions to exist before `RLIMIT_AS` is computed from
/// the current virtual size. A `Vec` per size class materializes the Darwin
/// malloc zones and the Rust arena reservations the worker will rely on; the
/// reservations persist after the buffers drop, so the measured limit stays
/// above them. Untouched pages are never committed.
#[cfg(target_os = "macos")]
pub(crate) fn warm_allocator_regions() {
    for size in [64usize, 4 * 1024, 64 * 1024, 1024 * 1024, 16 * 1024 * 1024] {
        let mut region = vec![0u8; size];
        region[0] = 1;
        region[size - 1] = 1;
    }
}

/// The process's current address-space footprint. On Darwin the shared cache
/// is mapped into every task, so the AS limit must be incremental over the
/// kernel's own accounting — `proc_taskinfo.pti_virtual_size` is the same
/// value the retired Python worker read via `task_info(TASK_BASIC_INFO)`.
/// On Linux the incremental component is zero — the budget is absolute.
#[cfg(target_os = "macos")]
fn current_virtual_size_bytes() -> Option<u64> {
    use libproc::proc_pid::pidinfo;
    use libproc::task_info::TaskInfo;

    let info = pidinfo::<TaskInfo>(std::process::id() as i32, 0).ok()?;
    (info.pti_virtual_size > 0).then_some(info.pti_virtual_size)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn current_virtual_size_bytes() -> Option<u64> {
    Some(0)
}

/// Linux deny-list: network creation, process creation/exec, io_uring, and
/// filesystem-mutation syscalls return EPERM. The inspection code never uses
/// them, so the list is a kernel enforcement of the worker's documented
/// behavior — matching the retired Python audit hook's deny set.
#[cfg(target_os = "linux")]
fn apply_seccomp_deny_list() -> Result<(), ()> {
    use seccompiler::{
        apply_filter, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
        TargetArch,
    };
    use std::collections::BTreeMap;

    fn deny(syscall: i64) -> (i64, Vec<SeccompRule>) {
        (syscall, Vec::new())
    }
    fn deny_flagged(syscall: i64, arg_index: u8, flag: u64) -> (i64, Vec<SeccompRule>) {
        let condition = SeccompCondition::new(
            arg_index,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(flag),
            flag,
        )
        .expect("static seccomp condition");
        (
            syscall,
            vec![SeccompRule::new(vec![condition]).expect("non-empty rule")],
        )
    }

    // ARM64 uses Linux's asm-generic syscall table. musl's libc bindings omit
    // this constant, but the syscall must remain in the containment deny list.
    // include/uapi/asm-generic/unistd.h defines __NR_kexec_file_load as 294.
    #[cfg(target_arch = "aarch64")]
    const KEXEC_FILE_LOAD: libc::c_long = 294;
    #[cfg(not(target_arch = "aarch64"))]
    const KEXEC_FILE_LOAD: libc::c_long = libc::SYS_kexec_file_load;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for syscall in [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_kexec_load,
        KEXEC_FILE_LOAD,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_mknodat,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_fallocate,
        libc::SYS_utimensat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        // openat2 flags live in a user-space struct the filter cannot
        // inspect, and open_by_handle_at bypasses the path walk; both must
        // be denied unconditionally to keep the write denial complete.
        libc::SYS_openat2,
        libc::SYS_open_by_handle_at,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fsconfig,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
    ] {
        rules.insert(syscall, deny(syscall).1);
    }
    // Legacy single-argument syscalls absent on aarch64/riscv64 (the *at
    // variants above already cover their semantics there).
    #[cfg(target_arch = "x86_64")]
    for syscall in [
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_creat,
        libc::SYS_mkdir,
        libc::SYS_rmdir,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_link,
        libc::SYS_symlink,
        libc::SYS_mknod,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ] {
        rules.insert(syscall, deny(syscall).1);
    }
    // Open-with-write family: any access-mode or destructive flag bit set.
    // open() carries flags in arg1, openat(dirfd, path, flags, mode) in arg2;
    // libc/glibc issue openat exclusively, so the arg2 rule is the one that
    // actually gates writes.
    for flag in [
        libc::O_WRONLY as u64,
        libc::O_RDWR as u64,
        libc::O_CREAT as u64,
        libc::O_TRUNC as u64,
        libc::O_APPEND as u64,
        libc::O_TMPFILE as u64,
    ] {
        #[cfg(target_arch = "x86_64")]
        rules
            .entry(libc::SYS_open)
            .or_default()
            .extend(deny_flagged(libc::SYS_open, 1, flag).1);
        rules
            .entry(libc::SYS_openat)
            .or_default()
            .extend(deny_flagged(libc::SYS_openat, 2, flag).1);
    }
    let filter = SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::Allow,
        seccompiler::SeccompAction::Errno(libc::EPERM as u32),
        // Unknown architectures must not silently receive x86_64's filter;
        // seccompiler kills the process on arch mismatch, so fail closed.
        TargetArch::try_from(std::env::consts::ARCH).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let program: seccompiler::BpfProgram = filter.try_into().map_err(|_| ())?;
    apply_filter(&program).map_err(|_| ())
}
