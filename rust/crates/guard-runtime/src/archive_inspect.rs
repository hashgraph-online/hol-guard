//! `archive-inspect --stdin`: bounded offline archive inspection.
//!
//! Reads one `ArchiveInspectionRequestV1` from stdin, applies the process
//! containment Python used to establish in a child interpreter (resource
//! limits, platform sandbox verification, no network/process capability),
//! then hands the digest-bound blob to `guard_archive`. Every inspection
//! outcome is a typed result on stdout with exit code 0; transport-level
//! failures exit nonzero so the caller fails closed.

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

use guard_archive::{ArchiveCaps, ArchiveOutcome, ArchiveStatus};
use guard_contracts::{
    ArchiveInspectionCountersV1, ArchiveInspectionRequestV1, ArchiveInspectionResultV1,
    ARCHIVE_CAP_ARCHIVE_BYTES, ARCHIVE_CAP_DECOMPRESSION_RATIO, ARCHIVE_CAP_EXPANDED_BYTES,
    ARCHIVE_CAP_FILES, ARCHIVE_CAP_MEMBER_BYTES, ARCHIVE_CAP_MEMORY_BYTES,
    ARCHIVE_CAP_NESTED_ARCHIVES, ARCHIVE_CAP_PACKAGE_JSON_BYTES, ARCHIVE_CAP_PATH_DEPTH,
    ARCHIVE_CAP_TIMEOUT_MS, ARCHIVE_INSPECTION_REQUEST_SCHEMA, ARCHIVE_INSPECTION_RESULT_SCHEMA,
};
use sha2::{Digest, Sha256};

const MAX_ARCHIVE_PATH_BYTES: usize = 16 * 1024;

pub(crate) fn evaluate_archive_inspection_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let value = crate::strict_json_value(bytes)?;
    let request: ArchiveInspectionRequestV1 = serde_json::from_value(value)
        .map_err(|_| "archive_inspection_request_invalid".to_owned())?;
    let request_sha256 = hex::encode(Sha256::digest(bytes));
    let outcome = match validated_caps(&request) {
        Some(caps) => run_inspection(&request, caps),
        None => ArchiveOutcome::incomplete(
            "external_archive_inspection_policy_invalid",
            "External archive inspection policy is invalid.",
            None,
        ),
    };
    let result = ArchiveInspectionResultV1 {
        schema: ARCHIVE_INSPECTION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: match outcome.status {
            ArchiveStatus::Clean => "clean",
            ArchiveStatus::Blocked => "blocked",
            ArchiveStatus::Incomplete | ArchiveStatus::Halted => "incomplete",
        }
        .to_owned(),
        code: outcome.code.to_owned(),
        message: outcome.message.to_owned(),
        severity: outcome.severity.to_owned(),
        sha256: outcome.sha256,
        counters: ArchiveInspectionCountersV1 {
            members: outcome.members_seen,
            expanded_bytes: outcome.expanded_bytes,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
    };
    serde_json::to_vec(&result).map_err(|_| "archive_inspection_encode_failed".to_owned())
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validated_caps(request: &ArchiveInspectionRequestV1) -> Option<ArchiveCaps> {
    let caps = &request.caps;
    let valid = request.schema == ARCHIVE_INSPECTION_REQUEST_SCHEMA
        && is_lower_hex(&request.request_id, 32)
        && !request.archive_path.is_empty()
        && request.archive_path.len() <= MAX_ARCHIVE_PATH_BYTES
        && is_lower_hex(&request.expected_sha256, 64)
        && request.timeout_ms > 0
        && request.timeout_ms <= ARCHIVE_CAP_TIMEOUT_MS
        && caps.max_archive_bytes > 0
        && caps.max_archive_bytes <= ARCHIVE_CAP_ARCHIVE_BYTES
        && caps.max_files > 0
        && caps.max_files <= ARCHIVE_CAP_FILES
        && caps.max_expanded_bytes > 0
        && caps.max_expanded_bytes <= ARCHIVE_CAP_EXPANDED_BYTES
        && caps.max_member_bytes > 0
        && caps.max_member_bytes <= ARCHIVE_CAP_MEMBER_BYTES
        && caps.max_package_json_bytes > 0
        && caps.max_package_json_bytes <= ARCHIVE_CAP_PACKAGE_JSON_BYTES
        && caps.max_memory_bytes > 0
        && caps.max_memory_bytes <= ARCHIVE_CAP_MEMORY_BYTES
        && caps.max_decompression_ratio.is_finite()
        && caps.max_decompression_ratio > 0.0
        && caps.max_decompression_ratio <= ARCHIVE_CAP_DECOMPRESSION_RATIO
        && caps.max_nested_archives <= ARCHIVE_CAP_NESTED_ARCHIVES
        && caps.max_path_depth > 0
        && caps.max_path_depth <= ARCHIVE_CAP_PATH_DEPTH;
    if !valid {
        return None;
    }
    Some(ArchiveCaps {
        max_archive_bytes: caps.max_archive_bytes,
        max_files: caps.max_files,
        max_expanded_bytes: caps.max_expanded_bytes,
        max_member_bytes: caps.max_member_bytes,
        max_package_json_bytes: caps.max_package_json_bytes,
        max_decompression_ratio: caps.max_decompression_ratio,
        max_nested_archives: caps.max_nested_archives,
        max_path_depth: caps.max_path_depth,
    })
}

fn sandbox_unavailable() -> ArchiveOutcome {
    ArchiveOutcome::incomplete(
        "external_archive_sandbox_unavailable",
        "External archive resource sandbox is unavailable on this platform.",
        None,
    )
}

#[cfg(not(unix))]
fn run_inspection(_request: &ArchiveInspectionRequestV1, _caps: ArchiveCaps) -> ArchiveOutcome {
    sandbox_unavailable()
}

#[cfg(unix)]
fn run_inspection(request: &ArchiveInspectionRequestV1, caps: ArchiveCaps) -> ArchiveOutcome {
    if !apply_child_limits(request.timeout_ms, request.caps.max_memory_bytes) {
        return sandbox_unavailable();
    }
    if !apply_capability_deny() {
        return sandbox_unavailable();
    }
    if !network_capability_denied() {
        return sandbox_unavailable();
    }
    let deadline = Instant::now() + Duration::from_millis(request.timeout_ms);
    // If the spawning parent disappears the inspection is orphaned: stop
    // rather than burn the budget unattributed.
    let original_parent = nix::unistd::getppid();
    let halt = move || nix::unistd::getppid() != original_parent;
    guard_archive::inspect_path(
        Path::new(&request.archive_path),
        &request.expected_sha256,
        &caps,
        deadline,
        &halt,
    )
}

/// `_child_limits` port: CPU, file-descriptor, and address-space bounds that
/// must all be established before parsing untrusted bytes. Returns false when
/// any required limit cannot be applied — the caller fails closed.
#[cfg(unix)]
fn apply_child_limits(timeout_ms: u64, max_memory_bytes: u64) -> bool {
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
    let memory_limit = current_virtual.saturating_add(max_memory_bytes);
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

/// The process's current address-space footprint. On Darwin the shared cache
/// is mapped into every task, so the AS limit must be incremental over the
/// current mapping (mirroring `_darwin_virtual_size_bytes`). On Linux the
/// incremental component is zero — the budget is absolute.
#[cfg(target_os = "macos")]
fn current_virtual_size_bytes() -> Option<u64> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

    let pid = Pid::from_u32(std::process::id());
    let mut system = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing().with_memory()),
    );
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system
        .process(pid)
        .map(|process| process.virtual_memory())
        .filter(|size| *size > 0)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn current_virtual_size_bytes() -> Option<u64> {
    Some(0)
}

/// Capability denial: on Linux a seccomp deny-list removes the socket and
/// process families outright; on macOS the caller wraps this binary in
/// `sandbox-exec` and the probe below verifies the denial landed. Other Unix
/// targets have no containment layer to verify, so inspection is unavailable.
#[cfg(unix)]
fn apply_capability_deny() -> bool {
    #[cfg(target_os = "linux")]
    {
        apply_seccomp_deny_list().is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        // The sandbox-exec wrapper established by the caller carries the
        // denial; the probe verifies it. No in-process mechanism exists.
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Probe that outbound network is actually denied before parsing untrusted
/// bytes. Under seccomp the socket call itself fails; under seatbelt the
/// socket is created but connect is denied. Anything else means the worker
/// has unmediated network and must refuse to inspect.
#[cfg(unix)]
fn network_capability_denied() -> bool {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, SockaddrIn};
    use std::os::fd::AsRawFd;

    let descriptor = match socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    ) {
        Ok(descriptor) => descriptor,
        Err(_) => return true,
    };
    let loopback = SockaddrIn::new(127, 0, 0, 1, 9);
    matches!(
        connect(descriptor.as_raw_fd(), &loopback),
        Err(nix::errno::Errno::EPERM) | Err(nix::errno::Errno::EACCES)
    )
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
        libc::SYS_kexec_file_load,
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
