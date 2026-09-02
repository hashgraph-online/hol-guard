from __future__ import annotations

from pathlib import Path


def replace(path: str, old: str, new: str, *, expected: int = 1) -> None:
    file = Path(path)
    content = file.read_text(encoding="utf-8")
    count = content.count(old)
    if count != expected:
        raise RuntimeError(f"{path}: expected {expected} guarded match(es), found {count}")
    file.write_text(content.replace(old, new, expected), encoding="utf-8")


private_files = "rust/crates/guard-runtime-windows-process/src/private_files.rs"
replace(
    private_files,
    """use winapi::um::winnt::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, WRITE_DAC,
};
""",
    """use winapi::um::winnt::{
    DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GENERIC_READ, GENERIC_WRITE, WRITE_DAC,
};
""",
)
replace(
    private_files,
    """pub(super) fn open_directory_bound(
    path: &Path,
    allow_acl_repair: bool,
) -> io::Result<std::fs::File> {
    let file = open_raw_directory_bound(path, allow_acl_repair)?;
    validate_handle(&file, true)?;
    Ok(file)
}

/// Open a directory with delete sharing withheld so its checked ancestry
/// cannot be renamed or removed while the binding remains alive.
pub(super) fn open_raw_directory_bound(
    path: &Path,
    allow_acl_repair: bool,
) -> io::Result<std::fs::File> {
    let access = GENERIC_READ
        | if allow_acl_repair {
            GENERIC_WRITE | WRITE_DAC | DELETE
        } else {
            0
        };
    open_raw_with_access(path, true, FILE_SHARE_READ | FILE_SHARE_WRITE, access)
}
""",
    """pub(super) fn open_directory_bound(
    path: &Path,
    allow_acl_repair: bool,
    allow_add_file: bool,
) -> io::Result<std::fs::File> {
    let file = open_raw_directory_bound(path, allow_acl_repair, allow_add_file, false)?;
    validate_handle(&file, true)?;
    Ok(file)
}

/// Open a directory with delete sharing withheld so its checked ancestry
/// cannot be renamed or removed while the binding remains alive. Existing
/// bindings never request DELETE themselves, allowing independent readers to
/// hold the same rename barrier without a Windows sharing violation.
pub(super) fn open_raw_directory_bound(
    path: &Path,
    allow_acl_repair: bool,
    allow_add_file: bool,
    allow_delete: bool,
) -> io::Result<std::fs::File> {
    let mut access = GENERIC_READ;
    if allow_acl_repair {
        access |= WRITE_DAC;
    }
    if allow_add_file {
        access |= FILE_ADD_FILE;
    }
    if allow_delete {
        access |= DELETE;
    }
    open_raw_with_access(path, true, FILE_SHARE_READ | FILE_SHARE_WRITE, access)
}
""",
)

directory_binding = "rust/crates/guard-runtime-windows-process/src/directory_binding.rs"
replace(
    directory_binding,
    "match open_directory_bound(&current, is_target || is_private)",
    "match open_directory_bound(&current, is_private, is_target)",
    expected=2,
)
replace(
    directory_binding,
    "let directory = open_raw_directory_bound(path, true)?;",
    "let directory = open_raw_directory_bound(path, true, true, true)?;",
)

containment = "rust/crates/guard-runtime/src/managed_resident_containment.rs"
replace(
    containment,
    """pub(super) fn state_process_identities(states: &[ResidentState]) -> Vec<ManagedProcessIdentity> {
    states
        .iter()
        // The owner is a shared client lease, not a managed resident.  A
        // stop request must never wait for or terminate that requester.
        .map(state_process_identity)
        .collect()
}

pub(super) fn spawn_managed_for_owner(
""",
    """pub(super) fn state_process_identities(states: &[ResidentState]) -> Vec<ManagedProcessIdentity> {
    states
        .iter()
        // The owner is a shared client lease, not a managed resident.  A
        // stop request must never wait for or terminate that requester.
        .map(state_process_identity)
        .collect()
}

pub(super) fn state_owner_is_live(state: &ResidentState) -> bool {
    #[cfg(unix)]
    {
        return validate_runtime_process_identity(
            state.owner_process_id,
            &state.owner_process_start_marker,
            &state.runtime_sha256,
        )
        .is_ok();
    }
    #[cfg(not(unix))]
    {
        let _ = state;
        true
    }
}

pub(super) fn spawn_managed_for_owner(
""",
)

managed_resident = "rust/crates/guard-runtime/src/managed_resident.rs"
replace(
    managed_resident,
    "        if (same_runtime\n",
    "        if !containment::state_owner_is_live(&state)\n            || (same_runtime\n",
)

constants = "src/codex_plugin_scanner/guard/native_policy_snapshot_constants.py"
replace(
    constants,
    """_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
""",
    """_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
""",
)

windows_io = "src/codex_plugin_scanner/guard/native_policy_snapshot_windows_io.py"
replace(
    windows_io,
    """    _WINDOWS_FILE_FLAG_WRITE_THROUGH,
    _WINDOWS_FILE_SHARE_READ,
    _WINDOWS_FILE_SHARE_WRITE,
""",
    """    _WINDOWS_FILE_FLAG_WRITE_THROUGH,
    _WINDOWS_FILE_SHARE_DELETE,
    _WINDOWS_FILE_SHARE_READ,
    _WINDOWS_FILE_SHARE_WRITE,
""",
)
replace(
    windows_io,
    """    directory: bool,
    create_new: bool,
    descriptor: Any | None,
""",
    """    directory: bool,
    create_new: bool,
    share_write: bool,
    share_delete: bool,
    descriptor: Any | None,
""",
)
replace(
    windows_io,
    """        share_mode = _WINDOWS_FILE_SHARE_READ
    if descriptor is not None or repair:
""",
    """        share_mode = _WINDOWS_FILE_SHARE_READ
        if share_write:
            share_mode |= _WINDOWS_FILE_SHARE_WRITE
        if share_delete:
            share_mode |= _WINDOWS_FILE_SHARE_DELETE
    if descriptor is not None or repair:
""",
)
replace(
    windows_io,
    """    directory: bool,
    create_new: bool = False,
    descriptor: Any | None = None,
""",
    """    directory: bool,
    create_new: bool = False,
    share_write: bool = False,
    share_delete: bool = False,
    descriptor: Any | None = None,
""",
)
replace(
    windows_io,
    """        directory=directory,
        create_new=create_new,
        descriptor=descriptor,
""",
    """        directory=directory,
        create_new=create_new,
        share_write=share_write,
        share_delete=share_delete,
        descriptor=descriptor,
""",
)
replace(
    windows_io,
    '    """Open/create one non-reparse Windows object while denying deletion."""\n',
    '    """Open/create one non-reparse Windows object with explicit sharing."""\n',
)
replace(
    windows_io,
    """            kernel32, handle, information = api._windows_open_handle(
                path,
                directory=False,
                create_new=True,
                descriptor=descriptor,
            )
""",
    """            kernel32, handle, information = api._windows_open_handle(
                path,
                directory=False,
                create_new=True,
                share_write=True,
                descriptor=descriptor,
            )
""",
)
replace(
    windows_io,
    """        kernel32, handle, information = api._windows_open_handle(
            path,
            directory=False,
            repair=True,
        )
""",
    """        kernel32, handle, information = api._windows_open_handle(
            path,
            directory=False,
            share_write=True,
            repair=True,
        )
""",
)
replace(
    windows_io,
    "kernel32, handle, _information = api._windows_open_handle(path, directory=False)\n",
    """kernel32, handle, _information = api._windows_open_handle(
        path,
        directory=False,
        share_delete=True,
    )
""",
)

windows_storage = "src/codex_plugin_scanner/guard/native_policy_snapshot_storage_windows.py"
replace(
    windows_storage,
    "kernel32, handle, information = api._windows_open_handle(path, directory=False)",
    """kernel32, handle, information = api._windows_open_handle(
            path,
            directory=False,
            share_delete=True,
        )""",
    expected=2,
)

windows_atomic = "src/codex_plugin_scanner/guard/native_policy_snapshot_windows_atomic.py"
replace(
    windows_atomic,
    """            target_path,
            directory=False,
            repair=True,
""",
    """            target_path,
            directory=False,
            share_delete=True,
            repair=True,
""",
)
replace(
    windows_atomic,
    """            target_path,
            directory=False,
        )
""",
    """            target_path,
            directory=False,
            share_delete=True,
        )
""",
)
