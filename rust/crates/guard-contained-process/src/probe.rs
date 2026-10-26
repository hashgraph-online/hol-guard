use serde_json::{json, Value};
use std::ffi::OsString;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

pub const MODE: &str = "--guard-contained-probe";
pub const COPY_MODE: &str = "--guard-contained-copy";
pub const ENTRY_MODE: &str = "--guard-contained-entry";

#[cfg(target_os = "macos")]
const GROUP_MODE: &str = "--guard-contained-group-check";
/// Routed before the resident daemon accepts requests. Only the isolated native
/// process interprets these private paths; they are never returned publicly.
pub fn main(arguments: &[OsString]) -> Option<i32> {
    #[cfg(target_os = "macos")]
    if arguments.first().is_some_and(|arg| arg == GROUP_MODE) {
        return Some(if arguments.len() == 2 && arguments[1].to_str().and_then(|value| value.parse::<libc::pid_t>().ok()).is_some_and(|group| unsafe { libc::getpgrp() } == group && unsafe { libc::getsid(0) } == group) { 0 } else { 1 });
    }
    if arguments.first().is_some_and(|arg| arg == ENTRY_MODE) {
        return Some(match entry(arguments) {
            Ok(()) => 0,
            Err(_) => 126,
        });
    }
    if arguments.first().is_some_and(|arg| arg == COPY_MODE) {
        return Some(match copy(arguments) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("Guard contained copy failed: {}", error.kind());
                1
            }
        });
    }
    if arguments.first().is_none_or(|arg| arg != MODE) {
        return None;
    }
    Some(match run(arguments) {
        Ok(report) => {
            let mut stdout = io::stdout().lock();
            if serde_json::to_writer(&mut stdout, &report).is_err()
                || stdout.write_all(b"\n").is_err()
            {
                126
            } else {
                0
            }
        }
        Err(_) => 126,
    })
}
fn copy(arguments: &[OsString]) -> io::Result<()> {
    if arguments.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native copy",
        ));
    }
    let source = Path::new(&arguments[1]);
    let target = Path::new(&arguments[2]);
    crate::bound_fs::relative_components(source)?;
    crate::bound_fs::relative_components(target)?;
    let cwd = crate::bound_fs::Directory::open(&std::env::current_dir()?.canonicalize()?)?;
    let input = cwd.read(source, 16 * 1024 * 1024)?;
    match cwd.read(target, 16 * 1024 * 1024) {
        Ok(old) => cwd.write_existing(target, (&old.identity, &old.digest), &input.bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            cwd.create(target, &input.bytes, false)
        }
        Err(error) => Err(error),
    }
}
fn run(arguments: &[OsString]) -> io::Result<Value> {
    if arguments.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native probe",
        ));
    }
    let payload: Value = serde_json::from_slice(arguments[1].to_string_lossy().as_bytes())
        .map_err(io::Error::other)?;
    let path = |name: &str| {
        payload
            .get(name)
            .and_then(Value::as_str)
            .map(Path::new)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid native probe path"))
    };
    let socket: SocketAddr = payload
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(crate::bound_fs::changed)?
        .parse()
        .map_err(io::Error::other)?;
    let expected = payload
        .get("sentinel")
        .and_then(Value::as_str)
        .ok_or_else(crate::bound_fs::changed)?;
    let allowed_read =
        std::fs::read(path("allowed_read")?).is_ok_and(|bytes| bytes == expected.as_bytes());
    let allowed_write = std::fs::write(path("allowed_write")?, b"guard-native-probe").is_ok();
    let denied = |error: io::Error| -> io::Result<bool> {
        if error.kind() == io::ErrorKind::PermissionDenied
            || (cfg!(target_os = "linux") && error.kind() == io::ErrorKind::NotFound)
        {
            Ok(true)
        } else {
            Err(error)
        }
    };
    let file_denied = match std::fs::File::open(path("external_read")?) {
        Ok(_) => false,
        Err(error) => denied(error)?,
    };
    let directory_identity = payload["external_directory_identity"]
        .as_str()
        .ok_or_else(crate::bound_fs::changed)?;
    let directory_denied = match crate::bound_fs::Directory::open(path("external_directory")?) {
        Ok(directory) => crate::bound_fs::object_token(directory.handle())? != directory_identity,
        Err(error) => denied(error)?,
    };
    let live_workspace_reads_denied = file_denied && directory_denied;
    let external_writes_denied = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path("external_write")?)
    {
        Ok(_) => false,
        Err(error) => denied(error)?,
    };
    let network_denied = match TcpStream::connect_timeout(&socket, Duration::from_millis(250)) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => true,
        #[cfg(target_os = "linux")]
        Err(error)
            if error.raw_os_error().is_some_and(|code| {
                [libc::ECONNREFUSED, libc::ENETUNREACH, libc::EHOSTUNREACH].contains(&code)
            }) =>
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata("/proc/self/ns/net")?.ino()
                != payload["parent_network_namespace"]
                    .as_u64()
                    .ok_or_else(crate::bound_fs::changed)?
        }
        Err(error) => return Err(error),
    };
    #[cfg(target_os = "macos")]
    let process_group_contained = process_group_probe()?;
    #[cfg(target_os = "linux")]
    let process_group_contained = {
        use std::os::unix::fs::MetadataExt;
        let parent = payload["parent_pid_namespace"]
            .as_u64()
            .ok_or_else(crate::bound_fs::changed)?;
        std::fs::metadata("/proc/self/ns/pid")?.ino() != parent && unsafe { libc::getpid() } > 1
    };
    #[cfg(windows)]
    let process_group_contained = crate::windows::job_containment_probe()?;
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    let process_group_contained = false;
    Ok(
        json!({"allowed_read":allowed_read,"allowed_write":allowed_write,"live_workspace_reads_denied":live_workspace_reads_denied,"external_writes_denied":external_writes_denied,"network_denied":network_denied,"process_group_contained":process_group_contained}),
    )
}
#[cfg(target_os = "macos")]
fn process_group_probe() -> io::Result<bool> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        let group = unsafe { libc::getpgrp() };
        let group_result = unsafe { libc::setpgid(0, 0) };
        let group_error = unsafe { *libc::__error() };
        let session_result = unsafe { libc::setsid() };
        let session_error = unsafe { *libc::__error() };
        let denied = group_result == -1
            && group_error == libc::EPERM
            && session_result == -1
            && session_error == libc::EPERM
            && unsafe { libc::getpgrp() } == group;
        unsafe {
            libc::_exit(if denied { 0 } else { 1 });
        }
    }
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            break;
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(libc::WIFEXITED(status)
        && libc::WEXITSTATUS(status) == 0
        && spawn_group_probe(false)?
        && spawn_group_probe(true)?)
}

#[cfg(target_os = "macos")]
fn spawn_group_probe(detached: bool) -> io::Result<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let executable = CString::new(std::env::current_exe()?.as_os_str().as_bytes())
        .map_err(|_| crate::bound_fs::changed())?;
    let mode = CString::new(GROUP_MODE).map_err(|_| crate::bound_fs::changed())?;
    let group = CString::new(unsafe { libc::getpgrp() }.to_string())
        .map_err(|_| crate::bound_fs::changed())?;
    let argv = [
        executable.as_ptr() as *mut _,
        mode.as_ptr() as *mut _,
        group.as_ptr() as *mut _,
        std::ptr::null_mut(),
    ];
    let env = std::env::vars_os()
        .map(|(key, value)| {
            let mut bytes = key.as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            CString::new(bytes).map_err(|_| crate::bound_fs::changed())
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut env_ptr: Vec<_> = env.iter().map(|value| value.as_ptr() as *mut _).collect();
    env_ptr.push(std::ptr::null_mut());
    let mut attributes = unsafe { std::mem::zeroed() };
    let initialized = unsafe { libc::posix_spawnattr_init(&mut attributes) };
    if initialized != 0 {
        return Err(io::Error::from_raw_os_error(initialized));
    }
    let setup = if detached {
        let flags = unsafe {
            libc::posix_spawnattr_setflags(
                &mut attributes,
                libc::POSIX_SPAWN_SETPGROUP as libc::c_short,
            )
        };
        if flags == 0 {
            unsafe { libc::posix_spawnattr_setpgroup(&mut attributes, 0) }
        } else {
            flags
        }
    } else {
        0
    };
    let mut pid = 0;
    let launched = if setup == 0 {
        unsafe {
            libc::posix_spawn(
                &mut pid,
                executable.as_ptr(),
                std::ptr::null(),
                &attributes,
                argv.as_ptr(),
                env_ptr.as_ptr(),
            )
        }
    } else {
        setup
    };
    let destroyed = unsafe { libc::posix_spawnattr_destroy(&mut attributes) };
    if destroyed != 0 {
        return Err(io::Error::from_raw_os_error(destroyed));
    }
    if detached && [libc::EPERM, libc::EACCES].contains(&launched) {
        return Ok(true);
    }
    if launched != 0 {
        return Err(io::Error::from_raw_os_error(launched));
    }
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            break;
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
}

#[cfg(target_os = "linux")]
fn entry(arguments: &[OsString]) -> io::Result<()> {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    if arguments.len() != 3 {
        return Err(crate::bound_fs::changed());
    }
    let mut manifest = crate::bound_fs::open_regular(Path::new(&arguments[1]))?;
    let body = crate::bound_fs::read_file(&mut manifest, 16 * 1024 * 1024)?;
    if body.digest != arguments[2].to_string_lossy() {
        return Err(crate::bound_fs::changed());
    }
    let payload: Value = serde_json::from_slice(&body.bytes).map_err(io::Error::other)?;
    let directories = payload["directories"]
        .as_array()
        .ok_or_else(crate::bound_fs::changed)?;
    let files = payload["files"]
        .as_array()
        .ok_or_else(crate::bound_fs::changed)?;
    if directories.len() > 100_000 || files.len() > 50_000 {
        return Err(crate::bound_fs::changed());
    }
    let mut seen = BTreeSet::new();
    for row in directories {
        let path = row["path"].as_str().ok_or_else(crate::bound_fs::changed)?;
        if !seen.insert(path) {
            return Err(crate::bound_fs::changed());
        }
        let directory = crate::bound_fs::Directory::open(Path::new(path))?;
        let metadata = directory.handle().metadata()?;
        if row.get("device").is_some()
            && (row["device"].as_u64() != Some(metadata.dev())
                || row["inode"].as_u64() != Some(metadata.ino()))
        {
            return Err(crate::bound_fs::changed());
        }
        let expected = row["entries"]
            .as_array()
            .ok_or_else(crate::bound_fs::changed)?
            .iter()
            .map(|name| {
                name.as_str()
                    .map(OsString::from)
                    .ok_or_else(crate::bound_fs::changed)
            })
            .collect::<io::Result<Vec<_>>>()?;
        if directory.entries(Path::new("."), 100_000)? != expected {
            return Err(crate::bound_fs::changed());
        }
    }
    let executable = payload["executable"]
        .as_str()
        .ok_or_else(crate::bound_fs::changed)?;
    let mut image = None;
    for row in files {
        let path = row["path"].as_str().ok_or_else(crate::bound_fs::changed)?;
        if !seen.insert(path) {
            return Err(crate::bound_fs::changed());
        }
        let mut file = crate::bound_fs::open_executable(Path::new(path))?;
        let metadata = file.metadata()?;
        if row.get("device").is_some()
            && (row["device"].as_u64() != Some(metadata.dev())
                || row["inode"].as_u64() != Some(metadata.ino()))
        {
            return Err(crate::bound_fs::changed());
        }
        if Some(crate::bound_fs::digest_executable(&mut file, 256 * 1024 * 1024)?.as_str())
            != row["digest"].as_str()
        {
            return Err(crate::bound_fs::changed());
        }
        if path == executable {
            image = Some(file);
        }
    }
    let image = image.ok_or_else(crate::bound_fs::changed)?;
    let cstring = |bytes: &[u8]| CString::new(bytes).map_err(|_| crate::bound_fs::changed());
    let argv = std::iter::once(Ok(executable))
        .chain(
            payload["argv"]
                .as_array()
                .ok_or_else(crate::bound_fs::changed)?
                .iter()
                .map(|value| value.as_str().ok_or_else(crate::bound_fs::changed)),
        )
        .map(|value| value.and_then(|value| cstring(value.as_bytes())))
        .collect::<io::Result<Vec<_>>>()?;
    let mut argv_ptr: Vec<_> = argv.iter().map(|value| value.as_ptr()).collect();
    argv_ptr.push(std::ptr::null());
    let env = std::env::vars_os()
        .map(|(key, value)| {
            let mut bytes = key.as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            cstring(&bytes)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut env_ptr: Vec<_> = env.iter().map(|value| value.as_ptr()).collect();
    env_ptr.push(std::ptr::null());
    if !payload["resources"].is_null() {
        let row = &payload["resources"];
        let resources = crate::ResourceLimits {
            cpu_seconds: row["cpu_seconds"]
                .as_u64()
                .ok_or_else(crate::bound_fs::changed)?,
            memory_bytes: row["memory_bytes"]
                .as_u64()
                .ok_or_else(crate::bound_fs::changed)?,
            file_bytes: row["file_bytes"]
                .as_u64()
                .ok_or_else(crate::bound_fs::changed)?,
            open_files: row["open_files"]
                .as_u64()
                .ok_or_else(crate::bound_fs::changed)?,
            processes: row["processes"]
                .as_u64()
                .ok_or_else(crate::bound_fs::changed)?,
        };
        let limits = crate::unix::resources::prepare(
            resources,
            payload["node_virtual_address_space"].as_bool() == Some(true),
            true,
        )?;
        if !unsafe { crate::unix::resources::apply(&limits) } {
            return Err(io::Error::last_os_error());
        }
    }
    // execveat consumes the same opened, verified namespace image. Its real
    // captured pathname stays visible to Python prefix discovery and Node's
    // process.execPath; no second pathname lookup selects the foreign image.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            image.as_raw_fd(),
            c"".as_ptr(),
            argv_ptr.as_ptr(),
            env_ptr.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    Err(io::Error::last_os_error())
}
#[cfg(not(target_os = "linux"))]
fn entry(_arguments: &[OsString]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native namespace entry unavailable",
    ))
}
