use crate::ResourceLimits;
use std::io;
#[cfg(target_os = "linux")]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type Resource = libc::c_int;

pub(crate) struct Limit {
    kind: Resource,
    value: libc::rlimit,
    enabled: bool,
}
pub(crate) type Limits = [Limit; 6];

pub(crate) fn process_ceiling(additional: u64) -> io::Result<u64> {
    // An inherited unlimited allowance stays unlimited; adding a live process
    // count would overflow and scanning the host cannot change this result.
    if additional == libc::RLIM_INFINITY {
        return Ok(libc::RLIM_INFINITY);
    }
    #[cfg(target_os = "linux")]
    let count = {
        use std::os::unix::fs::MetadataExt;
        let uid = unsafe { libc::getuid() };
        let mut count = 0u64;
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            if !entry
                .file_name()
                .as_encoded_bytes()
                .iter()
                .all(u8::is_ascii_digit)
            {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.uid() != uid {
                continue;
            }
            let tasks = match std::fs::read_dir(entry.path().join("task")) {
                Ok(tasks) => tasks,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            for task in tasks {
                let task = task?;
                if task
                    .file_name()
                    .as_encoded_bytes()
                    .iter()
                    .all(u8::is_ascii_digit)
                {
                    count += 1;
                }
                if count > 1_048_576 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "process count budget exceeded",
                    ));
                }
            }
        }
        if count == 0 {
            return Err(crate::bound_fs::changed());
        }
        count
    };
    #[cfg(target_os = "macos")]
    let count = {
        #[link(name = "proc")]
        unsafe extern "C" {
            fn proc_listpids(kind: u32, uid: u32, buffer: *mut libc::c_void, bytes: i32) -> i32;
        }
        let uid = unsafe { libc::getuid() };
        let bytes = unsafe { proc_listpids(5, uid, std::ptr::null_mut(), 0) };
        if bytes <= 0 || bytes > 4 * 1_048_576 {
            return Err(crate::bound_fs::changed());
        }
        let mut pids = vec![0i32; bytes as usize / std::mem::size_of::<i32>() + 64];
        let read = unsafe {
            proc_listpids(
                5,
                uid,
                pids.as_mut_ptr().cast(),
                (pids.len() * std::mem::size_of::<i32>()) as i32,
            )
        };
        if read <= 0 || read as usize >= pids.len() * std::mem::size_of::<i32>() {
            return Err(crate::bound_fs::changed());
        }
        pids[..read as usize / std::mem::size_of::<i32>()]
            .iter()
            .filter(|pid| **pid > 0)
            .count() as u64
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let count = return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native process counting unavailable",
    ));
    count
        .checked_add(additional)
        .ok_or_else(crate::bound_fs::changed)
}

pub(crate) fn prepare(
    resources: ResourceLimits,
    node: bool,
    absolute_processes: bool,
) -> io::Result<Limits> {
    let processes = if absolute_processes {
        resources.processes
    } else {
        process_ceiling(resources.processes)?
    };
    #[cfg(target_os = "linux")]
    let address_space = if node {
        16 * 1024 * 1024 * 1024
    } else {
        resources.memory_bytes
    };
    #[cfg(not(target_os = "linux"))]
    let address_space = resources.memory_bytes;
    let values = [
        (libc::RLIMIT_CPU, resources.cpu_seconds),
        (libc::RLIMIT_AS, address_space),
        (libc::RLIMIT_FSIZE, resources.file_bytes),
        (libc::RLIMIT_NOFILE, resources.open_files),
        (libc::RLIMIT_NPROC, processes),
        (libc::RLIMIT_DATA, resources.memory_bytes),
    ];
    let mut limits = values.map(|(kind, value)| Limit {
        kind,
        value: libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        },
        enabled: true,
    });
    limits[5].enabled = cfg!(target_os = "linux") && node;
    for limit in &mut limits {
        if !limit.enabled {
            continue;
        }
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(limit.kind, &mut current) } != 0 {
            return Err(io::Error::last_os_error());
        }
        limit.value.rlim_max = limit.value.rlim_max.min(current.rlim_max);
        limit.value.rlim_cur = limit
            .value
            .rlim_cur
            .min(current.rlim_cur)
            .min(limit.value.rlim_max);
    }
    Ok(limits)
}
/// No allocations, locks or formatting after fork.
pub(crate) unsafe fn apply(limits: &Limits) -> bool {
    for limit in limits {
        if !limit.enabled {
            continue;
        }
        if unsafe { libc::setrlimit(limit.kind, &limit.value) } != 0 {
            return false;
        }
        let mut actual = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(limit.kind, &mut actual) } != 0
            || actual.rlim_cur > limit.value.rlim_cur
            || actual.rlim_max > limit.value.rlim_max
        {
            return false;
        }
    }
    true
}
