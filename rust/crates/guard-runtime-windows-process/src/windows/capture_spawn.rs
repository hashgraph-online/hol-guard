use super::*;
use std::ffi::OsString;
use std::mem::size_of_val;

struct AttributeList(Vec<usize>);
impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast());
        }
    }
}

fn bind_launch_directory(path: &Path) -> io::Result<PrivateDirectoryBinding> {
    bind_readonly_directory(path)
}

/// Borrowed launch inputs; capture owns the process and pipe lifetime.
pub struct CaptureCommand<'a> {
    pub executable: &'a Path,
    pub args: &'a [&'a OsStr],
    pub cwd: &'a Path,
    pub environment: &'a [(OsString, OsString)],
}

pub fn capture(
    command: CaptureCommand<'_>,
    input: &[u8],
    limit: usize,
    deadline: Instant,
    cancellation: &AtomicBool,
) -> io::Result<CapturedOutput> {
    let CaptureCommand {
        executable,
        args,
        cwd,
        environment: env,
    } = command;
    if cancellation.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "launch cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "launch deadline"));
    }
    let executable_parent = executable.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "executable parent unavailable")
    })?;
    let _executable_parent = bind_launch_directory(executable_parent)?;
    let _executable = open_bound_executable_file(executable)?;
    let _cwd = bind_launch_directory(cwd)?;
    let mut line = command_line(executable.as_os_str(), args)?;
    let executable = wide_path(executable)?;
    let cwd = wide_path(cwd)?;
    let mut environment = Vec::new();
    let mut sorted: Vec<_> = env
        .iter()
        .map(|(key, value)| (key.to_string_lossy().to_uppercase(), key, value))
        .collect();
    sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut previous = None;
    for (folded, key, value) in sorted {
        if previous.as_ref() == Some(&folded) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplicate environment name",
            ));
        }
        previous = Some(folded);
        let key_start = environment.len();
        environment.extend(key.encode_wide());
        if environment[key_start..].is_empty()
            || environment[key_start..].contains(&0)
            || environment[key_start..].contains(&(b'=' as u16))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid environment name",
            ));
        }
        environment.push(b'=' as u16);
        let value_start = environment.len();
        environment.extend(value.encode_wide());
        if environment[value_start..].contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid environment value",
            ));
        }
        environment.push(0);
    }
    environment.push(0);
    if environment.len() == 1 {
        environment.push(0);
    }
    let pipes = capture_pipes()?;
    let mut inherited = [
        pipes.child_stdin.as_raw_handle() as HANDLE,
        pipes.child_stdout.as_raw_handle() as HANDLE,
        pipes.child_stderr.as_raw_handle() as HANDLE,
    ];
    let mut size: SIZE_T = 0;
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
    }
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut storage = vec![0_usize; size.div_ceil(size_of::<usize>())];
    let list = storage.as_mut_ptr().cast();
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = AttributeList(storage);
    let list = attributes.0.as_mut_ptr().cast();
    if unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited.as_mut_ptr().cast(),
            size_of_val(&inherited),
            null_mut(),
            null_mut(),
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    let mut startup = unsafe { zeroed::<STARTUPINFOEXW>() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as DWORD;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited[0];
    startup.StartupInfo.hStdOutput = inherited[1];
    startup.StartupInfo.hStdError = inherited[2];
    startup.lpAttributeList = list;
    let mut information = unsafe { zeroed::<PROCESS_INFORMATION>() };
    if cancellation.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "launch cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "launch deadline"));
    }
    if unsafe {
        CreateProcessW(
            executable.as_ptr(),
            line.as_mut_ptr(),
            null_mut(),
            null_mut(),
            TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            environment.as_mut_ptr().cast(),
            cwd.as_ptr(),
            &mut startup.StartupInfo,
            &mut information,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess as RawHandle) };
    let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread as RawHandle) };
    let child = attach_suspended_process(process, thread, None, deadline, cancellation)?;
    capture_owned_child(child, pipes, input, limit, false, deadline, cancellation)
}
