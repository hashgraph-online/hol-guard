//! The process identity facts the daemon lifecycle compares, for
//! `windows-process-lifecycle --stdin`: a process's kernel creation time,
//! the user its token runs as, termination of one exact process generation
//! and the Windows command-line split.

use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::processthreadsapi::{OpenProcessToken, TerminateProcess};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::shellapi::CommandLineToArgvW;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{LocalFree, WAIT_OBJECT_0};
use winapi::um::winnt::{
    TokenUser, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, SYNCHRONIZE, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_permissions::wrappers::ConvertSidToStringSid;
use windows_permissions::Sid;

use super::process_lifecycle::{duration_to_wait_millis, process_creation_filetime};

/// The longest wait for a terminated process to exit.
const TERMINATION_WAIT: Duration = Duration::from_secs(1);
/// More than any `TOKEN_USER` Windows writes: a SID holds at most 68 bytes.
const TOKEN_USER_BUFFER_LIMIT: u32 = 4 * 1024;

/// The kernel creation time that tells one generation of a reused process
/// id from the next, as one `FILETIME` value.
pub fn process_creation_time(process_id: u32) -> Option<u64> {
    let process = super::open_process(process_id, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
    process_creation_filetime(&process).ok()
}

/// `sid:` and the string SID of the user the process's token runs as.
pub fn process_owner_sid(process_id: u32) -> Option<String> {
    let process = super::open_process(process_id, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
    let mut raw_token: HANDLE = null_mut();
    // SAFETY: `process` owns a valid process handle and `raw_token` is
    // writable storage for the token handle.
    if unsafe {
        OpenProcessToken(
            process.as_raw_handle() as HANDLE,
            TOKEN_QUERY,
            &mut raw_token,
        )
    } == FALSE
    {
        return None;
    }
    // SAFETY: OpenProcessToken returned this handle exactly once.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token as RawHandle) };
    let mut required = 0u32;
    // SAFETY: A zero-length query with a null buffer only reports the size it
    // needs through `required`, which is writable storage.
    let _ = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            null_mut(),
            0,
            &mut required,
        )
    };
    let smallest = size_of::<TOKEN_USER>() as u32;
    if !(smallest..=TOKEN_USER_BUFFER_LIMIT).contains(&required) {
        return None;
    }
    // Whole words keep the TOKEN_USER Windows writes at the start aligned.
    let mut words = vec![0u64; (required as usize).div_ceil(size_of::<u64>())];
    // SAFETY: `words` holds at least `required` writable bytes for the
    // duration of the call and `required` is writable storage.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            words.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == FALSE
    {
        return None;
    }
    // SAFETY: The call above wrote a TOKEN_USER at the start of the aligned
    // buffer.
    let user = unsafe { std::ptr::read(words.as_ptr().cast::<TOKEN_USER>()) };
    if user.User.Sid.is_null() {
        return None;
    }
    // SAFETY: The SID Windows wrote points into `words`, which outlives this
    // borrow.
    let sid = unsafe { &*(user.User.Sid as *const Sid) };
    let text = ConvertSidToStringSid(sid).ok()?.into_string().ok()?;
    (!text.is_empty()).then(|| format!("sid:{text}"))
}

/// Terminate the process only while the handle that proves its creation
/// time is still open, so a reused id is never terminated. `true` once that
/// generation has exited. Nothing is terminated after `timeout`, and the
/// wait for the exit is bounded by both `timeout` and one second.
pub fn terminate_if_creation_time(
    process_id: u32,
    expected_creation_time: u64,
    timeout: Option<Duration>,
) -> bool {
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    let Ok(process) = super::open_process(
        process_id,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
    ) else {
        return false;
    };
    if process_creation_filetime(&process).ok() != Some(expected_creation_time) {
        return false;
    }
    let handle = process.as_raw_handle() as HANDLE;
    // SAFETY: `process` owns a valid process handle until this call returns.
    match unsafe { WaitForSingleObject(handle, 0) } {
        WAIT_OBJECT_0 => return true,
        WAIT_TIMEOUT => {}
        _ => return false,
    }
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return false;
    }
    // SAFETY: `process` owns a valid handle opened with PROCESS_TERMINATE.
    if unsafe { TerminateProcess(handle, 1) } == FALSE {
        return false;
    }
    let wait = deadline.map_or(TERMINATION_WAIT, |deadline| {
        deadline
            .saturating_duration_since(Instant::now())
            .min(TERMINATION_WAIT)
    });
    // SAFETY: `process` owns a valid process handle until this call returns.
    unsafe { WaitForSingleObject(handle, duration_to_wait_millis(wait)) == WAIT_OBJECT_0 }
}

/// The arguments `CommandLineToArgvW` splits `command` into. `None` for an
/// empty command, one holding a NUL, or one Windows cannot split.
pub fn command_line_to_argv(command: &str) -> Option<Vec<String>> {
    if command.is_empty() || command.contains('\0') {
        return None;
    }
    let wide: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
    let mut count = 0i32;
    // SAFETY: `wide` is NUL-terminated and `count` is writable storage.
    let arguments = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    if arguments.is_null() {
        return None;
    }
    let parsed = usize::try_from(count)
        .ok()
        .filter(|count| *count > 0)
        .map(|count| {
            (0..count)
                .map(|index| {
                    // SAFETY: Windows returned `count` pointers, each to a
                    // NUL-terminated string inside the same allocation.
                    let argument = unsafe { *arguments.add(index) };
                    let mut length = 0;
                    // SAFETY: Every unit up to the terminating NUL is readable.
                    while unsafe { *argument.add(length) } != 0 {
                        length += 1;
                    }
                    // SAFETY: The first `length` units were read above.
                    String::from_utf16_lossy(unsafe {
                        std::slice::from_raw_parts(argument, length)
                    })
                })
                .collect()
        });
    // SAFETY: CommandLineToArgvW allocated `arguments` as one LocalAlloc block
    // and nothing reads it after this call.
    let _ = unsafe { LocalFree(arguments.cast()) };
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_current_process() {
        let own = std::process::id();
        let creation_time = process_creation_time(own).unwrap();
        assert!(creation_time > 0);
        assert!(process_owner_sid(own).unwrap().starts_with("sid:S-1-"));
        // A creation time that is not this process's never terminates it.
        assert!(!terminate_if_creation_time(own, creation_time + 1, None));
        assert_eq!(process_creation_time(0), None);
        assert_eq!(process_owner_sid(0), None);
    }

    #[test]
    fn terminates_only_the_matching_generation() {
        let mut child = std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let creation_time = process_creation_time(child.id()).unwrap();
        assert!(!terminate_if_creation_time(
            child.id(),
            creation_time - 1,
            None
        ));
        assert!(!terminate_if_creation_time(
            child.id(),
            creation_time,
            Some(Duration::ZERO)
        ));
        assert!(child.try_wait().unwrap().is_none());
        assert!(terminate_if_creation_time(child.id(), creation_time, None));
        assert!(child.wait().is_ok());
        // `child` still holds its handle, so the exited generation keeps its
        // id and answers as already gone.
        assert!(terminate_if_creation_time(child.id(), creation_time, None));
    }

    #[test]
    fn splits_command_lines_as_windows_does() {
        assert_eq!(
            command_line_to_argv(r#""C:\Program Files\py.exe" -m "a b" c\\"d""#),
            Some(vec![
                r"C:\Program Files\py.exe".to_owned(),
                "-m".to_owned(),
                "a b".to_owned(),
                r#"c\d"#.to_owned(),
            ])
        );
        assert_eq!(
            command_line_to_argv(r#""C:\Users\深紫色\Guard Home\nested\\""#),
            Some(vec![r"C:\Users\深紫色\Guard Home\nested\".to_owned()])
        );
        assert_eq!(command_line_to_argv(""), None);
        assert_eq!(command_line_to_argv("guard.exe\0--status"), None);
    }
}
