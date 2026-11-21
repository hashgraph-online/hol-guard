use super::*;
use std::env;
use std::io::Write;

const SENTINEL_ENV: &str = "HOL_GUARD_TEST_UNLISTED_HANDLE";

#[test]
fn short_win32_path_keeps_8_3_form() {
    let encoded = wide_path(Path::new(r"C:\Users\runneradmin\native-runtime")).unwrap();
    assert!(!encoded.starts_with(&[92, 92, 63, 92]));
}

#[test]
fn over_max_path_drive_path_uses_verbatim_prefix() {
    let long = format!(r"C:\Users\runneradmin\{}", "long-private-home-".repeat(14));
    assert!(long.encode_utf16().count() >= MAX_PATH);
    let encoded = wide_path(Path::new(&long)).unwrap();
    let prefix: Vec<u16> = r"\\?\".encode_utf16().collect();
    assert!(encoded.starts_with(&prefix));
    assert!(!encoded[prefix.len()..].starts_with(&prefix));
    assert_eq!(encoded.last().copied(), Some(0));
}

#[test]
fn over_max_path_unc_uses_unc_verbatim_prefix() {
    let long = format!(r"\\server\share\{}", "long-private-home-".repeat(14));
    assert!(long.encode_utf16().count() >= MAX_PATH);
    let encoded = wide_path(Path::new(&long)).unwrap();
    let prefix: Vec<u16> = r"\\?\UNC\".encode_utf16().collect();
    assert!(encoded.starts_with(&prefix));
    let tail: Vec<u16> = format!(r"server\share\{}", "long-private-home-".repeat(14))
        .encode_utf16()
        .chain([0])
        .collect();
    assert_eq!(&encoded[prefix.len()..], tail.as_slice());
}

#[test]
fn over_max_path_forward_slashes_are_normalized() {
    let long = format!("C:/Users/runneradmin/{}", "long-private-home-".repeat(14));
    assert!(long.encode_utf16().count() >= MAX_PATH);
    let encoded = wide_path(Path::new(&long)).unwrap();
    let prefix: Vec<u16> = r"\\?\".encode_utf16().collect();
    let expected: Vec<u16> = format!(r"C:\Users\runneradmin\{}", "long-private-home-".repeat(14))
        .encode_utf16()
        .chain([0])
        .collect();
    assert_eq!(&encoded[..prefix.len()], prefix.as_slice());
    assert_eq!(&encoded[prefix.len()..], expected.as_slice());
}

#[test]
fn already_verbatim_long_path_is_not_reprefixed() {
    let long = format!(
        r"\\?\C:\Users\runneradmin\{}",
        "long-private-home-".repeat(12)
    );
    let encoded = wide_path(Path::new(&long)).unwrap();
    let expected: Vec<u16> = long.encode_utf16().chain([0]).collect();
    assert_eq!(encoded, expected);
}

#[test]
fn long_device_path_is_not_rewritten() {
    let long = format!(
        r"\\.\C:\Users\runneradmin\{}",
        "long-private-home-".repeat(12)
    );
    let encoded = wide_path(Path::new(&long)).unwrap();
    let expected: Vec<u16> = long.encode_utf16().chain([0]).collect();
    assert_eq!(encoded, expected);
}

#[test]
fn long_relative_path_is_not_verbatim() {
    let long = "long-private-home-".repeat(20);
    assert!(long.encode_utf16().count() >= MAX_PATH);
    let encoded = wide_path(Path::new(&long)).unwrap();
    assert!(!encoded.starts_with(&[92, 92, 63, 92]));
}

#[test]
fn inherited_handle_is_not_leaked() {
    if let Ok(raw_handle) = env::var(SENTINEL_ENV) {
        let handle = raw_handle.parse::<usize>().expect("test handle is numeric") as HANDLE;
        let mut flags = 0;
        let inherited = unsafe {
            GetHandleInformation(handle, &mut flags) != FALSE
                && GetFileType(handle) == FILE_TYPE_UNKNOWN
        };
        assert!(!inherited, "unlisted parent handle reached managed child");
        return;
    }

    let mut security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    let mut open_handles = Vec::new();
    for _ in 0..128 {
        open_handles.push(create_null_handle(GENERIC_WRITE, &mut security).unwrap());
    }
    let sentinel = unsafe { CreateEventW(&mut security, FALSE, FALSE, null()) };
    assert!(!sentinel.is_null());
    let sentinel = unsafe { OwnedHandle::from_raw_handle(sentinel as RawHandle) };
    env::set_var(
        SENTINEL_ENV,
        (sentinel.as_raw_handle() as usize).to_string(),
    );

    let executable = env::current_exe().unwrap();
    let arguments = [
        OsStr::new("--nocapture"),
        OsStr::new("inherited_handle_is_not_leaked"),
    ];
    let mut child = spawn_managed_child(&executable, &arguments).unwrap();
    let mut stdin = child.take_stdin().unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    assert!(child
        .wait_success_with_timeout(std::time::Duration::from_secs(2))
        .unwrap());
    env::remove_var(SENTINEL_ENV);
    drop(open_handles);
}
