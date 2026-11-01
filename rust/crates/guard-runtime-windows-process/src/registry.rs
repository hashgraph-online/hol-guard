use std::ptr::null_mut;

use winapi::shared::minwindef::{DWORD, HKEY};
use winapi::shared::winerror::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
};
use winapi::um::winnt::{KEY_QUERY_VALUE, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ};
use winapi::um::winreg::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
};

/// How often a value that grows between sizing and reading it is re-read.
const READ_ATTEMPTS: usize = 3;

/// What reading one string value under `HKEY_LOCAL_MACHINE` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineRegistryString {
    /// The key or the value does not exist.
    Missing,
    /// The key exists and this account may not read it.
    Denied,
    /// The value exists and is not `REG_SZ` or `REG_EXPAND_SZ`.
    NotText,
    /// The value holds more UTF-16 units than the caller accepts.
    TooLarge,
    /// The value's UTF-16 units, up to its first NUL.
    Text(Vec<u16>),
    /// Any other Win32 error code.
    Failed(u32),
}

struct OpenKey(HKEY);

impl Drop for OpenKey {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a key RegOpenKeyExW opened and nothing else
        // closes it.
        unsafe { RegCloseKey(self.0) };
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn failure(status: i32) -> MachineRegistryString {
    match status as u32 {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => MachineRegistryString::Missing,
        ERROR_ACCESS_DENIED => MachineRegistryString::Denied,
        code => MachineRegistryString::Failed(code),
    }
}

/// Read `HKLM\<subkey>\<value>` from the 64-bit registry view, where Group
/// Policy and MDM write machine policy, as a 64-bit Python's `winreg` reads it.
///
/// A value larger than `max_units` UTF-16 units is refused before its data is
/// read, so a hostile value cannot make the caller allocate without bound.
pub fn read_machine_registry_string(
    subkey: &str,
    value: &str,
    max_units: usize,
) -> MachineRegistryString {
    let subkey = wide(subkey);
    let name = wide(value);
    let mut raw: HKEY = null_mut();
    // SAFETY: `subkey` is NUL-terminated and `raw` receives the opened key.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut raw,
        )
    };
    if status as u32 != ERROR_SUCCESS {
        return failure(status);
    }
    let key = OpenKey(raw);
    // Room for the terminator a string value is stored with.
    let max_bytes = max_units.saturating_add(1).saturating_mul(2);
    for _ in 0..READ_ATTEMPTS {
        let mut kind: DWORD = 0;
        let mut size: DWORD = 0;
        // SAFETY: `name` is NUL-terminated; a null data pointer asks only for
        // the value's type and byte size.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null_mut(),
                &mut kind,
                null_mut(),
                &mut size,
            )
        };
        if status as u32 != ERROR_SUCCESS {
            return failure(status);
        }
        if kind != REG_SZ && kind != REG_EXPAND_SZ {
            return MachineRegistryString::NotText;
        }
        if size as usize > max_bytes {
            return MachineRegistryString::TooLarge;
        }
        let mut units = vec![0u16; (size as usize).div_ceil(2).max(1)];
        let mut read = (units.len() * 2) as DWORD;
        // SAFETY: `units` holds `read` writable bytes.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null_mut(),
                &mut kind,
                units.as_mut_ptr().cast(),
                &mut read,
            )
        };
        if status as u32 == ERROR_MORE_DATA {
            // The value grew after it was sized; size it again.
            continue;
        }
        if status as u32 != ERROR_SUCCESS {
            return failure(status);
        }
        if kind != REG_SZ && kind != REG_EXPAND_SZ {
            return MachineRegistryString::NotText;
        }
        units.truncate(read as usize / 2);
        if let Some(end) = units.iter().position(|&unit| unit == 0) {
            units.truncate(end);
        }
        if units.len() > max_units {
            return MachineRegistryString::TooLarge;
        }
        return MachineRegistryString::Text(units);
    }
    MachineRegistryString::Failed(ERROR_MORE_DATA)
}

/// The hive [`read_registry_value`] opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryHive {
    CurrentUser,
    LocalMachine,
}

/// What reading one registry value of any type found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryValue {
    /// The key or the value does not exist.
    Missing,
    /// The key exists and this account may not read it.
    Denied,
    /// The value holds more bytes than the caller accepts.
    TooLarge,
    /// The value's registry type (`REG_*`) and its raw data.
    Data { kind: u32, bytes: Vec<u8> },
    /// Any other Win32 error code.
    Failed(u32),
}

fn value_failure(status: i32) -> RegistryValue {
    match failure(status) {
        MachineRegistryString::Missing => RegistryValue::Missing,
        MachineRegistryString::Denied => RegistryValue::Denied,
        _ => RegistryValue::Failed(status as u32),
    }
}

/// Read `<hive>\<subkey>\<value>` from the 64-bit registry view with its type,
/// as a 64-bit Python's `winreg.QueryValueEx` reads it.
///
/// A value larger than `max_bytes` is refused before its data is read, so a
/// hostile value cannot make the caller allocate without bound.
pub fn read_registry_value(
    hive: RegistryHive,
    subkey: &str,
    value: &str,
    max_bytes: usize,
) -> RegistryValue {
    let root = match hive {
        RegistryHive::CurrentUser => HKEY_CURRENT_USER,
        RegistryHive::LocalMachine => HKEY_LOCAL_MACHINE,
    };
    let subkey = wide(subkey);
    let name = wide(value);
    let mut raw: HKEY = null_mut();
    // SAFETY: `subkey` is NUL-terminated and `raw` receives the opened key.
    let status = unsafe {
        RegOpenKeyExW(
            root,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut raw,
        )
    };
    if status as u32 != ERROR_SUCCESS {
        return value_failure(status);
    }
    let key = OpenKey(raw);
    for _ in 0..READ_ATTEMPTS {
        let mut kind: DWORD = 0;
        let mut size: DWORD = 0;
        // SAFETY: `name` is NUL-terminated; a null data pointer asks only for
        // the value's type and byte size.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null_mut(),
                &mut kind,
                null_mut(),
                &mut size,
            )
        };
        if status as u32 != ERROR_SUCCESS {
            return value_failure(status);
        }
        if size as usize > max_bytes {
            return RegistryValue::TooLarge;
        }
        let mut bytes = vec![0u8; (size as usize).max(1)];
        let mut read = bytes.len() as DWORD;
        // SAFETY: `bytes` holds `read` writable bytes.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null_mut(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut read,
            )
        };
        if status as u32 == ERROR_MORE_DATA {
            // The value grew after it was sized; size it again.
            continue;
        }
        if status as u32 != ERROR_SUCCESS {
            return value_failure(status);
        }
        bytes.truncate(read as usize);
        return RegistryValue::Data { kind, bytes };
    }
    RegistryValue::Failed(ERROR_MORE_DATA)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_policy_key_reads_as_missing() {
        assert_eq!(
            read_machine_registry_string(
                r"Software\Policies\HOL\GuardRegistryProbeThatIsNeverInstalled",
                "PolicyJson",
                1024,
            ),
            MachineRegistryString::Missing
        );
    }

    #[test]
    fn an_absent_value_under_a_present_key_reads_as_missing() {
        assert_eq!(
            read_machine_registry_string(
                r"Software\Microsoft\Windows NT\CurrentVersion",
                "HolGuardRegistryProbeThatIsNeverInstalled",
                1024,
            ),
            MachineRegistryString::Missing
        );
    }

    #[test]
    fn a_present_string_value_reads_as_its_text() {
        let MachineRegistryString::Text(units) = read_machine_registry_string(
            r"Software\Microsoft\Windows NT\CurrentVersion",
            "SystemRoot",
            1024,
        ) else {
            panic!("SystemRoot is a string value every Windows machine carries");
        };
        let text = String::from_utf16(&units).expect("utf-16");
        assert!(text.contains(':'), "{text}");
    }

    #[test]
    fn a_value_longer_than_the_bound_is_refused() {
        assert_eq!(
            read_machine_registry_string(
                r"Software\Microsoft\Windows NT\CurrentVersion",
                "SystemRoot",
                2,
            ),
            MachineRegistryString::TooLarge
        );
    }

    #[test]
    fn a_value_that_is_not_a_string_is_not_text() {
        assert_eq!(
            read_machine_registry_string(
                r"Software\Microsoft\Windows NT\CurrentVersion",
                "InstallDate",
                1024,
            ),
            MachineRegistryString::NotText
        );
    }

    #[test]
    fn a_typed_value_reads_with_its_kind_and_data() {
        let RegistryValue::Data { kind, bytes } = read_registry_value(
            RegistryHive::LocalMachine,
            r"Software\Microsoft\Windows NT\CurrentVersion",
            "InstallDate",
            64,
        ) else {
            panic!("InstallDate is a DWORD every Windows machine carries");
        };
        assert_eq!(kind, winapi::um::winnt::REG_DWORD);
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn a_typed_read_refuses_large_values_and_reads_absence() {
        assert_eq!(
            read_registry_value(
                RegistryHive::LocalMachine,
                r"Software\Microsoft\Windows NT\CurrentVersion",
                "SystemRoot",
                2,
            ),
            RegistryValue::TooLarge
        );
        assert_eq!(
            read_registry_value(
                RegistryHive::CurrentUser,
                r"Software\HOL\GuardRegistryProbeThatIsNeverInstalled",
                "ProxyEnable",
                64,
            ),
            RegistryValue::Missing
        );
    }
}
