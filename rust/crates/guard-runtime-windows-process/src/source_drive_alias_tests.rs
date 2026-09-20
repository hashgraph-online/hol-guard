use super::*;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;

use winapi::um::fileapi::{DefineDosDeviceW, QueryDosDeviceW};

const DDD_RAW_TARGET_PATH: DWORD = 0x0000_0001;
const DDD_REMOVE_DEFINITION: DWORD = 0x0000_0002;
const DDD_EXACT_MATCH_ON_REMOVE: DWORD = 0x0000_0004;
const DDD_NO_BROADCAST_SYSTEM: DWORD = 0x0000_0008;

struct DriveAlias {
    name: Vec<u16>,
    root: PathBuf,
    targets: Vec<Vec<u16>>,
}

impl DriveAlias {
    fn unused() -> Self {
        for letter in (b'M'..=b'Z').rev() {
            let name = wide(OsStr::new(&format!("{}:", char::from(letter))));
            let mut buffer = [0_u16; 1024];
            // SAFETY: The terminated name and writable output buffer remain
            // live for the call. Only a missing name may be used by this test.
            let length = unsafe {
                QueryDosDeviceW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as DWORD)
            };
            if length == 0 && io::Error::last_os_error().raw_os_error() == Some(2) {
                return Self {
                    name,
                    root: PathBuf::from(format!("{}:\\", char::from(letter))),
                    targets: Vec::new(),
                };
            }
        }
        panic!("no unused DOS drive name is available for the namespace control");
    }

    fn map(&mut self, path: &Path) {
        let path = fs::canonicalize(path).unwrap();
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            panic!("the fixture has no local drive prefix");
        };
        let letter = match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => panic!("the fixture is not on a local drive"),
        };
        assert!(matches!(components.next(), Some(Component::RootDir)));
        let mut target = OsString::from(format!(r"\??\{}:\", char::from(letter)));
        for component in components {
            target.push(component.as_os_str());
            target.push(r"\");
        }
        let target = wide(&target);
        // SAFETY: Both strings are terminated and remain live. This name was
        // unused; the exact fixture target is retained for bounded cleanup.
        let result = unsafe {
            DefineDosDeviceW(
                DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                self.name.as_ptr(),
                target.as_ptr(),
            )
        };
        assert_ne!(result, FALSE, "{}", io::Error::last_os_error());
        self.targets.push(target);
    }
}

impl Drop for DriveAlias {
    fn drop(&mut self) {
        for target in self.targets.iter().rev() {
            // SAFETY: Removal is restricted to an exact target created by
            // this fixture; no unrelated or previously existing alias is popped.
            unsafe {
                DefineDosDeviceW(
                    DDD_RAW_TARGET_PATH
                        | DDD_REMOVE_DEFINITION
                        | DDD_EXACT_MATCH_ON_REMOVE
                        | DDD_NO_BROADCAST_SYSTEM,
                    self.name.as_ptr(),
                    target.as_ptr(),
                );
            }
        }
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

#[test]
fn relative_children_keep_the_original_parent_after_dos_drive_remapping() {
    let first = Fixture::new("drive-original");
    let second = Fixture::new("drive-replacement");
    fs::write(second.source(), b"outside fixture content\n").unwrap();
    let mut alias = DriveAlias::unused();
    alias.map(&first.0.join("src"));
    let source_path = alias.root.join("source.rs");
    let original_parent = open_component(&alias.root, true).unwrap();
    let source = SourceFile::open(&source_path).unwrap();
    source.validate_path().unwrap();

    alias.map(&second.0.join("src"));
    // This control proves the full pathname really changed its namespace.
    assert_eq!(
        fs::read(&source_path).unwrap(),
        b"outside fixture content\n"
    );
    let mut child = open_source_child(&original_parent, OsStr::new("source.rs"), false).unwrap();
    let mut bytes = Vec::new();
    child.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"fn source() {}\n");
    assert!(source.validate_path().is_err());
}
