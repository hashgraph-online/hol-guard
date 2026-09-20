use std::os::unix::fs::{symlink, DirBuilderExt};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    directory_identity: Identity,
    path: PathBuf,
    socket_identity: Identity,
    _receiver: UnixDatagram,
}

impl Fixture {
    fn new() -> Self {
        let mut owned = None;
        for _ in 0..16 {
            let next = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = PathBuf::from(format!(
                "/tmp/guard-native-phase-{}-{next}", std::process::id()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    owned = Some(path);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create owned diagnostic fixture: {error}"),
            }
        }
        let directory = owned.expect("bounded diagnostic fixture names exhausted");
        let path = directory.join("phase.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            directory_identity: identity(&directory, true).unwrap(),
            socket_identity: identity(&path, false).unwrap(),
            directory,
            path,
            _receiver: receiver,
        }
    }

    fn acquire(&self) -> Option<UnixDatagram> {
        acquire(&self.path, self.socket_identity.device, self.socket_identity.inode)
    }
}

fn same_object(left: Identity, right: Identity) -> bool {
    (left.device, left.inode, left.uid) == (right.device, right.inode, right.uid)
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let Ok(parent) = fs::symlink_metadata(&self.directory) else { return };
        if !parent.is_dir() || !same_object(Identity::from_metadata(&parent), self.directory_identity) {
            return;
        }
        if let Ok(socket) = fs::symlink_metadata(&self.path) {
            if socket.file_type().is_socket()
                && same_object(Identity::from_metadata(&socket), self.socket_identity)
            {
                let _ = fs::remove_file(&self.path);
            }
        }
        // Only the exact newly created, now-empty directory is removed.
        let _ = fs::remove_dir(&self.directory);
    }
}

#[test]
fn private_endpoint_requires_exact_owned_socket_identity() {
    let fixture = Fixture::new();
    let socket = fixture.acquire().unwrap();
    assert_eq!(socket.peer_addr().unwrap().as_pathname(), Some(fixture.path.as_path()));
    assert!(acquire(&fixture.path, fixture.socket_identity.device, fixture.socket_identity.inode + 1).is_none());
    assert!(acquire(&fixture.path, fixture.socket_identity.device.wrapping_add(1), fixture.socket_identity.inode).is_none());
}

#[test]
fn directory_and_socket_modes_are_admission_boundaries() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(fixture.acquire().is_none());
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(fixture.acquire().is_none());
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(fixture.acquire().is_some());
}

#[test]
fn symlink_endpoint_and_unadmitted_path_shapes_are_refused() {
    let fixture = Fixture::new();
    let second = Fixture::new();
    fs::remove_file(&second.path).unwrap();
    symlink(&fixture.path, &second.path).unwrap();
    assert!(acquire(&second.path, fixture.socket_identity.device, fixture.socket_identity.inode).is_none());
    fs::remove_file(&second.path).unwrap();
    assert!(acquire(Path::new("phase.sock"), 0, 0).is_none());
    assert!(acquire(&fixture.directory.join("../phase.sock"), 0, 0).is_none());
    assert!(acquire(&fixture.directory.join("other.sock"), 0, 0).is_none());
    assert!(acquire(Path::new("/tmp/phase.sock"), 0, 0).is_none());
}

#[test]
fn regular_file_cannot_stand_in_for_the_diagnostic_socket() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.path).unwrap();
    fs::write(&fixture.path, b"controlled nonsocket").unwrap();
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(fixture.acquire().is_none());
    fs::remove_file(&fixture.path).unwrap();
}

#[test]
fn startup_identity_parser_handles_comm_delimiters_and_refuses_ambiguity() {
    let stat = format!("{} (controlled ) name) S {} 777\n",
        std::process::id(), "0 ".repeat(18));
    assert_eq!(parse_start_ticks(stat.as_bytes(), std::process::id()), Some(777));
    assert!(parse_start_ticks(stat.as_bytes(), std::process::id().wrapping_add(1)).is_none());
    assert!(parse_start_ticks(b"123 (short) S 0", 123).is_none());
    let zero = stat.replace("777", "0");
    assert!(parse_start_ticks(zero.as_bytes(), std::process::id()).is_none());
    assert!(self_start_ticks().is_some());
}
