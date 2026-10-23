//! Held descriptor for the controller's fixed Native docs/mail frontdoor.
//! This identifies socket files, not the process or messages behind them.

use crate::{hex, open_root_owned_public_directory, StagingRole};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::process::geteuid;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

const FRONT_GID: u32 = 10001;
const FRONT_MODE: u32 = 0o710;
const SOCKET_MODE: u32 = 0o660;
const PRIVATE_MODE: u32 = 0o700;
const FAMILIES: [&str; 2] = ["docs.sock", "mail.sock"];

pub struct HeldNativeFrontdoor {
    state: OwnedFd,
    role: OwnedFd,
    front: OwnedFd,
    state_path: PathBuf,
    role_name: &'static str,
    state_stat: Stat,
    role_stat: Stat,
    front_stat: Stat,
    sockets: [Stat; 2],
}

fn same_inode(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
}

fn exact_private(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0
        && stat.st_gid == 0
        && stat.st_mode & 0o7777 == PRIVATE_MODE
        && stat.st_nlink >= 2
}

fn exact_front(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0
        && stat.st_gid == FRONT_GID
        && stat.st_mode & 0o7777 == FRONT_MODE
        && stat.st_nlink >= 2
}

fn exact_socket(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Socket
        && stat.st_uid == 0
        && stat.st_gid == FRONT_GID
        && stat.st_mode & 0o7777 == SOCKET_MODE
        && stat.st_nlink == 1
}

impl HeldNativeFrontdoor {
    /// Reopen the visible fixed state path and compare the held Root-owned
    /// state/role/front and both socket inodes before a tap child receives a
    /// duplicate of the frontdoor directory descriptor.
    pub fn recheck(&self) -> Result<(), String> {
        let reopened = open_root_owned_public_directory(&self.state_path)
            .map_err(|error| error.to_string())?;
        let visible_state = fstat(&reopened).map_err(|error| error.to_string())?;
        let held_state = fstat(&self.state).map_err(|error| error.to_string())?;
        if !exact_private(&visible_state)
            || !same_inode(&visible_state, &self.state_stat)
            || !same_inode(&held_state, &self.state_stat)
        {
            return Err("Native controller state identity changed".to_owned());
        }
        let visible_role = statat(&self.state, self.role_name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| error.to_string())?;
        let held_role = fstat(&self.role).map_err(|error| error.to_string())?;
        if !exact_private(&visible_role)
            || !same_inode(&visible_role, &self.role_stat)
            || !same_inode(&held_role, &self.role_stat)
        {
            return Err("Native controller role directory changed".to_owned());
        }
        let visible_front = statat(&self.role, "front", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| error.to_string())?;
        let held_front = fstat(&self.front).map_err(|error| error.to_string())?;
        if !exact_front(&visible_front)
            || !same_inode(&visible_front, &self.front_stat)
            || !same_inode(&held_front, &self.front_stat)
        {
            return Err("Native frontdoor directory changed".to_owned());
        }
        for (name, original) in FAMILIES.iter().zip(self.sockets.iter()) {
            let visible = statat(&self.front, *name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| error.to_string())?;
            if !exact_socket(&visible) || !same_inode(&visible, original) {
                return Err(format!("Native frontdoor socket changed: {name}"));
            }
        }
        Ok(())
    }

    pub fn duplicate_directory(&self) -> Result<OwnedFd, String> {
        self.recheck()?;
        self.front.try_clone().map_err(|error| error.to_string())
    }
}

fn open_under_base(
    base: &Path,
    run_id: &str,
    role: StagingRole,
) -> Result<HeldNativeFrontdoor, String> {
    if geteuid().as_raw() != 0 || !hex(run_id, 16) {
        return Err("Root and fixed staging run ID required for Native frontdoor".to_owned());
    }
    let state_path = base.join(format!("hx-{run_id}"));
    let state = open_root_owned_public_directory(&state_path).map_err(|error| error.to_string())?;
    let state_stat = fstat(&state).map_err(|error| error.to_string())?;
    if !exact_private(&state_stat) {
        return Err("Native controller state lacks Root-only custody".to_owned());
    }
    let role_name = role.as_str();
    let role = openat(
        &state,
        role_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| error.to_string())?;
    let role_stat = fstat(&role).map_err(|error| error.to_string())?;
    if !exact_private(&role_stat) {
        return Err("Native controller role lacks Root-only custody".to_owned());
    }
    let front = openat(
        &role,
        "front",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| error.to_string())?;
    let front_stat = fstat(&front).map_err(|error| error.to_string())?;
    if !exact_front(&front_stat) {
        return Err("Native frontdoor directory lacks fixed socket custody".to_owned());
    }
    let sockets = FAMILIES
        .map(|name| {
            statat(&front, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| error.to_string())
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    if sockets.iter().any(|stat| !exact_socket(stat)) {
        return Err("Native frontdoor socket lacks fixed custody".to_owned());
    }
    let held = HeldNativeFrontdoor {
        state,
        role,
        front,
        state_path,
        role_name,
        state_stat,
        role_stat,
        front_stat,
        sockets: [sockets[0], sockets[1]],
    };
    held.recheck()?;
    Ok(held)
}

/// Open only the validated one-use staging control's Native frontdoor under
/// `/home`; this is not an SDK peer, Native process or verdict observation.
pub fn open_fixed_native_frontdoor_ineligible(
    run_id: &str,
    role: StagingRole,
) -> Result<HeldNativeFrontdoor, String> {
    open_under_base(Path::new("/home"), run_id, role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{chmodat, chownat};
    use rustix::process::Gid;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    #[test]
    #[ignore = "requires Linux Root for exact Native frontdoor custody"]
    fn holds_native_frontdoor_and_refuses_changed_socket() {
        let base = tempfile::Builder::new()
            .prefix("gauntlet-native-front-")
            .tempdir_in("/root")
            .unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let state = base.path().join("hx-0123456789abcdef");
        let role = state.join("success");
        let front = role.join("front");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&role).unwrap();
        fs::create_dir(&front).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&role, fs::Permissions::from_mode(0o700)).unwrap();
        chownat(
            rustix::fs::CWD,
            &front,
            None,
            Some(Gid::from_raw(FRONT_GID)),
            AtFlags::empty(),
        )
        .unwrap();
        fs::set_permissions(&front, fs::Permissions::from_mode(FRONT_MODE)).unwrap();
        let _docs = UnixListener::bind(front.join("docs.sock")).unwrap();
        let _mail = UnixListener::bind(front.join("mail.sock")).unwrap();
        for name in FAMILIES {
            let socket = front.join(name);
            chownat(
                rustix::fs::CWD,
                &socket,
                None,
                Some(Gid::from_raw(FRONT_GID)),
                AtFlags::empty(),
            )
            .unwrap();
            chmodat(
                rustix::fs::CWD,
                &socket,
                Mode::from_bits_truncate(SOCKET_MODE),
                AtFlags::empty(),
            )
            .unwrap();
        }
        let held = open_under_base(base.path(), "0123456789abcdef", StagingRole::Success).unwrap();
        held.recheck().unwrap();
        let duplicate = held.duplicate_directory().unwrap();
        assert_eq!(
            fstat(&duplicate).unwrap().st_ino,
            fstat(&held.front).unwrap().st_ino
        );
        fs::set_permissions(front.join("mail.sock"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(held.recheck().is_err());
        assert!(held.duplicate_directory().is_err());
        fs::set_permissions(
            front.join("mail.sock"),
            fs::Permissions::from_mode(SOCKET_MODE),
        )
        .unwrap();
        held.recheck().unwrap();
        fs::remove_file(front.join("mail.sock")).unwrap();
        let _replacement = UnixListener::bind(front.join("mail.sock")).unwrap();
        chownat(
            rustix::fs::CWD,
            front.join("mail.sock"),
            None,
            Some(Gid::from_raw(FRONT_GID)),
            AtFlags::empty(),
        )
        .unwrap();
        fs::set_permissions(
            front.join("mail.sock"),
            fs::Permissions::from_mode(SOCKET_MODE),
        )
        .unwrap();
        assert!(held.recheck().is_err());
        assert!(held.duplicate_directory().is_err());
    }
}
