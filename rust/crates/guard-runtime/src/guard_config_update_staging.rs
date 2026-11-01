//! Recover only this writer's bounded reserved temporary namespace. The
//! profile lock proves no cooperating writer still owns one of these files.
use super::*;

fn reserved(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix(".config.toml.")
        .and_then(|n| n.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((pid, nonce)) = stem.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && pid.len() <= 10
        && pid.bytes().all(|b| b.is_ascii_digit())
        && pid.parse::<u32>().is_ok_and(|n| n != 0)
        && nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl WriteLock {
    pub(super) fn recover_staging(&self) -> Result<(), Failure> {
        self.check()?;
        let mut pending = Vec::new();
        for (index, entry) in fs::read_dir(&self.canonical)
            .map_err(|_| failure("config_directory_unavailable"))?
            .enumerate()
        {
            if index >= 4096 {
                return Err(failure("config_staging_limit_exceeded"));
            }
            let entry = entry.map_err(|_| failure("config_directory_unavailable"))?;
            let name = entry.file_name();
            let Some(name) = name.to_str().filter(|n| reserved(n)) else {
                continue;
            };
            if pending.len() == 32 {
                return Err(failure("config_staging_limit_exceeded"));
            }
            let stat = fstatat(&self.directory, name, AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| failure("config_staging_changed"))?;
            if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
                || stat.st_uid != nix::unistd::geteuid().as_raw()
                || stat.st_nlink != 1
                || stat.st_mode & 0o077 != 0
                || stat.st_size < 0
                || stat.st_size as u64 > MAX_CONFIG_BYTES as u64
            {
                return Err(failure("config_staging_unsafe"));
            }
            pending.push((name.to_owned(), stat));
        }
        self.check()?;
        for (name, expected) in &pending {
            self.check()?;
            let stat = fstatat(&self.directory, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| failure("config_staging_changed"))?;
            if stat.st_dev != expected.st_dev
                || stat.st_ino != expected.st_ino
                || stat.st_nlink != expected.st_nlink
                || stat.st_mode != expected.st_mode
                || stat.st_size != expected.st_size
                || stat.st_uid != expected.st_uid
            {
                return Err(failure("config_staging_changed"));
            }
            unlinkat(&self.directory, name.as_str(), UnlinkatFlags::NoRemoveDir)
                .map_err(|_| failure("config_staging_cleanup_failed"))?;
        }
        if !pending.is_empty() {
            self.directory
                .sync_all()
                .map_err(|_| failure("config_staging_cleanup_failed"))?;
        }
        self.check()
    }
}
