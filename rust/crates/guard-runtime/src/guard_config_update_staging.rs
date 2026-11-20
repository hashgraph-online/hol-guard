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
        let names = self.directory.names(4096).map_err(|e| match e {
            Names::Limit => failure("config_staging_limit_exceeded"),
            Names::Failed => failure("config_directory_unavailable"),
        })?;
        for name in names.iter().filter(|n| reserved(n)) {
            if pending.len() == 32 {
                return Err(failure("config_staging_limit_exceeded"));
            }
            let entry = self
                .directory
                .stat(name)
                .map_err(|_| failure("config_staging_changed"))?;
            if !entry.private_file() || entry.len > MAX_CONFIG_BYTES as u64 {
                return Err(failure("config_staging_unsafe"));
            }
            pending.push((name, entry));
        }
        self.check()?;
        for (name, expected) in &pending {
            self.check()?;
            let entry = self
                .directory
                .stat(name)
                .map_err(|_| failure("config_staging_changed"))?;
            if entry != *expected {
                return Err(failure("config_staging_changed"));
            }
            self.directory
                .remove_file(name)
                .map_err(|_| failure("config_staging_cleanup_failed"))?;
        }
        if !pending.is_empty() {
            self.directory
                .sync()
                .map_err(|_| failure("config_staging_cleanup_failed"))?;
        }
        self.check()
    }
}
