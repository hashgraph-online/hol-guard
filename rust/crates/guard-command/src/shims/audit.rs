//! Package-shim audit stamp. Non-finite JSON objects keep their other fields.

use std::io;

use serde_json::{json, Value};

use super::audit_manifest::{read_manifest, with_stamp, ManifestBody};
use super::pyfs::ReadError;
use super::{ShimContext, ShimResult};

/// `_load_package_shim_manifest`: a JSON object, or the original non-finite text.
fn load_any(context: &ShimContext) -> ShimResult<ManifestBody> {
    let facts = &context.facts;
    let path = context.manifest_path();
    if !facts.exists(&path) {
        return Ok(ManifestBody::Object(Default::default()));
    }
    let text = match facts.read_text(&path) {
        Ok(text) => text,
        Err(ReadError::Io(_)) => return Ok(ManifestBody::Object(Default::default())),
        Err(error) => return Err(error.message(&path)),
    };
    read_manifest(&text)
}

/// `record_package_shim_audit_result`: stamp `last_audit_at` into the manifest.
pub fn record_package_shim_audit_result(
    context: &ShimContext,
    audited_at: Option<&str>,
) -> ShimResult<Value> {
    let facts = &context.facts;
    let body = load_any(context)?;
    let stamp = audited_at.unwrap_or(&facts.now).to_owned();
    let path = facts.expanded_abspath(&context.manifest_path());
    let root = facts.expanded_abspath(&context.guard_home);
    let within = match (facts.resolve(&root), facts.resolve(&path)) {
        (Ok(resolved_root), Ok(resolved_target)) => {
            facts.is_within(&resolved_target, &resolved_root)
        }
        _ => false,
    };
    if !within {
        return Err("package shim manifest escapes the Guard home".to_owned());
    }
    let payload = with_stamp(body, &stamp);
    write_no_follow(&path, payload.as_bytes())
        .map_err(|error| format!("cannot write {path}: {error}"))?;
    Ok(json!({ "last_audit_at": stamp }))
}

#[cfg(unix)]
fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

/// Replace `path` without following an untrusted symlink.
#[cfg(unix)]
fn write_no_follow(path: &str, payload: &[u8]) -> io::Result<()> {
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::path::{Component, Path};

    use nix::errno::Errno;
    use nix::fcntl::{open, openat, renameat, OFlag};
    use nix::sys::stat::{fchmod, mkdirat, Mode};
    use nix::unistd::{fsync, unlinkat, UnlinkatFlags};

    let normalized = normalize_trusted_output_path(Path::new(path))?;
    let target = normalized.as_path();
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_owned();
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let directory_flags =
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let root = open("/", directory_flags, Mode::empty()).map_err(errno_io)?;
    let mut directory = File::from(root);
    for component in parent.components() {
        let part = match component {
            Component::RootDir => continue,
            Component::Normal(part) => part,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path is not normalised",
                ))
            }
        };
        let child = match openat(&directory, part, directory_flags, Mode::empty()) {
            Ok(child) => child,
            Err(Errno::ENOENT) => {
                mkdirat(&directory, part, Mode::from_bits_truncate(0o755)).map_err(errno_io)?;
                openat(&directory, part, directory_flags, Mode::empty()).map_err(errno_io)?
            }
            Err(error) => return Err(errno_io(error)),
        };
        directory = File::from(child);
    }

    let mut token = [0_u8; 16];
    getrandom::fill(&mut token).map_err(|error| io::Error::other(error.to_string()))?;
    let suffix = hex::encode(token);
    let temporary = format!(".{}.{suffix}", name.to_string_lossy());
    let descriptor = openat(
        &directory,
        temporary.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(errno_io)?;
    let mut file = File::from(descriptor);
    let written = (|| -> io::Result<()> {
        fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(errno_io)?;
        file.write_all(payload)?;
        file.flush()?;
        fsync(&file).map_err(errno_io)
    })();
    drop(file);
    let published = written
        .and_then(|()| {
            renameat(
                directory.as_fd(),
                temporary.as_str(),
                directory.as_fd(),
                name.as_os_str(),
            )
            .map_err(errno_io)
        })
        .and_then(|()| fsync(&directory).map_err(errno_io));
    if published.is_err() {
        let _ = unlinkat(&directory, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    published
}

#[cfg(unix)]
fn normalize_trusted_output_path(path: &std::path::Path) -> io::Result<std::path::PathBuf> {
    use std::path::{Component, PathBuf};

    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not absolute",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut parts = Vec::new();
    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => parts.push(part.to_os_string()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path is not normalised",
                ))
            }
        }
    }
    let mut current = PathBuf::from("/");
    for (index, part) in parts.iter().enumerate() {
        let candidate = current.join(part);
        match std::fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut rest = candidate;
                for later in parts.iter().skip(index + 1) {
                    rest.push(later);
                }
                rest.push(name);
                return Ok(rest);
            }
            Err(error) => return Err(error),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                if !trusted_system_link(&candidate)? {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "refusing symlinked output directory: {}",
                            candidate.display()
                        ),
                    ));
                }
                current = std::fs::canonicalize(&candidate)?;
            }
            Ok(_) => current = candidate,
        }
    }
    current.push(name);
    Ok(current)
}

#[cfg(unix)]
fn trusted_system_link(path: &std::path::Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    Ok(metadata.uid() == 0 && parent_metadata.uid() == 0 && parent_metadata.mode() & 0o022 == 0)
}

#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(any(unix, windows)))]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Refuse a symlink, junction, or other reparse point before creating or writing.
#[cfg(not(unix))]
fn write_no_follow(path: &str, payload: &[u8]) -> io::Result<()> {
    use std::fs;
    use std::path::{Component, Path, PathBuf};

    let target = Path::new(path);
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let mut current = PathBuf::new();
    let mut missing = false;
    for component in parent.components() {
        match component {
            Component::CurDir | Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path is not normalised",
                ));
            }
            other => current.push(other),
        }
        if missing {
            fs::create_dir(&current)?;
        }
        match fs::symlink_metadata(&current) {
            Ok(meta) if is_reparse_point(&meta) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing reparse-point output directory: {}",
                        current.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && !missing => {
                fs::create_dir(&current)?;
                missing = true;
                let created = fs::symlink_metadata(&current)?;
                if is_reparse_point(&created) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "refusing reparse-point output directory: {}",
                            current.display()
                        ),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    if let Ok(meta) = fs::symlink_metadata(target) {
        if is_reparse_point(&meta) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("refusing reparse-point output path: {}", target.display()),
            ));
        }
    }
    let mut token = [0_u8; 16];
    getrandom::fill(&mut token).map_err(|error| io::Error::other(error.to_string()))?;
    let suffix = hex::encode(token);
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let temporary = parent.join(format!(".{}.{suffix}", name.to_string_lossy()));
    let written = fs::write(&temporary, payload).and_then(|()| fs::rename(&temporary, target));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::{ShimContext, ShimFacts};
    use super::record_package_shim_audit_result;

    fn facts() -> ShimFacts {
        ShimFacts {
            environ: BTreeMap::new(),
            home: "/Users/home".to_owned(),
            cwd: "/".to_owned(),
            executable: "/usr/bin/python3".to_owned(),
            frozen: false,
            frozen_cli: String::new(),
            trusted_frozen_cli_paths: Vec::new(),
            python_version: (3, 12),
            import_root: "/Users/src".to_owned(),
            argv0: None,
            windows: false,
            sqlite_connect_timeout_seconds: 30.0,
            now: "2026-01-01T00:00:00+00:00".to_owned(),
            shim_dir_transient: None,
        }
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("temp dir")
            .join(format!("hol-guard-shim-audit-{label}-{stamp}"));
        fs::create_dir_all(&root).expect("scratch");
        root
    }

    #[test]
    fn stamps_a_missing_manifest_and_preserves_other_keys() {
        let root = scratch("stamp");
        let home = root.join("guard-home");
        let context = ShimContext::new(home.to_str().expect("utf8"), None, None, facts());
        let result = record_package_shim_audit_result(&context, None).expect("stamp");
        assert_eq!(result["last_audit_at"], "2026-01-01T00:00:00+00:00");
        let manifest = home.join("package-shims").join("manifest.json");
        assert_eq!(
            fs::read_to_string(&manifest).expect("manifest"),
            "{\"last_audit_at\": \"2026-01-01T00:00:00+00:00\"}"
        );
        let mode = fs::metadata(&manifest).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::write(&manifest, "{\"b\": 1, \"a\": [true]}").expect("seed");
        record_package_shim_audit_result(&context, Some("2026-02-02T00:00:00+00:00"))
            .expect("restamp");
        assert_eq!(
            fs::read_to_string(&manifest).expect("manifest"),
            "{\"a\": [true], \"b\": 1, \"last_audit_at\": \"2026-02-02T00:00:00+00:00\"}"
        );
        fs::write(&manifest, "[1]").expect("non-object");
        record_package_shim_audit_result(&context, None).expect("replace");
        assert_eq!(
            fs::read_to_string(&manifest).expect("manifest"),
            "{\"last_audit_at\": \"2026-01-01T00:00:00+00:00\"}"
        );
        fs::write(
            &manifest,
            "{\"enabled\": true, \"score\": NaN, \"limit\": Infinity}",
        )
        .expect("nan");
        record_package_shim_audit_result(&context, None).expect("stamp nan");
        assert_eq!(
            fs::read_to_string(&manifest).expect("manifest"),
            "{\"enabled\": true, \"score\": NaN, \"limit\": Infinity, \"last_audit_at\": \"2026-01-01T00:00:00+00:00\"}"
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn refuses_a_symlinked_manifest_directory_and_leaves_the_target_alone() {
        let root = scratch("symlink");
        let home = root.join("guard-home");
        let outside = root.join("outside");
        fs::create_dir_all(&home).expect("home");
        fs::create_dir_all(&outside).expect("outside");
        symlink(&outside, home.join("package-shims")).expect("link");
        let context = ShimContext::new(home.to_str().expect("utf8"), None, None, facts());
        let error = record_package_shim_audit_result(&context, None).expect_err("escape");
        assert!(error.contains("escapes the Guard home"), "{error}");
        assert_eq!(fs::read_dir(&outside).expect("outside").count(), 0);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn writes_a_relative_guard_home_under_facts_cwd() {
        let root = scratch("relative");
        let work = root.join("work");
        fs::create_dir_all(&work).expect("work");
        let mut request_facts = facts();
        request_facts.cwd = work.to_str().expect("utf8").to_owned();
        let context = ShimContext::new("guard-home", None, None, request_facts);
        record_package_shim_audit_result(&context, None).expect("stamp");
        let manifest = work
            .join("guard-home")
            .join("package-shims")
            .join("manifest.json");
        assert_eq!(
            fs::read_to_string(&manifest).expect("manifest"),
            "{\"last_audit_at\": \"2026-01-01T00:00:00+00:00\"}"
        );
        assert!(!root.join("guard-home").exists());
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn refuses_an_untrusted_symlinked_ancestor_inside_the_guard_home() {
        let root = scratch("untrusted-link");
        let real = root.join("real");
        fs::create_dir_all(&real).expect("real");
        let link = root.join("link");
        symlink(&real, &link).expect("link");
        let context = ShimContext::new(link.to_str().expect("utf8"), None, None, facts());
        let error = record_package_shim_audit_result(&context, None).expect_err("symlink");
        assert!(
            error.contains("refusing symlinked output directory"),
            "{error}"
        );
        assert!(!real.join("package-shims").exists());
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn writes_through_a_root_owned_system_symlink() {
        let tmp = std::path::Path::new("/tmp");
        let metadata = fs::symlink_metadata(tmp).expect("tmp");
        if !metadata.file_type().is_symlink() {
            return;
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let logical =
            std::path::PathBuf::from(format!("/tmp/hol-guard-shim-audit-syslink-{stamp}"));
        let home = logical.join("guard-home");
        let context = ShimContext::new(home.to_str().expect("utf8"), None, None, facts());
        record_package_shim_audit_result(&context, None).expect("stamp");
        let manifest = home.join("package-shims").join("manifest.json");
        assert_eq!(
            fs::read_to_string(&manifest).expect("manifest"),
            "{\"last_audit_at\": \"2026-01-01T00:00:00+00:00\"}"
        );
        fs::remove_dir_all(&logical).expect("cleanup");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::write_no_follow;

    #[test]
    fn refuses_a_junction_and_does_not_write_outside() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("hol-guard-shim-audit-junction-{stamp}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("root");
        let outside = root.join("outside");
        let home = root.join("guard-home");
        fs::create_dir_all(&outside).expect("outside");
        fs::create_dir_all(&home).expect("home");
        let junction = home.join("package-shims");
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .status()
            .expect("mklink");
        assert!(status.success(), "mklink /J");
        let manifest = junction.join("manifest.json");
        let path = manifest.to_str().expect("utf8");
        let error = write_no_follow(path, b"{}").expect_err("junction");
        assert!(error.to_string().contains("reparse-point"), "{error}");
        assert_eq!(fs::read_dir(&outside).expect("outside").count(), 0);
        let _ = fs::remove_dir(&junction);
        fs::remove_dir_all(&root).expect("cleanup");
    }
}

#[cfg(all(test, unix))]
#[path = "audit_fail_closed_tests.rs"]
mod audit_fail_closed_tests;
