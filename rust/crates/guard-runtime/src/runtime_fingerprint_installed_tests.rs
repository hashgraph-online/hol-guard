use super::*;

fn installed(root: &Path, version: &str, cache_dir: Option<&Path>) -> Option<String> {
    installed_fingerprint(root.to_str().unwrap(), version, cache_dir)
}

#[test]
fn installed_fingerprint_is_the_command_answer_and_follows_the_tree() {
    let root = tree();
    let first = installed(root.path(), VERSION, None).expect("readable");
    assert_eq!(
        run(root.path(), None)["fingerprint"].as_str(),
        Some(first.as_str())
    );
    assert_ne!(installed(root.path(), "9.9.10", None).unwrap(), first);
    fs::write(root.path().join(PACKAGE).join("a.py"), b"x = 22\n").unwrap();
    assert_ne!(installed(root.path(), VERSION, None).unwrap(), first);
}

/// Every `daemon-manage` request is a new process, so the installed check
/// reuses the cache file a starting process left rather than rehashing.
#[cfg(unix)]
#[test]
fn installed_fingerprint_reuses_the_command_cache_file() {
    let root = tree();
    let (_home, cache_dir) = private_cache_dir();
    let answer = run_with_cache_dir(root.path(), &cache_dir);
    let planted = "e".repeat(64);
    let body = json!({
        "content_fingerprint": planted,
        "source_root": root.path().to_str().unwrap(),
        "tree_sig": answer["tree_sig"],
    });
    plant_cache(&cache_dir, root.path(), body.to_string().as_bytes(), 0o600);
    assert_eq!(
        installed(root.path(), VERSION, Some(&cache_dir)),
        Some(planted)
    );
}

/// A file that cannot be read is no installed fingerprint, and neither the
/// installed check nor the command caches the partial digest, so the next
/// check after the file is readable again hashes it in full.
#[cfg(unix)]
#[test]
fn a_partial_read_is_neither_installed_nor_cached() {
    use std::os::unix::fs::PermissionsExt;

    let root = tree();
    let full = installed(root.path(), VERSION, None).unwrap();
    let module = root.path().join(PACKAGE).join("a.py");
    fs::set_permissions(&module, fs::Permissions::from_mode(0o000)).unwrap();
    if File::open(&module).is_ok() {
        // Running as root: permissions cannot make the file unreadable.
        return;
    }
    let (_home, cache_dir) = private_cache_dir();
    assert_eq!(installed(root.path(), VERSION, Some(&cache_dir)), None);
    let partial = run_with_cache_dir(root.path(), &cache_dir);
    assert_ne!(partial["fingerprint"].as_str(), Some(full.as_str()));
    assert!(!cache_file(&cache_dir, root.path()).exists());
    fs::set_permissions(&module, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        installed(root.path(), VERSION, Some(&cache_dir)),
        Some(full)
    );
}

/// A named pipe with a module's name is not opened for a blocking read.
#[cfg(unix)]
#[test]
fn a_named_pipe_in_the_tree_does_not_hold_the_answer() {
    let root = tree();
    let status = std::process::Command::new("mkfifo")
        .arg(root.path().join(PACKAGE).join("pipe.py"))
        .status()
        .expect("mkfifo runs");
    assert!(status.success(), "the fixture pipe");
    assert!(relative_names(root.path()).contains(&format!("{PACKAGE}/pipe.py")));
    let answer = run(root.path(), None);
    assert_eq!(
        installed(root.path(), VERSION, None).as_deref(),
        answer["fingerprint"].as_str()
    );
}

/// A package directory that cannot be listed leaves its files out of the
/// digest, so the listing is no installed fingerprint and is not cached.
#[cfg(unix)]
#[test]
fn an_unlisted_directory_is_no_installed_fingerprint() {
    use std::os::unix::fs::PermissionsExt;

    let root = tree();
    let guard = root.path().join(PACKAGE).join("guard");
    fs::set_permissions(&guard, fs::Permissions::from_mode(0o000)).unwrap();
    let listed = fs::read_dir(&guard).is_ok();
    let (_home, cache_dir) = private_cache_dir();
    let installed_now = installed(root.path(), VERSION, Some(&cache_dir));
    let partial = run_with_cache_dir(root.path(), &cache_dir);
    fs::set_permissions(&guard, fs::Permissions::from_mode(0o755)).unwrap();
    if listed {
        // Running as root: permissions cannot hide the directory.
        return;
    }
    assert_eq!(installed_now, None);
    assert!(partial["fingerprint"].is_string());
    assert!(!cache_file(&cache_dir, root.path()).exists());
}

/// A module path whose metadata cannot be read (here a dangling link) is
/// no installed fingerprint, even with a cache entry written before it
/// appeared.
#[cfg(unix)]
#[test]
fn a_dangling_module_link_is_no_installed_fingerprint_even_when_cached() {
    let root = tree();
    let (_home, cache_dir) = private_cache_dir();
    assert!(installed(root.path(), VERSION, Some(&cache_dir)).is_some());
    assert!(cache_file(&cache_dir, root.path()).exists());
    std::os::unix::fs::symlink(
        root.path().join("missing.py"),
        root.path().join(PACKAGE).join("extra.py"),
    )
    .unwrap();
    assert_eq!(installed(root.path(), VERSION, Some(&cache_dir)), None);
}

/// A socket with a module's name is listed but never opened: it adds its
/// path and size, as it always has, and leaves the digest complete.
#[cfg(unix)]
#[test]
fn a_socket_in_the_tree_is_listed_and_not_opened() {
    let root = tree();
    let _socket =
        std::os::unix::net::UnixListener::bind(root.path().join(PACKAGE).join("w.py")).unwrap();
    assert!(relative_names(root.path()).contains(&format!("{PACKAGE}/w.py")));
    let answer = run(root.path(), None);
    assert_eq!(
        installed(root.path(), VERSION, None).as_deref(),
        answer["fingerprint"].as_str()
    );
}

/// A static asset behind a directory that cannot be searched hides whether
/// it is a file, so the listing is no installed fingerprint and is not
/// cached rather than a shortened tree.
#[cfg(unix)]
#[test]
fn an_asset_whose_target_cannot_be_searched_is_no_installed_fingerprint() {
    use std::os::unix::fs::PermissionsExt;

    let root = tree();
    let hidden = root.path().join("hidden");
    fs::create_dir(&hidden).unwrap();
    fs::write(hidden.join("page.html"), b"<p>\n").unwrap();
    let link = root
        .path()
        .join(PACKAGE)
        .join("guard/daemon/static/linked.html");
    std::os::unix::fs::symlink(hidden.join("page.html"), &link).unwrap();
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o000)).unwrap();
    let searchable = fs::metadata(&link).is_ok();
    let (_home, cache_dir) = private_cache_dir();
    let installed_now = installed(root.path(), VERSION, Some(&cache_dir));
    let answer = run_with_cache_dir(root.path(), &cache_dir);
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o755)).unwrap();
    if searchable {
        // Running as root: permissions cannot hide the target.
        return;
    }
    assert_eq!(installed_now, None);
    assert!(answer["fingerprint"].is_string());
    assert!(!cache_file(&cache_dir, root.path()).exists());
}

/// A signature that could not read every path does not select a cached
/// digest, even one stored under that very signature.
#[cfg(unix)]
#[test]
fn a_short_signature_does_not_reuse_the_cache() {
    let root = tree();
    std::os::unix::fs::symlink(
        root.path().join("missing.py"),
        root.path().join(PACKAGE).join("extra.py"),
    )
    .unwrap();
    let (_home, cache_dir) = private_cache_dir();
    let first = run_with_cache_dir(root.path(), &cache_dir);
    assert!(!cache_file(&cache_dir, root.path()).exists());
    let body = json!({
        "content_fingerprint": "e".repeat(64),
        "source_root": root.path().to_str().unwrap(),
        "tree_sig": first["tree_sig"],
    });
    plant_cache(&cache_dir, root.path(), body.to_string().as_bytes(), 0o600);
    let again = run_with_cache_dir(root.path(), &cache_dir);
    assert_eq!(again["reused"], false);
    assert_eq!(again["fingerprint"], first["fingerprint"]);
}

/// The content pass is only paired with the signature taken before it when
/// the tree still has that signature afterwards.
#[test]
fn a_tree_changed_after_its_signature_is_not_paired_with_it() {
    let root = tree();
    let (paths, _) = identity_paths(root.path());
    let (signature, _) = tree_signature(root.path(), VERSION, &paths);
    assert!(unchanged_since(root.path(), VERSION, &paths, &signature));
    fs::write(root.path().join(PACKAGE).join("a.py"), b"x = 22\n").unwrap();
    assert!(!unchanged_since(root.path(), VERSION, &paths, &signature));
    plant(root.path(), &[("a.py", b"x = 1\n"), ("late.py", b"\n")]);
    assert!(!unchanged_since(root.path(), VERSION, &paths, &signature));
}
