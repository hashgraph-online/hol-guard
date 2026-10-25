use super::*;
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt},
    path::PathBuf,
};

struct Fixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    source: PathBuf,
    objects: BTreeSet<String>,
    archives: BTreeSet<String>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let source = base.join("source");
        let mut sets = Vec::new();
        for (family, suffix, contents) in [
            (
                "objects",
                "json",
                vec![b"public one".as_slice(), b"public two".as_slice()],
            ),
            ("archives", "zip", vec![b"public archive".as_slice()]),
        ] {
            fs::create_dir_all(source.join(family)).unwrap();
            let mut ids = BTreeSet::new();
            for bytes in contents {
                let id = hash(bytes);
                fs::write(source.join(family).join(format!("{id}.{suffix}")), bytes).unwrap();
                ids.insert(id);
            }
            sets.push(ids);
        }
        Self {
            _temp: temp,
            base,
            source,
            objects: sets.remove(0),
            archives: sets.remove(0),
        }
    }

    fn export(
        &self,
        destination: &Path,
        checkpoint: &mut impl FnMut(&str, &str) -> Result<()>,
    ) -> Result<Value> {
        run(
            destination,
            &self.source,
            b"public root",
            &self.objects,
            &self.archives,
            checkpoint,
        )
    }
}

#[test]
fn every_file_sync_and_temporary_unlink_precedes_data_barriers_and_root() {
    let f = Fixture::new();
    let destination = f.base.join("export");
    let mut events = Vec::new();
    f.export(&destination, &mut |event, name| {
        if event == "data_directory_synced" || event == "hierarchy_synced" {
            assert!(!destination.join("root.json").exists());
        }
        events.push((event.to_owned(), name.to_owned()));
        Ok(())
    })
    .unwrap();
    let root_sync = events
        .iter()
        .position(|(e, n)| e == "file_synced" && n == "root.json")
        .unwrap();
    let barriers = events
        .iter()
        .enumerate()
        .filter(|(_, (e, _))| e == "data_directory_synced")
        .collect::<Vec<_>>();
    assert_eq!(barriers.len(), 2);
    for (family, ids, suffix) in [
        ("objects", &f.objects, "json"),
        ("archives", &f.archives, "zip"),
    ] {
        let barrier = barriers.iter().find(|(_, (_, n))| n == family).unwrap().0;
        assert!(barrier < root_sync);
        for id in ids {
            let name = format!("{id}.{suffix}");
            let sequence = ["file_synced", "published", "temporary_removed"].map(|event| {
                events
                    .iter()
                    .position(|(e, n)| e == event && *n == name)
                    .unwrap()
            });
            assert!(
                sequence[0] < sequence[1] && sequence[1] < sequence[2] && sequence[2] < barrier
            );
        }
        assert!(fs::read_dir(destination.join(family)).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
    }
    assert_eq!(events.iter().filter(|(e, _)| e == "file_synced").count(), 4);
    assert_eq!(
        events
            .iter()
            .filter(|(e, _)| e == "before_directory_sync")
            .count(),
        5
    );
    assert_eq!(events.last().unwrap().0, "root_directory_synced");
}

#[test]
fn every_injected_io_boundary_failure_leaves_no_root_or_owned_temporary() {
    let f = Fixture::new();
    let mut count = 0;
    f.export(&f.base.join("count"), &mut |_, _| {
        count += 1;
        Ok(())
    })
    .unwrap();
    for fail_at in 0..count {
        let destination = f.base.join(format!("failure-{fail_at}"));
        let mut index = 0;
        let result = f.export(&destination, &mut |_, _| {
            let fail = index == fail_at;
            index += 1;
            if fail {
                Err("injected_io_failure".into())
            } else {
                Ok(())
            }
        });
        assert!(result.is_err(), "boundary {fail_at}");
        assert!(
            !destination.join("root.json").exists(),
            "boundary {fail_at}"
        );
        for directory in [
            destination.clone(),
            destination.join("objects"),
            destination.join("archives"),
        ] {
            if directory.exists() {
                assert!(fs::read_dir(directory).unwrap().all(|e| !e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".transfer-")));
            }
        }
    }
}

#[test]
fn existing_empty_partial_and_published_destinations_are_rejected_unchanged() {
    let f = Fixture::new();
    let destination = f.base.join("existing");
    fs::create_dir(&destination).unwrap();
    assert!(f.export(&destination, &mut |_, _| Ok(())).is_err());
    fs::write(destination.join("root.json"), b"previous root").unwrap();
    assert!(f.export(&destination, &mut |_, _| Ok(())).is_err());
    assert_eq!(
        fs::read(destination.join("root.json")).unwrap(),
        b"previous root"
    );
    let partial = f.base.join("partial");
    assert!(f
        .export(&partial, &mut |_, _| Err("interrupted".into()))
        .is_err());
    assert!(f.export(&partial, &mut |_, _| Ok(())).is_err());
}

#[test]
fn symlink_destination_ancestor_and_source_are_refused() {
    let f = Fixture::new();
    let alias = f.base.join("alias");
    symlink(&f.source, &alias).unwrap();
    assert!(f.export(&alias, &mut |_, _| Ok(())).is_err());
    assert!(f.export(&alias.join("export"), &mut |_, _| Ok(())).is_err());
    assert!(!f.source.join("export").exists());
    let id = f.objects.first().unwrap();
    let source = f.source.join("objects").join(format!("{id}.json"));
    fs::remove_file(&source).unwrap();
    let sentinel = f.base.join("private");
    fs::write(&sentinel, b"private sentinel").unwrap();
    symlink(&sentinel, &source).unwrap();
    let destination = f.base.join("rejected-source");
    assert!(f.export(&destination, &mut |_, _| Ok(())).is_err());
    assert_eq!(
        fs::read_dir(destination.join("objects")).unwrap().count(),
        0
    );
}

#[test]
fn source_substitution_never_writes_private_bytes() {
    let f = Fixture::new();
    let id = f.objects.first().unwrap();
    fs::write(
        f.source.join("objects").join(format!("{id}.json")),
        b"private credential sentinel",
    )
    .unwrap();
    let destination = f.base.join("substitution");
    assert_eq!(
        f.export(&destination, &mut |_, _| Ok(())).unwrap_err(),
        "offline_copy_source_integrity_invalid"
    );
    assert_eq!(
        fs::read_dir(destination.join("objects")).unwrap().count(),
        0
    );
    assert!(!destination.join("root.json").exists());
}

#[test]
fn replaced_data_directory_is_not_followed_or_used_as_a_sync_target() {
    let f = Fixture::new();
    let destination = f.base.join("replaced");
    let outside = f.base.join("outside");
    fs::create_dir(&outside).unwrap();
    let mut replaced = false;
    let result = f.export(&destination, &mut |event, name| {
        if !replaced && event == "published" && name.ends_with(".json") {
            fs::rename(
                destination.join("objects"),
                destination.join("moved-objects"),
            )
            .unwrap();
            symlink(&outside, destination.join("objects")).unwrap();
            replaced = true;
        }
        Ok(())
    });
    assert!(replaced && result.is_err());
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    assert!(!destination.join("root.json").exists());
}

#[test]
fn generic_export_and_import_retain_identity_and_existing_destination_behavior() {
    let f = Fixture::new();
    let fresh = f.base.join("fresh");
    let generic = f.base.join("generic");
    let result = f.export(&fresh, &mut |_, _| Ok(())).unwrap();
    let request = json!({"operation":"export-copy", "destination":generic});
    assert_eq!(
        copy::batch(&request, &f.source, b"public root", &f.objects, &f.archives).unwrap(),
        result
    );
    assert_eq!(
        copy::batch(&request, &f.source, b"public root", &f.objects, &f.archives).unwrap(),
        result
    );
    for (family, suffix, ids) in [
        ("objects", "json", &f.objects),
        ("archives", "zip", &f.archives),
    ] {
        assert_eq!(
            fs::metadata(fresh.join(family)).unwrap().mode(),
            fs::metadata(generic.join(family)).unwrap().mode()
        );
        for id in ids {
            let path = Path::new(family).join(format!("{id}.{suffix}"));
            assert_eq!(
                fs::read(fresh.join(&path)).unwrap(),
                fs::read(generic.join(&path)).unwrap()
            );
        }
    }
    assert_eq!(
        fs::read(fresh.join("root.json")).unwrap(),
        fs::read(generic.join("root.json")).unwrap()
    );
    let cache = f.base.join("cache");
    fs::create_dir(&cache).unwrap();
    let request = json!({"operation":"import-copy", "destination":cache});
    copy::batch(&request, &fresh, b"public root", &f.objects, &f.archives).unwrap();
    copy::batch(&request, &fresh, b"public root", &f.objects, &f.archives).unwrap();
    assert!(!cache.join("root.json").exists());
    let id = f.objects.first().unwrap();
    fs::write(cache.join("objects").join(format!("{id}.json")), b"corrupt").unwrap();
    assert!(copy::batch(&request, &fresh, b"public root", &f.objects, &f.archives).is_err());
}

#[test]
fn late_directory_replacement_rolls_back_root_through_the_held_descriptor() {
    for replace_data in [false, true] {
        let f = Fixture::new();
        let destination = f.base.join("export");
        let moved = f.base.join("moved");
        let outside = f.base.join("outside");
        fs::create_dir(&outside).unwrap();
        let mut replaced = false;
        let result = f.export(&destination, &mut |event, name| {
            if !replaced && event == "file_synced" && name == "root.json" {
                let path = if replace_data {
                    destination.join("objects")
                } else {
                    destination.clone()
                };
                fs::rename(&path, &moved).unwrap();
                symlink(&outside, &path).unwrap();
                replaced = true;
            }
            Ok(())
        });
        assert!(replaced && result.is_err());
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
        let root_directory = if replace_data { destination } else { moved };
        assert!(!root_directory.join("root.json").exists());
    }
}

#[test]
fn substituted_temporary_inode_is_rejected_before_publication() {
    for symlink_leaf in [false, true] {
        let f = Fixture::new();
        let destination = f.base.join("export");
        let private = f.base.join("private");
        fs::write(&private, b"private credential sentinel").unwrap();
        let mut replaced = false;
        let result = f.export(&destination, &mut |event, name| {
            if !replaced && event == "file_synced" && name.ends_with(".json") {
                let temporary = fs::read_dir(destination.join("objects"))
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".transfer-")
                    })
                    .unwrap();
                fs::remove_file(&temporary).unwrap();
                if symlink_leaf {
                    symlink(&private, &temporary).unwrap();
                } else {
                    fs::write(&temporary, b"private credential sentinel").unwrap();
                }
                replaced = true;
            }
            Ok(())
        });
        assert!(replaced && result.is_err());
        assert!(!destination.join("root.json").exists());
        let foreign = fs::read_dir(destination.join("objects"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(foreign.len(), 1);
        assert!(foreign[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".transfer-"));
        assert_eq!(
            fs::read(&foreign[0]).unwrap(),
            b"private credential sentinel"
        );
        assert_eq!(fs::read(&private).unwrap(), b"private credential sentinel");
    }
}

#[test]
fn rollback_preserves_observed_foreign_data_and_root_entries() {
    for replace_root in [false, true] {
        let f = Fixture::new();
        let destination = f.base.join("export");
        let mut foreign_path = None;
        let result = f.export(&destination, &mut |event, name| {
            let trigger = if replace_root {
                event == "root_directory_synced"
            } else {
                event == "published" && name.ends_with(".json")
            };
            if foreign_path.is_none() && trigger {
                let path = if replace_root {
                    destination.join("root.json")
                } else {
                    destination.join("objects").join(name)
                };
                fs::remove_file(&path).unwrap();
                fs::write(&path, b"foreign sentinel").unwrap();
                foreign_path = Some(path);
                if replace_root {
                    return Err("injected_final_barrier_error".into());
                }
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(foreign_path.unwrap()).unwrap(),
            b"foreign sentinel"
        );
        if !replace_root {
            assert!(!destination.join("root.json").exists());
        }
    }
}
