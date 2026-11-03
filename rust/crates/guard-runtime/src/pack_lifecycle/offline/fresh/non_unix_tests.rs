use super::*;
use std::fs;

#[test]
fn fresh_non_unix_export_preserves_native_exclusive_creation() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    let source = base.join("source");
    let destination = base.join("export");
    let object = b"public object";
    let archive = b"public archive";
    let root = b"public root";
    let object_id = hash(object);
    let archive_id = hash(archive);
    let objects = BTreeSet::from([object_id.clone()]);
    let archives = BTreeSet::from([archive_id.clone()]);
    let object_path = Path::new("objects").join(format!("{object_id}.json"));
    let archive_path = Path::new("archives").join(format!("{archive_id}.zip"));
    fs::create_dir_all(source.join("objects")).unwrap();
    fs::create_dir(source.join("archives")).unwrap();
    fs::write(source.join(&object_path), object).unwrap();
    fs::write(source.join(&archive_path), archive).unwrap();
    let request = json!({"operation":"export-fresh-copy","destination":destination});

    assert_eq!(
        batch(&request, &source, root, &objects, &archives).unwrap(),
        json!({"complete":true,"files":2,"root":hash(root)})
    );
    assert_eq!(fs::read(destination.join("root.json")).unwrap(), root);
    assert_eq!(fs::read(destination.join(&object_path)).unwrap(), object);
    assert_eq!(fs::read(destination.join(&archive_path)).unwrap(), archive);

    // Native creation rejects an existing export before touching any member.
    fs::write(
        destination.join(&object_path),
        b"foreign destination sentinel",
    )
    .unwrap();
    assert!(batch(&request, &source, root, &objects, &archives).is_err());
    assert_eq!(
        fs::read(destination.join(&object_path)).unwrap(),
        b"foreign destination sentinel"
    );
    assert_eq!(fs::read(destination.join("root.json")).unwrap(), root);

    let partial = base.join("partial");
    fs::create_dir(&partial).unwrap();
    let request = json!({"operation":"export-fresh-copy","destination":partial});
    assert!(batch(&request, &source, root, &objects, &archives).is_err());
    assert_eq!(fs::read_dir(partial).unwrap().count(), 0);
}
