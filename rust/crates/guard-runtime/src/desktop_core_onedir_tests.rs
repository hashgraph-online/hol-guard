use super::*;

use std::io;

use crate::native_install_verdict::Ran;

const REGULAR: u32 = 0o100644;
const EXECUTABLE: u32 = 0o100755;
const LINK: u32 = 0o120777;

struct Member {
    name: Vec<u8>,
    data: Vec<u8>,
    mode: u32,
}

fn file(name: &str, data: &[u8]) -> Member {
    Member {
        name: name.as_bytes().to_vec(),
        data: data.to_vec(),
        mode: REGULAR,
    }
}

fn link(name: &str, target: &[u8]) -> Member {
    Member {
        name: name.as_bytes().to_vec(),
        data: target.to_vec(),
        mode: LINK,
    }
}

/// The members of a sealed onedir build with framework links.
fn sealed() -> Vec<Member> {
    vec![
        Member {
            mode: EXECUTABLE,
            ..file(LAUNCHER, b"launcher")
        },
        file("hol-guard/Info.plist", b"<plist/>"),
        file("hol-guard/_CodeSignature/CodeResources", b"<resources/>"),
        file(
            "hol-guard/_internal/Python.framework/Versions/3.12/Python",
            b"python",
        ),
        link(
            "hol-guard/_internal/Python.framework/Versions/Current",
            b"3.12",
        ),
        link(
            "hol-guard/_internal/Python.framework/Python",
            b"Versions/Current/Python",
        ),
    ]
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A stored archive written field by field, so a test controls every name,
/// mode and link target the way a hostile archive could.
fn zipped(members: &[Member]) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut central = Vec::new();
    for member in members {
        let offset = u32::try_from(archive.len()).expect("small archive");
        let crc = crc32(&member.data);
        let size = u32::try_from(member.data.len()).expect("small member");
        let name_length = u16::try_from(member.name.len()).expect("short name");
        // Version, UTF-8 flag, stored, time and date.
        let common = [20u16, 0x0800, 0, 0, 0x21];
        archive.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        for field in common {
            archive.extend_from_slice(&field.to_le_bytes());
        }
        for field in [crc, size, size] {
            archive.extend_from_slice(&field.to_le_bytes());
        }
        archive.extend_from_slice(&name_length.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&member.name);
        archive.extend_from_slice(&member.data);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        // Made by Unix, so the mode in the external attributes is read.
        central.extend_from_slice(&0x031eu16.to_le_bytes());
        for field in common {
            central.extend_from_slice(&field.to_le_bytes());
        }
        for field in [crc, size, size] {
            central.extend_from_slice(&field.to_le_bytes());
        }
        central.extend_from_slice(&name_length.to_le_bytes());
        // Extra and comment lengths, disk and internal attributes.
        central.extend_from_slice(&[0u8; 8]);
        central.extend_from_slice(&(member.mode << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(&member.name);
    }
    let count = u16::try_from(members.len()).expect("few members");
    let central_offset = u32::try_from(archive.len()).expect("small archive");
    let central_size = u32::try_from(central.len()).expect("small directory");
    archive.extend_from_slice(&central);
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&[0u8; 4]);
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&central_size.to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive
}

fn write_archive(directory: &Path, members: &[Member]) -> PathBuf {
    let archive = directory.join("core.zip");
    fs::write(&archive, zipped(members)).expect("archive");
    archive
}

fn admits(members: Vec<Member>) -> bool {
    let directory = tempfile::tempdir().expect("tempdir");
    admitted(&write_archive(directory.path(), &members)).is_some()
}

fn with(extra: Vec<Member>) -> Vec<Member> {
    let mut members = sealed();
    members.extend(extra);
    members
}

#[test]
fn a_sealed_archive_with_framework_links_is_admitted() {
    assert!(admits(sealed()));
    let longest = vec![b'x'; LINK_TARGET_MAX];
    assert!(admits(with(vec![link(
        "hol-guard/_internal/long",
        &longest
    )])));
}

#[test]
fn unsafe_member_names_are_refused() {
    for name in [
        "/abs/path",
        "hol-guard/../escape",
        "../escape",
        "sibling/x",
        "hol-guardian/x",
        "hol-guard/._launcher",
        "hol-guard/_internal/._x/",
        "hol-guard/__MACOSX/x",
        "hol-guard/_internal/./link/x",
        "hol-guard/./x",
        "hol-guard//x",
    ] {
        assert!(!admits(with(vec![file(name, b"x")])), "{name}");
    }
}

#[test]
fn unsafe_link_targets_are_refused() {
    let oversized = vec![b'x'; LINK_TARGET_MAX + 1];
    let targets: [&[u8]; 8] = [
        b"/abs/path",
        b"../../x",
        b"..",
        b"../../../etc/passwd",
        b"",
        &oversized,
        b"a\0b",
        b"\xff\xfe",
    ];
    for target in targets {
        let members = with(vec![link("hol-guard/_internal/link", target)]);
        assert!(!admits(members), "{target:?}");
    }
}

#[test]
fn members_beneath_a_link_are_refused() {
    for nested in [
        "hol-guard/_internal/lib/x",
        "hol-guard/_internal/LIB/x",
        "hol-guard/_internal/lib/deeper/x",
    ] {
        let members = with(vec![
            link("hol-guard/_internal/lib", b"Python.framework"),
            file(nested, b"x"),
        ]);
        assert!(!admits(members), "{nested}");
    }
}

#[test]
fn members_that_fold_to_one_name_are_refused() {
    for (first, second) in [
        ("hol-guard/_internal/a", "hol-guard/_internal/A"),
        ("hol-guard/_internal/\u{e9}", "hol-guard/_internal/e\u{301}"),
        ("hol-guard/_internal/a", "hol-guard/_internal/a"),
        ("hol-guard/_internal/d", "hol-guard/_internal/d/"),
    ] {
        let members = with(vec![file(first, b"1"), file(second, b"2")]);
        assert!(!admits(members), "{first} and {second}");
    }
}

#[test]
fn the_anchors_must_be_regular_members() {
    for anchor in REQUIRED_MEMBERS {
        assert!(!admits(missing_anchor(anchor)), "{anchor} missing");
        let mut linked = missing_anchor(anchor);
        linked.push(link(anchor, b"_internal/Python.framework/Python"));
        assert!(!admits(linked), "{anchor} linked");
    }
    let without_internal: Vec<Member> = sealed()
        .into_iter()
        .filter(|member| !member.name.starts_with(INTERNAL_PREFIX.as_bytes()))
        .collect();
    assert!(!admits(without_internal));
}

fn missing_anchor(anchor: &str) -> Vec<Member> {
    sealed()
        .into_iter()
        .filter(|member| member.name != anchor.as_bytes())
        .collect()
}

#[test]
fn an_unreadable_archive_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let archive = directory.path().join("core.zip");
    fs::write(&archive, b"not a zip").expect("archive");
    assert!(admitted(&archive).is_none());
    assert!(admitted(&directory.path().join("missing.zip")).is_none());
}

fn on_disk(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let archive = directory.path().join("core.zip");
    fs::write(&archive, bytes).expect("archive");
    (directory, archive)
}

fn recorded(bytes: &[u8]) -> Option<u64> {
    let (_directory, archive) = on_disk(bytes);
    recorded_entries(&mut fs::File::open(&archive).expect("open"))
}

fn admits_bytes(bytes: &[u8]) -> bool {
    let (_directory, archive) = on_disk(bytes);
    admitted(&archive).is_some()
}

/// `archive` with its end record deferring, through a Zip64 locator, to a
/// Zip64 end record that declares `total` entries.
fn zip64(archive: &[u8], total: u64) -> Vec<u8> {
    let end = archive.len() - 22;
    let field = |at: usize| {
        u64::from(u32::from_le_bytes(
            archive[end + at..end + at + 4].try_into().expect("field"),
        ))
    };
    let (central_size, central_offset) = (field(12), field(16));
    let mut out = archive[..end].to_vec();
    let record_offset = out.len() as u64;
    out.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
    out.extend_from_slice(&44u64.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    // This disk and the central directory's disk.
    out.extend_from_slice(&[0u8; 8]);
    for value in [total, total, central_size, central_offset] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&record_offset.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    let mut tail = archive[end..].to_vec();
    tail[8..12].copy_from_slice(&[0xff; 4]);
    out.extend_from_slice(&tail);
    out
}

#[test]
fn a_repeated_member_name_is_refused() {
    let members = with(vec![
        file("hol-guard/_internal/twice", b"a"),
        file("hol-guard/_internal/twice", b"b"),
    ]);
    let count = members.len() as u64;
    let bytes = zipped(&members);
    assert_eq!(recorded(&bytes), Some(count));
    // The refusal rests on the reader listing a repeated name once.
    if let Ok(reader) = ZipArchive::new(io::Cursor::new(bytes.clone())) {
        assert!((reader.len() as u64) < count);
    }
    assert!(!admits_bytes(&bytes));
}

#[test]
fn an_end_record_count_that_disagrees_is_refused() {
    let mut bytes = zipped(&sealed());
    let end = bytes.len() - 22;
    let count = u16::try_from(sealed().len()).expect("few members") + 1;
    bytes[end + 10..end + 12].copy_from_slice(&count.to_le_bytes());
    assert_eq!(recorded(&bytes), Some(u64::from(count)));
    assert!(!admits_bytes(&bytes));
}

#[test]
fn a_zip64_end_record_declares_the_count() {
    let plain = zipped(&sealed());
    let count = sealed().len() as u64;
    assert_eq!(recorded(&zip64(&plain, count)), Some(count));
    assert_eq!(recorded(&zip64(&plain, count + 1)), Some(count + 1));
    assert!(!admits_bytes(&zip64(&plain, count + 1)));
    let mut unlocated = zip64(&plain, count);
    let locator = unlocated.len() - 22 - 20;
    unlocated[locator] ^= 0xff;
    assert_eq!(recorded(&unlocated), None);
}

/// Records each `ditto` call and, when it succeeds, lays out a tree in the
/// destination as the extraction would.
struct FakeDitto {
    success: bool,
    materialize: fn(&Path),
    calls: Vec<(String, Vec<String>)>,
}

impl FakeDitto {
    fn new(success: bool, materialize: fn(&Path)) -> Self {
        Self {
            success,
            materialize,
            calls: Vec::new(),
        }
    }
}

impl Runner for FakeDitto {
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran> {
        self.calls
            .push((invocation.program.clone(), invocation.arguments.clone()));
        if self.success {
            (self.materialize)(Path::new(invocation.arguments.last().expect("a path")));
        }
        Ok(Ran {
            success: self.success,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}

fn request(directory: &Path, file_count: u64) -> Request {
    let destination = directory.join("tree");
    fs::create_dir_all(&destination).expect("destination");
    Request {
        schema: SCHEMA.to_owned(),
        archive: directory.join("core.zip").to_string_lossy().into_owned(),
        destination: destination.to_string_lossy().into_owned(),
        file_count,
    }
}

fn unpacked(answer: Result<Value, String>) -> bool {
    answer.expect("answer")["unpacked"] == json!(true)
}

#[test]
fn requests_are_validated() {
    let directory = tempfile::tempdir().expect("tempdir");
    let base = json!({
        "schema": SCHEMA,
        "archive": directory.path().join("core.zip"),
        "destination": directory.path().join("tree"),
        "file_count": 6,
    });
    let mut cases = Vec::new();
    for (field, value) in [
        ("schema", json!("desktop-core-onedir.v0")),
        ("archive", json!("core.zip")),
        ("destination", json!("tree")),
        ("file_count", json!(-1)),
        ("unknown", json!(true)),
    ] {
        let mut case = base.clone();
        case[field] = value;
        cases.push(case);
    }
    let mut missing = base.clone();
    missing
        .as_object_mut()
        .expect("object")
        .remove("file_count");
    cases.push(missing);
    for case in cases {
        assert_eq!(
            run_command(case.to_string().as_bytes()).expect_err("refused"),
            "desktop_core_onedir_request_invalid",
            "{case}"
        );
    }
    let oversized = vec![b' '; usize::try_from(MAX_REQUEST_BYTES).expect("fits") + 1];
    assert_eq!(
        run_command(oversized.as_slice()).expect_err("refused"),
        "desktop_core_onedir_request_too_large"
    );
}

#[test]
fn a_refused_archive_is_never_extracted() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_archive(directory.path(), &with(vec![file("sibling/x", b"x")]));
    let mut runner = FakeDitto::new(true, |_| {});
    assert!(!unpacked(answer(
        &request(directory.path(), 6),
        &mut runner
    )));
    assert!(runner.calls.is_empty());
}

#[test]
fn a_failed_extraction_is_not_unpacked() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_archive(directory.path(), &sealed());
    let mut runner = FakeDitto::new(false, |_| {});
    assert!(!unpacked(answer(
        &request(directory.path(), 6),
        &mut runner
    )));
    assert_eq!(runner.calls.len(), 1);
}

#[cfg(unix)]
fn materialize_sealed(destination: &Path) {
    use std::os::unix::fs::symlink;
    let tree = destination.join(TREE_ROOT);
    let versions = tree.join("_internal/Python.framework/Versions");
    fs::create_dir_all(versions.join("3.12")).expect("framework");
    fs::create_dir_all(tree.join("_CodeSignature")).expect("signature");
    fs::write(tree.join("hol-guard"), b"launcher").expect("launcher");
    fs::write(tree.join("Info.plist"), b"<plist/>").expect("plist");
    fs::write(tree.join("_CodeSignature/CodeResources"), b"<resources/>").expect("resources");
    fs::write(versions.join("3.12/Python"), b"python").expect("python");
    symlink("3.12", versions.join("Current")).expect("current");
    symlink(
        "Versions/Current/Python",
        tree.join("_internal/Python.framework/Python"),
    )
    .expect("python link");
}

#[cfg(unix)]
#[test]
fn an_admitted_archive_unpacks_when_the_tree_matches() {
    let directory = tempfile::tempdir().expect("tempdir");
    let archive = write_archive(directory.path(), &sealed());
    let mut runner = FakeDitto::new(true, materialize_sealed);
    let request = request(directory.path(), 6);
    assert!(unpacked(answer(&request, &mut runner)));
    assert_eq!(
        runner.calls,
        [(
            DITTO.to_owned(),
            vec![
                "-x".to_owned(),
                "-k".to_owned(),
                archive.to_string_lossy().into_owned(),
                request.destination.clone(),
            ]
        )]
    );
    let mut runner = FakeDitto::new(true, materialize_sealed);
    let miscounted = self::request(&directory.path().join("again"), 5);
    fs::copy(&archive, directory.path().join("again/core.zip")).expect("copy");
    assert!(!unpacked(answer(&miscounted, &mut runner)));
}

#[cfg(unix)]
#[test]
fn a_linked_launcher_is_not_unpacked() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_archive(directory.path(), &sealed());
    let mut runner = FakeDitto::new(true, |destination| {
        materialize_sealed(destination);
        let launcher = destination.join(LAUNCHER);
        fs::remove_file(&launcher).expect("remove launcher");
        std::os::unix::fs::symlink("Info.plist", &launcher).expect("link launcher");
    });
    assert!(!unpacked(answer(
        &request(directory.path(), 6),
        &mut runner
    )));
}

#[cfg(unix)]
#[test]
fn extracted_links_are_counted_once_and_must_stay_in_the_tree() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().expect("tempdir");
    let extracted = directory.path().join("tree");
    materialize_sealed(&extracted);
    assert_eq!(tree_file_count(&extracted), Some(6));
    let internal = extracted.join("hol-guard/_internal");
    symlink("Python.framework", internal.join("frameworks")).expect("directory link");
    assert_eq!(
        tree_file_count(&extracted),
        Some(7),
        "a linked directory counts once and is not descended"
    );
    let outside = directory.path().join("outside");
    fs::create_dir_all(&outside).expect("outside");
    let refused: [(&str, PathBuf); 4] = [
        ("broken", PathBuf::from("missing")),
        ("absolute", internal.join("frameworks")),
        ("escaping", PathBuf::from("../../../outside")),
        ("root", PathBuf::from("..")),
    ];
    for (name, target) in refused {
        let entry = internal.join(name);
        symlink(&target, &entry).expect("link");
        assert_eq!(tree_file_count(&extracted), None, "{name}");
        fs::remove_file(&entry).expect("remove link");
    }
    fs::write(extracted.join("stray"), b"x").expect("stray");
    assert_eq!(
        tree_file_count(&extracted),
        None,
        "an entry beside the tree"
    );
}

#[test]
fn ditto_unpacks_framework_links_as_links() {
    if !Path::new(DITTO).is_file() {
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    write_archive(directory.path(), &sealed());
    let request = request(directory.path(), 6);
    assert!(unpacked(answer(&request, &mut SystemRunner)));
    let current = Path::new(&request.destination)
        .join("hol-guard/_internal/Python.framework/Versions/Current");
    assert!(fs::symlink_metadata(current)
        .expect("current")
        .file_type()
        .is_symlink());
}
