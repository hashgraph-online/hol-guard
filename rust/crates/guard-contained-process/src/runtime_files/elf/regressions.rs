use super::*;
use std::cell::Cell;

fn image(strings: &[u8], entries: &[(u64, u64)]) -> Vec<u8> {
    let dynamic = 0x100;
    let length = (entries.len() + 3) * 16;
    let strtab = dynamic + length;
    let mut image = vec![0; strtab + strings.len()];
    image[..6].copy_from_slice(b"\x7fELF\x02\x01");
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&2u16.to_le_bytes());
    for (index, (kind, offset, address, size)) in [
        (1u32, 0u64, 0x400000u64, image.len() as u64),
        (2, dynamic as u64, 0, length as u64),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + index * 56;
        image[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        image[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
        image[at + 16..at + 24].copy_from_slice(&address.to_le_bytes());
        image[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
    }
    for (index, (tag, value)) in [(5, 0x400000 + strtab as u64), (10, strings.len() as u64)]
        .into_iter()
        .chain(entries.iter().copied())
        .chain([(0, 0)])
        .enumerate()
    {
        let at = dynamic + index * 16;
        image[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        image[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    image[strtab..].copy_from_slice(strings);
    image
}

#[test]
fn invalid_program_headers_and_oversized_dynamic_tables_fail_closed() {
    let library = Path::new("/app/bin/tool");
    for offset in [u64::MAX, u64::MAX - 32, 0x100000] {
        let mut bytes = image(b"\0libA.so\0", &[(1, 1)]);
        bytes[32..40].copy_from_slice(&offset.to_le_bytes());
        assert!(elf(&bytes, library).is_err());
        assert!(elf_interpreter(&bytes).is_err());
    }
    assert!(elf(
        &image(b"\0libA.so\0", &vec![(1, 1); MAX_IMPORTS + 1]),
        library
    )
    .is_err());
    assert!(elf(
        &image(b"\0libA.so\0", &vec![(7, 0); MAX_DYNAMIC_ENTRIES]),
        library
    )
    .is_err());
    let admitted = elf(&image(b"\0libA.so\0", &vec![(1, 1); MAX_IMPORTS]), library).unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &admitted[0].search,
        &admitted[MAX_IMPORTS - 1].search
    ));
}

#[test]
fn parser_checks_the_original_request_window_inside_dynamic_table() {
    let checks = Cell::new(0usize);
    let check = || {
        checks.set(checks.get() + 1);
        if checks.get() == 8 {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(())
        }
    };
    let error = elf_with_context(
        &image(b"\0libA.so\0", &vec![(1, 1); 64]),
        Path::new("/app/tool"),
        &[],
        &check,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(checks.get(), 8);
}

#[test]
fn search_path_count_and_expansion_are_bounded_before_import_allocation() {
    let mut strings = b"\0libA.so\0".to_vec();
    let offset = strings.len() as u64;
    strings.extend(
        (0..MAX_SEARCH_PATHS + 1)
            .map(|i| format!("/path{i}"))
            .collect::<Vec<_>>()
            .join(":")
            .as_bytes(),
    );
    strings.push(0);
    assert!(elf(
        &image(&strings, &[(1, 1), (15, offset)]),
        Path::new("/app/tool")
    )
    .is_err());
    let value = "$ORIGIN/".repeat(200);
    assert!(search_paths(
        &value,
        Path::new(&format!("/{}", "x".repeat(1024))),
        &|| Ok(())
    )
    .is_err());
}

#[test]
fn inherited_rpath_reaches_grandchildren_but_runpath_does_not() {
    let strings = b"\0libA.so\0/app/lib\0";
    let offset = 9;
    for tag in [15, 29] {
        let parent = elf(
            &image(strings, &[(1, 1), (tag, offset)]),
            Path::new("/app/bin/tool"),
        )
        .unwrap();
        assert_eq!(parent[0].search[0], PathBuf::from("/app/lib"));
        let child = elf_with_context(
            &image(b"\0libB.so\0", &[(1, 1)]),
            Path::new("/app/lib/libA.so"),
            &parent[0].inherited_rpath,
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(
            child[0].search.contains(&PathBuf::from("/app/lib")),
            tag == 15
        );
    }
    let own = elf_with_context(
        &image(b"\0libB.so\0/own/runpath\0", &[(1, 1), (29, 9)]),
        Path::new("/app/lib/libA.so"),
        &[PathBuf::from("/inherited")],
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(own[0].search[0], PathBuf::from("/own/runpath"));
    assert!(!own[0].search.contains(&PathBuf::from("/inherited")));
    assert_eq!(
        own[0].inherited_rpath.as_ref(),
        &[PathBuf::from("/inherited")]
    );
}

#[cfg(unix)]
#[test]
fn full_capture_retains_a_transitive_rpath_dependency() {
    use crate::bound_fs;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let lib = root.join("lib");
    std::fs::create_dir(&lib).unwrap();
    let mut strings = b"\0libA.so\0".to_vec();
    strings.extend(lib.to_string_lossy().as_bytes());
    strings.push(0);
    let executable = root.join("tool");
    std::fs::write(lib.join("libA.so"), image(b"\0libB.so\0", &[(1, 1)])).unwrap();
    std::fs::write(lib.join("libB.so"), image(b"\0", &[])).unwrap();
    for tag in [15, 29] {
        std::fs::write(&executable, image(&strings, &[(1, 1), (tag, 9)])).unwrap();
        let mut file = bound_fs::open_executable(&executable).unwrap();
        let digest = bound_fs::digest_executable(&mut file, 1 << 20).unwrap();
        let captured = super::super::capture(
            &executable,
            &digest,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
        );
        if tag == 15 {
            let captured = captured.unwrap();
            assert_eq!(captured.files.len(), 2);
            assert!(captured
                .files
                .iter()
                .any(|file| file.names.contains("libB.so")));
        } else {
            assert!(captured.is_err());
        }
    }
}
