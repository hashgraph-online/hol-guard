use super::*;

fn pe_image(imports: usize, name_bytes: usize) -> Vec<u8> {
    let optional = 0x80 + 24;
    let descriptors = 0x400;
    let table_bytes = (imports + 1) * 20;
    let mut image = vec![0; descriptors + table_bytes];
    image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    image[0x94..0x96].copy_from_slice(&224u16.to_le_bytes());
    image[optional..optional + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    let directory = optional + 96 + 8;
    image[directory..directory + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    image[directory + 4..directory + 8].copy_from_slice(&(table_bytes as u32).to_le_bytes());
    for index in 0..imports {
        let mut name = format!("module{index:04}");
        name.extend(std::iter::repeat_n(
            'x',
            name_bytes.saturating_sub(name.len() + 4),
        ));
        name.push_str(".dll");
        let address = 0x1000 + image.len() - descriptors;
        let at = descriptors + index * 20 + 12;
        image[at..at + 4].copy_from_slice(&(address as u32).to_le_bytes());
        image.extend_from_slice(name.as_bytes());
        image.push(0);
    }
    let section = optional + 224;
    let raw_size = (image.len() - descriptors) as u32;
    image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    image[section + 16..section + 20].copy_from_slice(&raw_size.to_le_bytes());
    image[section + 20..section + 24].copy_from_slice(&(descriptors as u32).to_le_bytes());
    image
}

#[test]
fn pe_import_descriptor_and_name_budgets_reject_before_materialization() {
    let library = Path::new("fixture.exe");
    let admitted = pe(&pe_image(1024, 32), library).expect("bounded import table");
    assert!(admitted.last().unwrap().name.starts_with("module1023"));
    assert!(pe(&pe_image(1025, 32), library).is_err());
    assert_eq!(pe(&pe_image(1, 255), library).unwrap()[0].name.len(), 255);
    assert!(pe(&pe_image(1, 256), library).is_err());
}

const ELF_DYNAMIC_OFFSET: usize = 0x100;
const ELF_STRING_TABLE: usize = 0x200;

fn elf_image(strings: &[u8], entries: &[(u64, u64)]) -> Vec<u8> {
    let dynamic_size = (entries.len() + 3) * 16;
    assert!(ELF_DYNAMIC_OFFSET + dynamic_size <= ELF_STRING_TABLE);
    let mut image = vec![0; ELF_STRING_TABLE + strings.len()];
    image[..6].copy_from_slice(b"\x7fELF\x02\x01");
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&2u16.to_le_bytes());
    for (index, (kind, offset, address, length)) in [
        (1u32, 0u64, 0x400000u64, image.len() as u64),
        (2, ELF_DYNAMIC_OFFSET as u64, 0, dynamic_size as u64),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + index * 56;
        image[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        image[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
        image[at + 16..at + 24].copy_from_slice(&address.to_le_bytes());
        image[at + 32..at + 40].copy_from_slice(&length.to_le_bytes());
    }
    for (index, (tag, value)) in [
        (5u64, 0x400000 + ELF_STRING_TABLE as u64),
        (10, strings.len() as u64),
    ]
    .into_iter()
    .chain(entries.iter().copied())
    .chain([(0, 0)])
    .enumerate()
    {
        let at = ELF_DYNAMIC_OFFSET + index * 16;
        image[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        image[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    image[ELF_STRING_TABLE..].copy_from_slice(strings);
    image
}

#[test]
fn elf_dynamic_strings_reject_out_of_table_and_wrapping_offsets() {
    let strings = b"\0libfixture.so\0/declared\0";
    let wrapped_offset = (0u64)
        .wrapping_sub(ELF_STRING_TABLE as u64)
        .wrapping_add(0xc0);
    for tag in [1, 15, 29] {
        for offset in [
            strings.len() as u64,
            strings.len() as u64 + 1,
            u64::MAX,
            wrapped_offset,
        ] {
            let entries = if tag == 1 {
                vec![(1, offset)]
            } else {
                vec![(1, 1), (tag, offset)]
            };
            let mut image = elf_image(strings, &entries);
            // A wrapping lookup used to reach this valid absolute string
            // before the dynamic string table, including in release builds.
            let outside = b"/outside\0";
            image[0xc0..0xc0 + outside.len()].copy_from_slice(outside);
            let error = elf(&image, Path::new("/fixture/app"))
                .err()
                .expect("reject an offset outside DT_STRSZ");
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "dynamic tag {tag}, offset {offset}"
            );
        }
    }
}

#[test]
fn elf_string_table_end_and_terminator_are_bounded_by_dt_strsz() {
    let strings = b"\0libfixture.so\0";
    let valid = elf(&elf_image(strings, &[(1, 1)]), Path::new("/fixture/app")).unwrap();
    assert_eq!(valid[0].name, "libfixture.so");
    for size in [strings.len() as u64 - 1, u64::MAX] {
        let error = elf(
            &elf_image(strings, &[(1, 1), (10, size)]),
            Path::new("/fixture/app"),
        )
        .err()
        .expect("reject truncated or overflowing string table");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[cfg(unix)]
#[test]
fn elf_declared_search_paths_select_the_dependency_instead_of_a_sibling() {
    let temporary = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temporary.path()).unwrap();
    let bin = root.join("bin");
    let declared = root.join("lib");
    std::fs::create_dir(&bin).unwrap();
    std::fs::create_dir(&declared).unwrap();
    let name = "libguard-elf-selection.so";
    std::fs::write(bin.join(name), b"undeclared sibling").unwrap();
    std::fs::write(declared.join(name), b"declared dependency").unwrap();
    let library = bin.join("app");
    let mut strings = format!("\0{name}\0").into_bytes();
    let path_offset = strings.len() as u64;
    strings.extend_from_slice(declared.to_str().unwrap().as_bytes());
    strings.push(0);
    for tag in [15, 29] {
        let imports = elf(
            &elf_image(&strings, &[(1, 1), (tag, path_offset)]),
            &library,
        )
        .unwrap();
        let selected = resolve(&imports[0], None).unwrap().unwrap().0;
        assert_eq!(selected, declared.join(name), "dynamic tag {tag}");
    }
    let strings = format!("\0{name}\0${{ORIGIN}}\0");
    let imports = elf(
        &elf_image(strings.as_bytes(), &[(1, 1), (29, path_offset)]),
        &library,
    )
    .unwrap();
    assert_eq!(
        resolve(&imports[0], None).unwrap().unwrap().0,
        bin.join(name),
        "an explicitly declared ORIGIN still selects the sibling"
    );
}
