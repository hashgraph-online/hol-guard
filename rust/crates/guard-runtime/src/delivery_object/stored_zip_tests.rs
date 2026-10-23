use super::*;

fn put16(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend(u16::try_from(value).unwrap().to_le_bytes());
}

fn put32(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend(u32::try_from(value).unwrap().to_le_bytes());
}

/// A stored archive of `members`, laid out the way the delivery builder writes
/// one: local header and data per member, then the central directory.
pub(crate) fn build(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut central = Vec::new();
    for (name, data) in members {
        let header = body.len();
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let sum = usize::try_from(crc.sum()).unwrap();
        body.extend(b"PK\x03\x04");
        put16(&mut body, 20);
        put16(&mut body, 0);
        put16(&mut body, 0);
        put32(&mut body, 0);
        put32(&mut body, sum);
        put32(&mut body, data.len());
        put32(&mut body, data.len());
        put16(&mut body, name.len());
        put16(&mut body, 0);
        body.extend(name.as_bytes());
        body.extend(*data);
        central.extend(b"PK\x01\x02");
        put16(&mut central, 20);
        put16(&mut central, 20);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put32(&mut central, 0);
        put32(&mut central, sum);
        put32(&mut central, data.len());
        put32(&mut central, data.len());
        put16(&mut central, name.len());
        put16(&mut central, 0);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put32(&mut central, 0o100644 << 16);
        put32(&mut central, header);
        central.extend(name.as_bytes());
    }
    let start = body.len();
    body.extend(&central);
    body.extend(b"PK\x05\x06");
    put16(&mut body, 0);
    put16(&mut body, 0);
    put16(&mut body, members.len());
    put16(&mut body, members.len());
    put32(&mut body, central.len());
    put32(&mut body, start);
    put16(&mut body, 0);
    body
}

#[test]
fn reads_a_stored_member() {
    let bytes = build(&[("a.json", b"one"), ("b.json", b"second")]);
    let tail = end(&bytes).unwrap();
    assert_eq!((tail.count, tail.tail), (2, bytes.len() - 22));
    let first = entry(&bytes, tail.start).unwrap();
    assert_eq!((first.name, first.size, first.packed), ("a.json", 3, 3));
    assert!(first.regular() && first.extra == 0 && first.comment == 0 && first.disk == 0);
    let second = entry(&bytes, first.next).unwrap();
    assert_eq!(second.name, "b.json");
    assert_eq!(second.next, tail.tail);
    let range = data(&bytes, &second, tail.start).unwrap();
    assert_eq!(&bytes[range], b"second");
}

#[test]
fn end_rejects_a_changed_terminator() {
    let bytes = build(&[("a.json", b"one")]);
    let tail = bytes.len() - 22;
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(end(&trailing).is_none());
    for (at, value) in [(4, 1u8), (6, 1), (8, 2), (10, 2), (20, 1)] {
        let mut changed = bytes.clone();
        changed[tail + at] = value;
        assert!(end(&changed).is_none(), "offset {at}");
    }
    let mut empty = bytes.clone();
    empty[tail + 8] = 0;
    empty[tail + 10] = 0;
    assert!(end(&empty).is_none());
    let mut gap = bytes.clone();
    gap[tail + 16] = gap[tail + 16].wrapping_sub(1);
    assert!(end(&gap).is_none());
    assert!(end(&bytes[..10]).is_none());
}

#[test]
fn entry_rejects_a_truncated_or_unmarked_record() {
    let bytes = build(&[("a.json", b"one")]);
    let start = end(&bytes).unwrap().start;
    assert!(entry(&bytes, bytes.len()).is_none());
    assert!(entry(&bytes[..start + 40], start).is_none());
    let mut unmarked = bytes.clone();
    unmarked[start] = b'X';
    assert!(entry(&unmarked, start).is_none());
    let mut long_name = bytes.clone();
    long_name[start + 28] = 0xff;
    assert!(entry(&long_name, start).is_none());
}

#[test]
fn data_requires_agreement_between_central_and_local_records() {
    let bytes = build(&[("a.json", b"one")]);
    let tail = end(&bytes).unwrap();
    let row = entry(&bytes, tail.start).unwrap();
    assert!(data(&bytes, &row, tail.start).is_some());
    // flags, method, crc, packed, size, name length, extra length, name.
    for at in [6usize, 8, 14, 18, 22, 26, 28, 30] {
        let mut changed = bytes.clone();
        changed[row.header + at] ^= 1;
        assert!(data(&changed, &row, tail.start).is_none(), "offset {at}");
    }
    let mut unmarked = bytes.clone();
    unmarked[row.header] = b'X';
    assert!(data(&unmarked, &row, tail.start).is_none());
}

#[test]
fn data_rejects_changed_bytes_and_overlong_ranges() {
    let bytes = build(&[("a.json", b"one")]);
    let tail = end(&bytes).unwrap();
    let row = entry(&bytes, tail.start).unwrap();
    let range = data(&bytes, &row, tail.start).unwrap();
    let mut changed = bytes.clone();
    changed[range.start] ^= 1;
    assert!(data(&changed, &row, tail.start).is_none());
    assert!(data(&bytes, &row, range.end - 1).is_none());
    assert!(data(&bytes[..range.end - 1], &row, tail.start).is_none());
}
