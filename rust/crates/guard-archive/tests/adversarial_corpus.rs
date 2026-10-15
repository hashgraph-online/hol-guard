//! Compiled adversarial corpus for the native archive parser: framing
//! (PAX, GNU long names, sparse, header metadata), terminators and gzip.
//! Every input is generated here (no committed binaries). Each row pins the
//! verdict the parser must reach; nothing is ever extracted or executed, so
//! the only observable is the typed outcome.
#![cfg(unix)]

mod common;

use common::*;

#[test]
fn pax_headers() {
    let long_dotdot = pax_header(&pax_record("path", b"../escape"));
    let abs = pax_header(&pax_record("path", b"/etc/cron.d/x"));
    let linkpath = pax_header(&pax_record("linkpath", b"../../etc/passwd"));
    let size_smaller = pax_header(&pax_record("size", b"1"));
    let size_larger = pax_header(&pax_record("size", b"4096"));
    let size_invalid = pax_header(&pax_record("size", b"not-a-number"));
    let size_negative = pax_header(&pax_record("size", b"-5"));
    let dup = |key: &str, first: &[u8], last: &[u8]| {
        pax_header(&[pax_record(key, first), pax_record(key, last)].concat())
    };
    let global = member_with(
        b"pax_global_header",
        b'g',
        &pax_record("path", b"../g"),
        b"",
        Magic::Ustar,
    );
    run(vec![
        (
            "pax path override to ..",
            archive(&[long_dotdot, file("ok", b"x")]),
            SLIP,
        ),
        (
            "pax path override absolute",
            archive(&[abs, file("ok", b"x")]),
            SLIP,
        ),
        (
            "pax linkpath override escapes",
            archive(&[linkpath, symlink("link", "fine")]),
            SLIP,
        ),
        // `size=1` shrinks the member the iterator consumes; the 4 payload
        // bytes left over are parsed as the next header and fail framing.
        (
            "pax size override smaller than payload desyncs",
            archive(&[size_smaller, file("a", &[b'x'; 1024])]),
            INCOMPLETE,
        ),
        (
            "pax size override larger than the archive is truncated",
            archive(&[size_larger, file("a", b"xy")]),
            INCOMPLETE,
        ),
        // An unparsable size is ignored identically by the framing guard and
        // `tar` (the desync oracle would refuse otherwise): the header size
        // frames the member.
        (
            "pax invalid size is ignored",
            archive(&[size_invalid, file("a", b"x")]),
            CLEAN,
        ),
        (
            "pax negative size is ignored",
            archive(&[size_negative, file("a", b"x")]),
            CLEAN,
        ),
        // POSIX and GNU/bsd tar apply the LAST record, `tar` the first. A
        // repeated key has no single meaning, so either order is refused.
        (
            "pax duplicate path, benign first",
            archive(&[dup("path", b"ok", b"../a"), file("a", b"x")]),
            UNSUPPORTED,
        ),
        (
            "pax duplicate path, hostile first",
            archive(&[dup("path", b"../a", b"ok"), file("a", b"x")]),
            UNSUPPORTED,
        ),
        (
            "pax duplicate linkpath, benign first",
            archive(&[dup("linkpath", b"ok", b"../../a"), symlink("l", "t")]),
            UNSUPPORTED,
        ),
        (
            "pax duplicate size",
            archive(&[dup("size", b"1", b"4096"), file("a", b"x")]),
            UNSUPPORTED,
        ),
        (
            "pax record that does not parse",
            archive(&[pax_header(b"zz path=../a\n"), file("a", b"x")]),
            UNSUPPORTED,
        ),
        (
            "pax repeated unrelated key is harmless",
            archive(&[dup("comment", b"a", b"b"), file("a", b"x")]),
            CLEAN,
        ),
        (
            "pax global header entry is unsupported",
            archive(&[global, file("ok", b"x")]),
            UNSUPPORTED,
        ),
        (
            "pax benign override is clean",
            archive(&[
                pax_header(&pax_record("path", b"pkg/readme.txt")),
                file("a", b"x"),
            ]),
            CLEAN,
        ),
    ]);
}

#[test]
fn gnu_long_name_and_link_headers() {
    let long_ok = "d/".repeat(40) + "file.txt";
    run(vec![
        (
            "gnu longname dotdot",
            archive(&[gnu_longname(b"../../etc/x"), file("a", b"x")]),
            SLIP,
        ),
        (
            "gnu longname benign over 100 bytes",
            archive(&[gnu_longname(long_ok.as_bytes()), file("a", b"x")]),
            CLEAN,
        ),
        (
            "gnu longlink escapes",
            archive(&[gnu_longlink(b"../../../etc/passwd"), symlink("l", "short")]),
            SLIP,
        ),
        (
            "double longname is refused",
            archive(&[
                gnu_longname(b"safe/a"),
                gnu_longname(b"../evil"),
                file("a", b"x"),
            ]),
            INCOMPLETE,
        ),
        (
            "longname with no following entry is refused",
            archive(&[gnu_longname(b"../evil")]),
            INCOMPLETE,
        ),
        (
            "longname record with ustar magic is still honored and checked",
            archive(&[
                member_with(b"././@LongLink", b'L', b"../evil\0", b"", Magic::Ustar),
                file("a", b"x"),
            ]),
            SLIP,
        ),
        (
            "longname record with no magic is an unknown member type",
            archive(&[
                member_with(b"././@LongLink", b'L', b"../evil\0", b"", Magic::Old),
                file("a", b"x"),
            ]),
            UNSUPPORTED,
        ),
        (
            "longname length field larger than the archive",
            archive(&[
                header(b"././@LongLink", b'L', 4096, b"", Magic::Gnu).to_vec(),
                b"abc".to_vec(),
            ]),
            INCOMPLETE,
        ),
    ]);
}

#[test]
fn sparse_entries() {
    run(vec![
        (
            "sparse member is unsupported",
            archive(&[sparse_member("s", 0, 0)]),
            UNSUPPORTED,
        ),
        (
            "sparse member with a short chain is unsupported",
            archive(&[sparse_member("s", 3, 0)]),
            UNSUPPORTED,
        ),
        (
            "sparse chain at the guard limit is unsupported, not a parse error",
            archive(&[sparse_member("s", 8, 0)]),
            UNSUPPORTED,
        ),
        (
            "sparse chain past the guard limit is refused",
            archive(&[sparse_member("s", 9, 0)]),
            UNSUPPORTED,
        ),
        (
            "unsafe path outranks the sparse type",
            archive(&[sparse_member("../s", 0, 0)]),
            SLIP,
        ),
        (
            "sparse flag byte chains into the terminator blocks",
            archive(&[sparse_member("s", 2, 1)]),
            UNSUPPORTED,
        ),
        (
            "sparse flag byte claims another block that is not there",
            sparse_member("s", 2, 1),
            INCOMPLETE,
        ),
    ]);
}

#[test]
fn header_metadata() {
    let mut bad_checksum = file("a", b"x");
    bad_checksum[148..156].copy_from_slice(b"0000001\0");
    let mut base256 = header(b"a", b'0', 0, b"", Magic::Ustar);
    base256[124] = 0x80;
    base256[125..136].fill(0xff);
    finish_checksum(&mut base256);
    let mut base256_1tib = header(b"a", b'0', 0, b"", Magic::Ustar);
    base256_1tib[124] = 0x80;
    base256_1tib[128..136].copy_from_slice(&(1u64 << 40).to_be_bytes());
    finish_checksum(&mut base256_1tib);
    let garbage_size = raw_header(b"a", b'0', b"zzzzzzzzzzz\0", b"", Magic::Ustar);
    let huge_octal = raw_header(b"a", b'0', b"77777777777\0", b"", Magic::Ustar);
    let truncated = file("a", &[b'x'; 2048])[..BLOCK + 100].to_vec();
    let mut huge_member = header(b"a", b'0', 1 << 33, b"", Magic::Ustar).to_vec();
    huge_member.extend(vec![0u8; 4 * BLOCK]);
    let uid_garbage = {
        let mut block = header(b"a", b'0', 0, b"", Magic::Ustar);
        block[108..116].copy_from_slice(b"zzzzzzz\0");
        finish_checksum(&mut block);
        block.to_vec()
    };
    run(vec![
        ("bad checksum", archive(&[bad_checksum]), INCOMPLETE),
        (
            "base-256 size beyond u64",
            archive(&[base256.to_vec()]),
            INCOMPLETE,
        ),
        (
            "base-256 size of 1 TiB",
            archive(&[base256_1tib.to_vec()]),
            MEMBER_LIMIT,
        ),
        (
            "non-octal size",
            archive(&[garbage_size.to_vec()]),
            INCOMPLETE,
        ),
        (
            "max octal size (8 GiB) over the member cap",
            archive(&[huge_octal.to_vec()]),
            MEMBER_LIMIT,
        ),
        ("truncated mid-payload", truncated, INCOMPLETE),
        (
            "8 GiB declared member with 2 KiB present",
            huge_member,
            MEMBER_LIMIT,
        ),
        (
            "non-octal uid is ignored by policy",
            archive(&[uid_garbage]),
            CLEAN,
        ),
        ("single zero block then EOF", vec![0u8; BLOCK], CLEAN),
        ("empty input", Vec::new(), CLEAN),
        ("short garbage", b"not a tar".to_vec(), INCOMPLETE),
    ]);
}

#[test]
fn terminators_and_trailing_data() {
    let mut data_after_terminator = archive(&[file("a", b"x")]);
    data_after_terminator.extend(file("../escape", b"y"));
    let mut single_zero_then_member = file("a", b"x");
    single_zero_then_member.extend(vec![0u8; BLOCK]);
    single_zero_then_member.extend(file("../escape", b"y"));
    run(vec![
        // Everything after the terminator is ignored by the parser and never
        // extracted; the bytes are still covered by the digest and caps.
        (
            "member smuggled after the terminator",
            data_after_terminator,
            CLEAN,
        ),
        (
            "member smuggled after a lone zero block",
            single_zero_then_member,
            CLEAN,
        ),
    ]);
}

#[test]
fn gzip_headers_and_members() {
    let tar = archive(&[file("a", b"x")]);
    let evil = archive(&[file("../escape", b"x")]);
    let mut concatenated = gz(&tar);
    concatenated.extend(gz(&evil));
    let mut trailing_garbage = gz(&tar);
    trailing_garbage.extend(b"\0\0garbage");
    let mut truncated = gz(&tar);
    truncated.truncate(truncated.len() - 6);
    let mut bad_crc = gz(&tar);
    let last = bad_crc.len() - 5;
    bad_crc[last] ^= 0xff;
    let mut bz2 = b"BZh9".to_vec();
    bz2.extend(vec![0u8; 64]);
    let mut xz = vec![0xfd, b'7', b'z', b'X', b'Z', 0x00];
    xz.extend(vec![0u8; 64]);
    run(vec![
        ("gzip clean", gz(&tar), CLEAN),
        // MultiGzDecoder: the second member continues the tar stream after the
        // terminator, so it is never parsed; it is not smuggled in.
        (
            "concatenated gzip member after the terminator",
            concatenated,
            CLEAN,
        ),
        ("gzip with trailing garbage", trailing_garbage, INCOMPLETE),
        ("gzip truncated before the trailer", truncated, INCOMPLETE),
        ("gzip with a bad crc", bad_crc, INCOMPLETE),
        ("gzip FNAME 60 KiB", gz_with_fname(&tar, 60_000), CLEAN),
        ("gzip FCOMMENT 60 KiB", gz_with_comment(&tar, 60_000), CLEAN),
        ("gzip FEXTRA 64 KiB", gz_with_extra(&tar, 65_535), CLEAN),
        (
            "gzip FNAME over the header limit",
            gz_with_fname(&tar, 70_000),
            INCOMPLETE,
        ),
        (
            "gzip magic with nothing after",
            vec![0x1f, 0x8b],
            INCOMPLETE,
        ),
        ("gzip of an empty tar", gz(&[]), CLEAN),
        ("bzip2 magic", bz2, FORMAT),
        ("xz magic", xz, FORMAT),
    ]);
}

#[test]
fn expansion_after_the_tar_terminator_is_still_bounded() {
    let mut tar = archive(&[file("a", b"x")]);
    tar.extend(vec![0u8; 20 * MIB as usize]);
    let outcome = inspect(&gz(&tar));
    assert_outcome(
        &outcome,
        "blocked",
        "external_archive_decompression_ratio_limit",
    );
    let mut expanded = archive(&[file("a", b"x")]);
    expanded.extend(vec![0u8; 33 * MIB as usize]);
    let mut limit = caps();
    limit.max_decompression_ratio = 1e9;
    let outcome = inspect_with(&gz(&expanded), &limit);
    assert_outcome(&outcome, "blocked", "external_archive_expanded_size_limit");
}
