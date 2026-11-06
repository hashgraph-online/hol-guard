//! Both plist serialisations must read back as the same document, because a
//! profile delivered by macOS configuration management is binary while a
//! hand-written one is XML.

use super::*;
use serde_json::json;

/// `plutil -convert binary1` of the same document the XML case carries.
const BINARY: &[u8] = include_bytes!("../testdata/managed_policy/binary-policy.plist");

const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>daemonStartup</key>
	<string>login</string>
	<key>lockedSettings</key>
	<array>
		<string>mode</string>
	</array>
	<key>network</key>
	<dict>
		<key>allowPublicRegistries</key>
		<false/>
		<key>proxyMode</key>
		<string>explicit</string>
		<key>proxyUrl</key>
		<string>https://proxy.example.com:8443</string>
	</dict>
	<key>requiredHarnesses</key>
	<array>
		<string>claude-code</string>
	</array>
	<key>schemaVersion</key>
	<string>hol-guard-mdm-policy.v1</string>
	<key>settings</key>
	<dict>
		<key>mode</key>
		<string>enforce</string>
		<key>nested</key>
		<dict>
			<key>actions</key>
			<dict>
				<key>shell</key>
				<string>block</string>
			</dict>
		</dict>
		<key>ratio</key>
		<real>0.5</real>
		<key>retries</key>
		<integer>3</integer>
		<key>sync</key>
		<false/>
	</dict>
</dict>
</plist>
"#;

fn document() -> Value {
    json!({
        "schemaVersion": "hol-guard-mdm-policy.v1",
        "daemonStartup": "login",
        "lockedSettings": ["mode"],
        "requiredHarnesses": ["claude-code"],
        "network": {
            "proxyMode": "explicit",
            "proxyUrl": "https://proxy.example.com:8443",
            "allowPublicRegistries": false,
        },
        "settings": {
            "mode": "enforce",
            "sync": false,
            "retries": 3,
            "ratio": 0.5,
            "nested": {"actions": {"shell": "block"}},
        },
    })
}

#[test]
fn the_binary_profile_reads_as_the_policy_document() {
    assert_eq!(parse_plist(BINARY).expect("binary plist"), document());
}

#[test]
fn the_xml_profile_reads_as_the_same_document() {
    assert_eq!(
        parse_plist(XML.as_bytes()).expect("xml plist"),
        document(),
        "both serialisations are the same policy"
    );
}

#[test]
fn a_value_no_policy_can_carry_is_refused_rather_than_guessed() {
    // Python turns these into `bytes` and `datetime`, which the typed fields
    // reject and the canonical hash cannot serialise.
    for (fragment, expected) in [
        (
            "<data>aGk=</data>",
            "managed policy plist holds binary data",
        ),
        (
            "<date>2026-10-16T00:00:00Z</date>",
            "managed policy plist holds a date",
        ),
    ] {
        let document =
            format!("<plist version=\"1.0\"><dict><key>settings</key>{fragment}</dict></plist>");
        assert_eq!(
            parse_plist(document.as_bytes()).expect_err("refused"),
            expected
        );
    }
}

#[test]
fn a_document_that_is_not_a_plist_is_not_read_as_one() {
    for (bytes, expected) in [
        (
            b"{\"schemaVersion\": \"x\"}".to_vec(),
            "managed policy is not a valid plist",
        ),
        (
            b"<other><dict/></other>".to_vec(),
            "managed policy is not a plist document",
        ),
        (
            b"<plist version=\"1.0\"></plist>".to_vec(),
            "managed policy plist is empty",
        ),
        (
            b"<plist version=\"1.0\"><dict/><dict/></plist>".to_vec(),
            "managed policy plist has more than one value",
        ),
        (
            b"<plist version=\"1.0\"><dict><string>v</string></dict></plist>".to_vec(),
            "managed policy plist has a value without a key",
        ),
        (
            b"<plist version=\"1.0\"><dict><key>k</key></dict></plist>".to_vec(),
            "managed policy plist has a key without a value",
        ),
    ] {
        assert_eq!(
            parse_plist(&bytes).expect_err("refused"),
            expected,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[test]
fn a_truncated_binary_plist_is_refused_before_it_is_indexed() {
    // Too short to hold a trailer at all.
    assert_eq!(
        parse_plist(&BINARY[..30]).expect_err("refused"),
        "managed policy is not a valid plist"
    );

    let mut torn = BINARY.to_vec();
    // The object-table offset is the last eight bytes of the trailer.
    let table = torn.len() - 8;
    torn[table..].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        parse_plist(&torn).expect_err("refused"),
        "managed policy plist has an unreadable object table"
    );
}

#[test]
fn nesting_past_the_bound_is_refused() {
    let depth = MAX_DEPTH + 2;
    let mut document = String::from("<plist version=\"1.0\">");
    document.push_str(&"<array>".repeat(depth));
    document.push_str("<string>deep</string>");
    document.push_str(&"</array>".repeat(depth));
    document.push_str("</plist>");
    assert_eq!(
        parse_plist(document.as_bytes()).expect_err("refused"),
        "managed policy plist nests too deeply"
    );
}

#[test]
fn a_profile_that_points_at_a_local_file_reads_nothing_from_it() {
    // The DOCTYPE an XML profile carries is accepted, so this is the document
    // that has to stay refused: an entity the parser would have to fetch to
    // resolve is never fetched, and never expands into the policy either.
    let document = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<!DOCTYPE plist [<!ENTITY leak SYSTEM \"file:///etc/passwd\">]>\n",
        "<plist version=\"1.0\"><dict><key>schemaVersion</key>",
        "<string>&leak;</string></dict></plist>",
    );

    assert_eq!(
        parse_plist(document.as_bytes()).expect_err("refused"),
        "managed policy is not a valid plist"
    );
}

/// A binary plist whose arrays each hold `width` references to the next
/// object. Nothing about it is deep or large; every container simply points at
/// the same object its neighbours do, which is the sharing the format exists to
/// allow.
fn shared_reference_chain(depth: usize, width: usize) -> Vec<u8> {
    let mut bytes = BINARY_HEADER.to_vec();
    let mut offsets = Vec::new();
    for index in 0..depth {
        offsets.push(bytes.len());
        bytes.push(0xa0 | width as u8);
        bytes.extend_from_slice(&vec![index as u8 + 1; width]);
    }
    offsets.push(bytes.len());
    bytes.extend_from_slice(&[0x51, b'x']);
    let table = bytes.len();
    for offset in &offsets {
        bytes.extend_from_slice(&(*offset as u16).to_be_bytes());
    }
    let mut trailer = [0u8; TRAILER_BYTES];
    // Two-byte offsets, one-byte references, then the object count, the top
    // object and where the offset table starts.
    trailer[6] = 2;
    trailer[7] = 1;
    trailer[8..16].copy_from_slice(&(offsets.len() as u64).to_be_bytes());
    trailer[24..32].copy_from_slice(&(table as u64).to_be_bytes());
    bytes.extend_from_slice(&trailer);
    bytes
}

#[test]
fn a_document_that_describes_more_than_it_holds_is_refused_rather_than_expanded() {
    // Within the depth bound and a few hundred bytes on disk, yet 10^24 nodes
    // to anything that expands every reference it meets.
    let fanned = shared_reference_chain(24, 10);

    assert!(fanned.len() < 1024, "{} bytes", fanned.len());
    assert_eq!(
        parse_plist(&fanned).expect_err("refused"),
        "managed policy plist describes too many objects"
    );
    // The same shape inside the budget still reads, so sharing itself is not
    // what the bound refuses.
    assert_eq!(
        parse_plist(&shared_reference_chain(2, 2)).expect("shared references"),
        json!([["x", "x"], ["x", "x"]])
    );
}
