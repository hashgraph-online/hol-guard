use super::super::handoff_location;
use super::*;

// `build_approval_handoff_url(url, auth_token="vector-auth", now=1800000000)`.
const KEY: &str = "vector-auth";
const ID: &str = "20fce09561634ecab2055b539113c618";
const EXPIRES: &str = "1800043200";
const MAC: &str = "7c3d07b3dee665161df59cb58f93bcdf";
const NOW: i64 = 1_800_000_000 * 1_000_000 + 999_999;

fn location(id: &str, expires: &str, mac: &str) -> Option<String> {
    handoff_location(&format!("/requests/{id}/{expires}-{mac}"), KEY, NOW)
}

fn signed_page() -> String {
    let page = location(ID, EXPIRES, MAC).expect("the exact link is a short link");
    assert!(page.starts_with(&format!("/requests/{ID}#guard-token=gld1.")));
    page
}

fn dropped(text: &str, position: usize) -> String {
    let mut changed = text.to_owned();
    changed.remove(position);
    changed
}

fn added(text: &str, position: usize, inserted: char) -> String {
    let mut changed = text.to_owned();
    changed.insert(position, inserted);
    changed
}

fn changed(text: &str, position: usize) -> String {
    let mut bytes = text.as_bytes().to_vec();
    bytes[position] = if bytes[position] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("ascii")
}

#[test]
fn the_link_as_issued_opens_its_signed_page() {
    signed_page();
    assert_eq!(handoff_mac(KEY, ID, 1_800_043_200).as_deref(), Some(MAC));
}

#[test]
fn one_slipped_character_in_the_request_id_still_opens_that_request() {
    let page = signed_page();
    for position in [0, 1, 15, 30, 31] {
        assert_eq!(
            location(&dropped(ID, position), EXPIRES, MAC),
            Some(page.clone())
        );
        assert_eq!(
            location(&changed(ID, position), EXPIRES, MAC),
            Some(page.clone())
        );
        assert_eq!(
            location(&added(ID, position, 'e'), EXPIRES, MAC),
            Some(page.clone())
        );
    }
    assert_eq!(location(&added(ID, 32, '7'), EXPIRES, MAC), Some(page));
}

#[test]
fn one_slipped_character_in_the_mac_still_opens_the_request() {
    let page = signed_page();
    for position in [0, 9, 31] {
        assert_eq!(
            location(ID, EXPIRES, &dropped(MAC, position)),
            Some(page.clone())
        );
        assert_eq!(
            location(ID, EXPIRES, &changed(MAC, position)),
            Some(page.clone())
        );
        assert_eq!(
            location(ID, EXPIRES, &added(MAC, position, 'a')),
            Some(page.clone())
        );
    }
}

#[test]
fn one_slipped_digit_in_the_expiry_still_opens_the_request() {
    let page = signed_page();
    assert_eq!(location(ID, "180004320", MAC), Some(page.clone()));
    assert_eq!(location(ID, "1800043201", MAC), Some(page.clone()));
    assert_eq!(location(ID, "18000432000", MAC), Some(page));
}

#[test]
fn two_slips_open_no_signed_page() {
    let unsigned = format!("/requests/{}", changed(ID, 3));
    assert_eq!(
        location(&changed(ID, 3), EXPIRES, &changed(MAC, 4)),
        Some(unsigned)
    );
    assert_eq!(location(&dropped(ID, 3), EXPIRES, &dropped(MAC, 4)), None);
    assert_eq!(location(&dropped(&dropped(ID, 3), 3), EXPIRES, MAC), None);
    assert_eq!(
        location(ID, EXPIRES, &changed(&changed(MAC, 1), 2)),
        Some(format!("/requests/{ID}"))
    );
    assert_eq!(
        location(ID, "1800043201", &changed(MAC, 2)),
        Some(format!("/requests/{ID}"))
    );
}

#[test]
fn a_repair_never_verifies_under_another_key_or_after_expiry() {
    let other =
        |id: &str| handoff_location(&format!("/requests/{id}/{EXPIRES}-{MAC}"), "other", NOW);
    assert_eq!(other(ID), Some(format!("/requests/{ID}")));
    assert_eq!(other(&dropped(ID, 5)), None);
    let later = 1_800_043_200 * 1_000_000;
    assert_eq!(
        handoff_location(
            &format!("/requests/{}/{EXPIRES}-{MAC}", dropped(ID, 5)),
            KEY,
            later
        ),
        None
    );
}

#[test]
fn only_lowercase_hex_ids_one_character_from_full_length_are_short_links() {
    assert_eq!(location(&ID.to_uppercase(), EXPIRES, MAC), None);
    assert_eq!(location(&ID[..30], EXPIRES, MAC), None);
    assert_eq!(location(&format!("{ID}ab"), EXPIRES, MAC), None);
    assert_eq!(
        handoff_location(&format!("/requests/{ID}/{EXPIRES}-{MAC}/extra"), KEY, NOW),
        None
    );
}

#[test]
fn one_edit_means_one_dropped_added_or_changed_byte() {
    assert!(within_one_edit(b"abcd", b"abcd"));
    assert!(within_one_edit(b"abcd", b"abed"));
    assert!(within_one_edit(b"abcd", b"acd"));
    assert!(within_one_edit(b"abcd", b"abcde"));
    assert!(!within_one_edit(b"abcd", b"aecf"));
    assert!(!within_one_edit(b"abcd", b"ab"));
    assert!(!within_one_edit(b"abcd", b"bacd"));
}
