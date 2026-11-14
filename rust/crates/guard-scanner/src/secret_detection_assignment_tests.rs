use super::assignment_captures;
use crate::secret_detection::ASSIGNMENT;

fn spans(captures: &regex::Captures<'_>) -> Vec<Option<(usize, usize)>> {
    (0..captures.len())
        .map(|group| {
            captures
                .get(group)
                .map(|found| (found.start(), found.end()))
        })
        .collect()
}

fn assert_same(text: &str) {
    let whole: Vec<_> = ASSIGNMENT.captures_iter(text).map(|c| spans(&c)).collect();
    let windowed: Vec<_> = assignment_captures(&ASSIGNMENT, text)
        .map(|c| spans(&c))
        .collect();
    assert!(
        windowed == whole,
        "windowed scan differs; text length {}",
        text.len()
    );
}

/// A small deterministic generator, so a failure names its seed.
struct Shuffle(u64);

impl Shuffle {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("bounded")
    }
}

const PIECES: &[&str] = &[
    "a",
    "Z",
    "_",
    ".",
    "-",
    "7",
    " ",
    "\t",
    "\n",
    ":",
    "=",
    "\"",
    "'",
    "{",
    "}",
    ",",
    "é",
    "\u{2003}",
    "+",
    "/",
    "token",
    "api_key",
    "secret_name",
    "abcdefghijklmnop",
];

#[test]
fn windows_find_what_the_whole_text_scan_finds() {
    for seed in 1..=4_000u64 {
        let mut shuffle = Shuffle(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let pieces = 1 + shuffle.below(160);
        let mut text = String::new();
        for _ in 0..pieces {
            let piece = PIECES[shuffle.below(PIECES.len())];
            let repeat = if shuffle.below(8) == 0 {
                1 + shuffle.below(40)
            } else {
                1
            };
            for _ in 0..repeat {
                text.push_str(piece);
            }
        }
        assert_same(&text);
    }
}

#[test]
fn bounds_and_separators_match_the_whole_text_scan() {
    let name81 = format!("a{}", "b".repeat(80));
    let name82 = format!("a{}", "b".repeat(81));
    let value256 = "v".repeat(256);
    let value257 = "v".repeat(257);
    for text in [
        format!("{name81}={value256}"),
        format!("{name82}={value256}"),
        format!("{name81} = \"{value256}\""),
        format!("x=\"{value257}\""),
        format!("x='{value257}'"),
        format!("key:{value257}"),
        "ab = 'abcdefghijkl\" tail".to_owned(),
        "ab:\u{2003}\u{2003}abcdefghijklm".to_owned(),
        format!("ab{}=abcdefghijklm", " ".repeat(500)),
        format!("ab={}abcdefghijklm", "\t".repeat(500)),
        "a=b=c=d=e=f=g=h=i=j=k=l=m=n".to_owned(),
        "aa=\"bbbbbbbbbbbbb aa=bbbbbbbbbbbbbbb".to_owned(),
        "é:abcdefghijklmn ab:abcdefghijklm".to_owned(),
        "user: me\nsecret_name: correct-horse-battery\n".to_owned(),
        String::new(),
        "=".to_owned(),
    ] {
        assert_same(&text);
    }
}

#[test]
fn a_long_encoded_run_is_scanned_without_the_whole_text_engine() {
    // About a mebibyte of base64 alphabet with one padded end, the shape of
    // an attachment body. The whole-text scan falls to the PikeVM here; the
    // windowed scan touches only the padding.
    let mut shuffle = Shuffle(0x5EED);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text: String = (0..1_048_000)
        .map(|_| char::from(alphabet[shuffle.below(alphabet.len())]))
        .collect();
    text.push_str("==");
    let started = std::time::Instant::now();
    let found = assignment_captures(&ASSIGNMENT, &text).count();
    assert_eq!(found, 0);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn dense_separators_stay_within_the_window_budget() {
    // `--=` passes both window checks at every separator but never matches.
    // Windows stop overlapping past a miss, and the budget hands the rest of
    // the text to the whole-text scan, so the cost stays near one pass.
    let text = "--=".repeat(350_000);
    let started = std::time::Instant::now();
    let found = assignment_captures(&ASSIGNMENT, &text).count();
    assert_eq!(found, 0);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn matches_after_the_budget_is_spent_are_still_found() {
    let mut text = "--=".repeat(20_000);
    text.push_str("\napi_token = 'correct-horse-battery'\n");
    text.push_str(&"a1=b2:".repeat(5_000));
    text.push_str("\nclient_secret: correct-horse-battery-staple\n");
    assert_same(&text);
}
