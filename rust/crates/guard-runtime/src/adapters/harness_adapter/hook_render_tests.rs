use super::*;
use serde_json::json;

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn names(pairs: &[(&str, Option<&str>, Option<&str>)]) -> ShortNames {
    pairs
        .iter()
        .map(|(path, short, long)| {
            (
                (*path).to_owned(),
                (short.map(str::to_owned), long.map(str::to_owned)),
            )
        })
        .collect()
}

#[test]
fn a_posix_command_is_shlex_joined() {
    let line = render(
        &argv(&["/a b/py", "-I", "{\"x\":1}"]),
        false,
        &ShortNames::new(),
    );
    assert_eq!(line.ok(), Some(r#"'/a b/py' -I '{"x":1}'"#.to_owned()));
    assert!(unnamed([&argv(&["/a b/py"])[..]], false, &ShortNames::new()).is_empty());
}

#[test]
fn plain_windows_tokens_need_no_host() {
    let command = argv(&[
        "C:\\Guard\\hol-guard.exe",
        "codex-hook-bridge",
        "eyJ4IjoxfQ",
    ]);
    assert!(unnamed([&command[..]], true, &ShortNames::new()).is_empty());
    assert_eq!(
        render(&command, true, &ShortNames::new()).ok(),
        Some("C:\\Guard\\hol-guard.exe codex-hook-bridge eyJ4IjoxfQ".to_owned())
    );
}

#[test]
fn a_spaced_path_takes_its_short_name_when_it_maps_back() {
    let command = argv(&["C:\\Program Files\\py.exe", "-I", "x"]);
    let missing = unnamed([&command[..]], true, &ShortNames::new());
    assert_eq!(
        missing,
        BTreeSet::from(["C:\\Program Files\\py.exe".to_owned()])
    );
    let known = names(&[(
        "C:\\Program Files\\py.exe",
        Some("C:\\PROGRA~1\\py.exe"),
        Some("C:\\Program Files\\py.exe"),
    )]);
    assert!(unnamed([&command[..]], true, &known).is_empty());
    assert_eq!(
        render(&command, true, &known).ok(),
        Some("C:\\PROGRA~1\\py.exe -I x".to_owned())
    );
}

#[test]
fn a_short_name_that_does_not_map_back_falls_back_to_the_call_operator() {
    let command = argv(&["C:\\Program Files\\py.exe", "it's"]);
    for known in [
        names(&[
            ("C:\\Program Files\\py.exe", None, None),
            ("it's", None, None),
        ]),
        names(&[
            (
                "C:\\Program Files\\py.exe",
                Some("C:\\PROGRA~1\\py.exe"),
                Some("C:\\Other"),
            ),
            ("it's", None, None),
        ]),
        names(&[
            (
                "C:\\Program Files\\py.exe",
                Some("~PROGRA~1"),
                Some("C:\\Program Files\\py.exe"),
            ),
            ("it's", None, None),
        ]),
    ] {
        assert_eq!(
            render(&command, true, &known).ok(),
            Some("& 'C:\\Program Files\\py.exe' 'it''s'".to_owned())
        );
    }
}

#[test]
fn a_typographic_apostrophe_is_doubled_like_an_ascii_one() {
    let command = argv(&["C:\\Users\\O\u{2019}Neil\\py.exe", "\u{2018}x\u{201b}"]);
    let known = names(&[
        ("C:\\Users\\O\u{2019}Neil\\py.exe", None, None),
        ("\u{2018}x\u{201b}", None, None),
    ]);
    assert_eq!(
        render(&command, true, &known).ok(),
        Some(
            "& 'C:\\Users\\O\u{2019}\u{2019}Neil\\py.exe' '\u{2018}\u{2018}x\u{201b}\u{201b}'"
                .to_owned()
        )
    );
}

#[test]
fn a_leading_dash_always_uses_the_call_operator() {
    let command = argv(&["-x", "a b"]);
    assert!(unnamed([&command[..]], true, &ShortNames::new()).is_empty());
    assert_eq!(
        render(&command, true, &ShortNames::new()).ok(),
        Some("& '-x' 'a b'".to_owned())
    );
}

#[test]
fn windows_refuses_an_empty_argv_or_a_line_break() {
    for refused in [argv(&[]), argv(&["a", "b\nc"]), argv(&["a\0"])] {
        assert!(unnamed([&refused[..]], true, &ShortNames::new()).is_empty());
        assert!(matches!(
            render(&refused, true, &ShortNames::new()),
            Err(Failure::Refusal(message)) if message == REFUSAL
        ));
    }
}

#[test]
fn short_names_are_read_from_the_request() {
    let fields = json!({"short_names": {"C:\\a b": ["C:\\AB~1", null]}});
    let read = short_names(fields.as_object().unwrap()).ok().unwrap();
    assert_eq!(read, names(&[("C:\\a b", Some("C:\\AB~1"), None)]));
    let malformed = json!({"short_names": {"C:\\a b": ["C:\\AB~1"]}});
    assert!(short_names(malformed.as_object().unwrap()).is_err());
    assert!(short_names(&Map::new()).ok().unwrap().is_empty());
}

#[test]
fn names_the_request_supplies_are_used_without_a_lookup() {
    let command = argv(&["C:\\a b\\py.exe", "hook"]);
    let fields =
        json!({"short_names": {"C:\\a b\\py.exe": ["C:\\AB~1\\py.exe", "C:\\a b\\py.exe"]}});
    let found = names_for(fields.as_object().unwrap(), [&command[..]], true)
        .ok()
        .unwrap();
    assert_eq!(
        render(&command, true, &found).ok().unwrap(),
        "C:\\AB~1\\py.exe hook"
    );
    // A POSIX render needs no short name at all.
    assert!(names_for(&Map::new(), [&command[..]], false)
        .ok()
        .unwrap()
        .is_empty());
}

#[cfg(not(windows))]
#[test]
fn a_windows_render_from_another_host_has_no_short_name_to_give() {
    let missing = "C:\\a b\\py.exe";
    let command = argv(&[missing, "hook"]);
    let found = names_for(&Map::new(), [&command[..]], true).ok().unwrap();
    assert_eq!(found.get(missing), Some(&(None, None)));
    assert!(render(&command, true, &found)
        .ok()
        .unwrap()
        .starts_with("& '"));
}

#[cfg(windows)]
#[test]
fn a_windows_host_names_a_missing_path_itself() {
    let missing = "C:\\no such guard path\\py.exe";
    let command = argv(&[missing, "hook"]);
    let found = names_for(&Map::new(), [&command[..]], true).ok().unwrap();
    assert_eq!(found.get(missing), Some(&(None, None)));
    assert!(render(&command, true, &found)
        .ok()
        .unwrap()
        .starts_with("& '"));
}
