use super::*;

pub(super) fn begin(fixture: &Fixture) -> Value {
    let profile = if fixture.root["schema"] == "guard.command-pack-bundle.v1" {
        Profile::Installed
    } else {
        Profile::Remote
    };
    evaluate(Request {
        guard_home: fixture.home.path().into(),
        action: Action::Begin {
            authority: authority(&fixture.root, profile),
        },
    })
}
pub(super) fn prepare(fixture: &Fixture) -> std::result::Result<(Handle, usize), String> {
    finish(fixture, begin(fixture))
}
pub(super) fn finish(
    fixture: &Fixture,
    mut result: Value,
) -> std::result::Result<(Handle, usize), String> {
    let home = fixture.home.path();
    let mut fetches = 0;
    loop {
        match result["outcome"].as_str().unwrap() {
            "continue" => {
                result = evaluate(Request {
                    guard_home: home.into(),
                    action: Action::Resume {
                        session: result["session"].as_str().unwrap().into(),
                    },
                });
            }
            "complete" => {
                return Ok((
                    serde_json::from_value(result["handle"].clone()).unwrap(),
                    fetches,
                ))
            }
            "fetch" => {
                let target = &result["fetch"];
                assert!(target["location"]["asset"]
                    .as_str()
                    .unwrap()
                    .starts_with("object-"));
                let bytes = fs::read(
                    fixture
                        .origin
                        .path()
                        .join(format!("{}.json", target["sha256"].as_str().unwrap())),
                )
                .unwrap();
                assert!(bytes.len() <= OBJECT_BYTES);
                fetches += 1;
                result = evaluate(Request {
                    guard_home: home.into(),
                    action: Action::Advance {
                        session: result["session"].as_str().unwrap().into(),
                        data: bytes,
                    },
                });
            }
            _ => return Err(result.to_string()),
        }
    }
}

fn advance(fixture: &Fixture, session: &Value) -> Value {
    evaluate(Request {
        guard_home: fixture.home.path().into(),
        action: Action::Advance {
            session: session.as_str().unwrap().into(),
            data: vec![],
        },
    })
}

#[test]
fn regression_two_clients_preparing_one_home_both_complete() {
    // The daemon and a CLI read share one resident. Each used to begin by
    // dropping every other session for the home, so whichever client advanced
    // second failed with catalog_prepare_session_invalid at startup.
    let fixture = fixture(2, "");
    state().lock().unwrap().sessions.clear();
    let first = begin(&fixture);
    let second = begin(&fixture);
    assert_ne!(first["session"], second["session"]);
    finish(&fixture, second).unwrap();
    finish(&fixture, first).unwrap();
}

#[test]
fn a_full_session_budget_gives_up_only_this_homes_oldest_session() {
    let fixture = fixture(2, "");
    state().lock().unwrap().sessions.clear();
    let other = fixture_home_session(&fixture, "other-home");
    let results: Vec<_> = (0..MAX_SESSIONS).map(|_| begin(&fixture)).collect();
    assert_eq!(state().lock().unwrap().sessions.len(), MAX_SESSIONS);
    assert!(state().lock().unwrap().sessions.contains_key(&other));
    assert_eq!(
        advance(&fixture, &results[0]["session"])["error_code"],
        "catalog_prepare_session_invalid"
    );
    for result in results.into_iter().skip(1) {
        finish(&fixture, result).unwrap();
    }
    state().lock().unwrap().sessions.clear();
}

#[test]
fn a_full_budget_held_one_each_by_other_homes_refuses_a_new_session() {
    let fixture = fixture(2, "");
    state().lock().unwrap().sessions.clear();
    for index in 0..MAX_SESSIONS {
        fixture_home_session(&fixture, &format!("other-home-{index}"));
    }
    assert_eq!(
        begin(&fixture)["error_code"],
        "catalog_prepare_session_budget"
    );
    state().lock().unwrap().sessions.clear();
}

#[test]
fn regression_one_home_holding_the_whole_budget_cannot_keep_another_home_out() {
    let fixture = fixture(2, "");
    state().lock().unwrap().sessions.clear();
    let held: Vec<_> = (0..MAX_SESSIONS)
        .map(|_| fixture_home_session(&fixture, "other-home"))
        .collect();
    let result = begin(&fixture);
    assert!(result["session"].is_string(), "{result}");
    let guard = state().lock().unwrap();
    assert_eq!(guard.sessions.len(), MAX_SESSIONS);
    assert!(!guard.sessions.contains_key(&held[0]));
    assert!(held
        .iter()
        .skip(1)
        .all(|token| guard.sessions.contains_key(token)));
    drop(guard);
    finish(&fixture, result).unwrap();
    state().lock().unwrap().sessions.clear();
}

/// Starts a session for the home `name` beside the fixture's and returns
/// its token.
fn fixture_home_session(fixture: &Fixture, name: &str) -> String {
    let home = fixture.origin.path().join(name);
    fs::create_dir_all(&home).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let result = evaluate(Request {
        guard_home: home,
        action: Action::Begin {
            authority: authority(&fixture.root, Profile::Remote),
        },
    });
    result["session"].as_str().unwrap().to_owned()
}
