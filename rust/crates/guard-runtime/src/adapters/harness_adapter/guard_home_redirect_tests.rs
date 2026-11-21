//! `guard_home_redirected` against throwaway homes.

use std::fs;
use std::os::unix::fs::symlink;

use serde_json::{json, Value};

use super::super::dispatch;
use super::Home;

fn redirected(home: &Home, guard_home: &std::path::Path) -> bool {
    let mut context = home.context(json!({"PATH": ""}));
    context["guard_home"] = json!(guard_home);
    let answer: Value =
        dispatch(&json!({"op": "guard_home_redirected", "context": context})).unwrap();
    answer["redirected"].as_bool().unwrap()
}

#[test]
fn a_guard_home_with_no_link_is_not_redirected() {
    let home = Home::new();
    assert!(!redirected(&home, &home.home().join("state/guard")));
    assert!(!redirected(&home, &home.root.join("elsewhere/guard")));
}

#[test]
fn a_link_below_the_user_home_redirects_the_guard_home() {
    let home = Home::new();
    let outside = home.root.join("escape");
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, home.home().join("redirected")).unwrap();
    assert!(redirected(
        &home,
        &home.home().join("redirected/state/guard")
    ));
}

#[test]
fn a_link_outside_the_user_home_redirects_the_guard_home() {
    let home = Home::new();
    let outside = home.root.join("escape");
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, home.root.join("redirected")).unwrap();
    assert!(redirected(&home, &home.root.join("redirected/state/guard")));
}

#[test]
fn a_user_home_that_is_itself_a_link_is_an_anchor_not_a_redirect() {
    let home = Home::new();
    let linked = home.root.join("linked-home");
    symlink(home.home(), &linked).unwrap();
    let mut context = home.context(json!({"PATH": ""}));
    context["home"] = json!(linked);
    context["guard_home"] = json!(linked.join(".local/state/guard"));
    let answer = dispatch(&json!({"op": "guard_home_redirected", "context": context})).unwrap();
    assert_eq!(answer["redirected"], json!(false));
}
