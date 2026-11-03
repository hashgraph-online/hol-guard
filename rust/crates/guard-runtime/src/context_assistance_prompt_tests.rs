use super::*;
use serde_json::json;

fn excerpt(path: &str, text: &str) -> PickedExcerpt {
    PickedExcerpt {
        path: path.into(),
        start_line: 1,
        end_line: 3,
        text: text.into(),
    }
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn matching_code_is_rendered_as_file_contents_with_other_matches_listed() {
    let picked = [
        excerpt(
            "src/components/Header.tsx",
            "export function Header() {\n  return <header />;\n}\n",
        ),
        excerpt("src/api.ts", "export const load = () => fetch('/x');"),
    ];
    let found = words(&["src/components/Header.tsx", "src/theme.css", "src/api.ts"]);
    let rendered = render(&picked, &found, &words(&["color", "header"])).unwrap();
    assert!(rendered.starts_with(HEADER));
    assert!(rendered
        .contains("src/components/Header.tsx (lines 1-3)\n```tsx\nexport function Header()"));
    assert!(
        !rendered.contains("fetch('/x')"),
        "an unrelated excerpt is dropped"
    );
    assert!(rendered.ends_with("Other matching files: src/theme.css, src/api.ts"));
}

#[test]
fn nothing_is_added_when_no_excerpt_mentions_the_request() {
    let picked = [excerpt(
        "src/api.ts",
        "export const load = () => fetch('/x');",
    )];
    assert_eq!(
        render(&picked, &words(&["src/api.ts"]), &words(&["winter"])),
        None
    );
    assert_eq!(render(&[], &[], &words(&["header"])), None);
}

#[test]
fn rendered_context_stays_bounded() {
    let long = "header ".repeat(1_500);
    let picked: Vec<_> = (0..6)
        .map(|index| excerpt(&format!("src/header{index}.ts"), &long))
        .collect();
    let rendered = render(&picked, &[], &words(&["header"])).unwrap();
    assert!(rendered.len() <= MAX_CONTEXT_CHARS, "{}", rendered.len());
    assert!(rendered.contains("src/header0.ts"));
}

#[test]
fn files_that_did_not_fit_are_listed_within_the_limit() {
    let near_full = "header ".repeat(1_650);
    let picked = [
        excerpt("src/header.ts", &near_full),
        excerpt("src/header-dropped.ts", &near_full),
    ];
    let mut found = words(&["src/header.ts", "src/header-dropped.ts"]);
    found.extend((0..8).map(|index| format!("src/{}/header{index}.ts", "deep/".repeat(40))));
    let rendered = render(&picked, &found, &words(&["header"])).unwrap();
    assert!(rendered.len() <= MAX_CONTEXT_CHARS, "{}", rendered.len());
    assert!(
        rendered.contains("Other matching files: src/header-dropped.ts"),
        "an excerpt cut for space is still named"
    );
    let too_big = [excerpt("src/header.ts", &"header ".repeat(2_000))];
    assert_eq!(
        render(&too_big, &[], &words(&["header"])),
        None,
        "never a header with no code under it"
    );
}

#[test]
fn only_an_allowed_prompt_answer_takes_context() {
    assert!(allowed(
        &json!({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}})
    ));
    assert!(!allowed(
        &json!({"decision": "block", "hookSpecificOutput": {}})
    ));
    assert!(!allowed(
        &json!({"continue": false, "hookSpecificOutput": {}})
    ));
    assert!(!allowed(&json!({"policy_action": "allow"})));
}

#[test]
fn context_is_appended_after_any_existing_context() {
    let mut fresh = json!({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}});
    add_context(&mut fresh, "code");
    assert_eq!(fresh["hookSpecificOutput"]["additionalContext"], "code");
    let mut existing = json!({"hookSpecificOutput": {"additionalContext": "notice"}});
    add_context(&mut existing, "code");
    assert_eq!(
        existing["hookSpecificOutput"]["additionalContext"],
        "notice\n\ncode"
    );
}

#[test]
fn the_wait_leaves_the_hook_time_to_answer() {
    assert_eq!(waiting_time(None), DEFAULT_WAIT);
    assert_eq!(waiting_time(Some(9_000)), MAX_WAIT);
    assert_eq!(waiting_time(Some(1_000)), Duration::from_millis(750));
    assert!(waiting_time(Some(400)) < MIN_WAIT);
    assert_eq!(waiting_time(Some(100)), Duration::ZERO);
}

#[test]
fn a_long_prompt_is_cut_on_a_character_boundary() {
    let prompt = format!("{}é", "a".repeat(4_095));
    let cut = truncated(&prompt, MAX_QUERY_BYTES);
    assert_eq!(cut.len(), 4_095);
    assert_eq!(truncated("short", MAX_QUERY_BYTES), "short");
}

#[test]
fn code_fences_name_the_language() {
    assert_eq!(language("src/theme.css"), "css");
    assert_eq!(language("app/main.py"), "python");
    assert_eq!(language("README"), "");
}

#[test]
fn a_fence_inside_an_excerpt_cannot_close_the_block() {
    assert_eq!(fence_for("plain"), "```");
    assert_eq!(fence_for("a ``` b"), "````");
    let picked = [excerpt(
        "README.md",
        "Header usage:\n```tsx\n<Header />\n```",
    )];
    let rendered = render(&picked, &[], &words(&["header"])).unwrap();
    assert!(rendered.contains("README.md (lines 1-3)\n````markdown\nHeader usage:"));
    assert!(rendered.ends_with("<Header />\n```\n````"));
}

#[test]
fn a_test_an_earlier_prompt_loaded_gives_way_to_the_source() {
    let picked = [
        excerpt("src/Header.test.tsx", "it('header color', () => {});"),
        excerpt("src/Header.tsx", "export const Header = () => <header />;"),
    ];
    let rendered = render(&picked, &[], &words(&["header"])).unwrap();
    assert!(!rendered.contains("Header.test.tsx"), "{rendered}");
    let asked = render(&picked, &[], &words(&["header", "test"])).unwrap();
    assert!(asked.contains("Header.test.tsx"), "{asked}");
    let only_tests = render(&picked[..1], &[], &words(&["header"])).unwrap();
    assert!(only_tests.contains("Header.test.tsx"), "{only_tests}");
}

#[test]
fn pi_gets_context_only_from_an_extension_that_passes_it_on() {
    let flagged = json!({"prompt": "fix the cart", "guard_prompt_context": true});
    let older = json!({"prompt": "fix the cart"});
    for harness in ["pi", "omp"] {
        assert!(takes_context(harness, &flagged));
        assert!(!takes_context(harness, &older));
        assert!(!takes_context(
            harness,
            &json!({"guard_prompt_context": "yes"})
        ));
    }
    assert!(takes_context("claude-code", &older));
    assert!(takes_context("codex", &older));
    assert!(!takes_context("cursor", &flagged));
}

#[test]
fn excerpts_follow_this_prompts_ranking_before_earlier_files() {
    let picked = [
        excerpt("src/earlier.tsx", "<button>Cancel</button>"),
        excerpt("src/data-panel.tsx", "<button>Cancel</button>"),
        excerpt("src/confirm-dialog.tsx", "cancelLabel = \"Cancel\""),
    ];
    let found = words(&["src/confirm-dialog.tsx", "src/data-panel.tsx"]);
    let rendered = render(&picked, &found, &words(&["cancel"])).unwrap();
    let at = |path: &str| rendered.find(&format!("{path} (lines")).unwrap();
    assert!(
        at("src/confirm-dialog.tsx") < at("src/data-panel.tsx"),
        "{rendered}"
    );
    assert!(
        at("src/data-panel.tsx") < at("src/earlier.tsx"),
        "{rendered}"
    );
}

#[test]
fn a_prompt_cigar_cannot_answer_in_time_still_gets_the_matched_files() {
    assert_eq!(matched(&[]), None);
    let found: Vec<String> = (0..12).map(|n| format!("src/f{n}.ts")).collect();
    let listed = matched(&found).unwrap();
    assert!(listed.starts_with(MATCHED_HEADER), "{listed}");
    assert!(listed.ends_with(" src/f0.ts, src/f1.ts, src/f2.ts, src/f3.ts, src/f4.ts, src/f5.ts, src/f6.ts, src/f7.ts"), "{listed}");
}

#[test]
fn long_matched_paths_stay_within_the_context_limit() {
    let long = format!("src/{}.ts", "a".repeat(MAX_CONTEXT_CHARS / 3));
    let found = vec![long.clone(); MAX_OTHER_FILES];
    let listed = matched(&found).unwrap();
    assert!(listed.len() <= MAX_CONTEXT_CHARS, "{}", listed.len());
    assert_eq!(listed.matches(long.as_str()).count(), 2);
    assert_eq!(
        matched(&[format!("src/{}.ts", "b".repeat(MAX_CONTEXT_CHARS))]),
        None
    );
}
