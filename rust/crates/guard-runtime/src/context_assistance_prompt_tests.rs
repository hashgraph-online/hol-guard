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
