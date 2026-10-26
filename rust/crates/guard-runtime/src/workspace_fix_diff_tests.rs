use super::*;

#[test]
fn one_changed_line_gets_three_lines_of_context() {
    let before: String = (1..=9).map(|n| format!("line{n}\n")).collect();
    let after = before.replace("line5", "LINE5");
    assert_eq!(
        unified_diff(&before, &after, "package.json"),
        "--- a/package.json\n+++ b/package.json\n@@ -2,7 +2,7 @@\n line2\n line3\n line4\n-line5\n+LINE5\n line6\n line7\n line8\n"
    );
}

#[test]
fn distant_changes_make_separate_hunks_and_near_ones_merge() {
    let before: String = (1..=30).map(|n| format!("l{n}\n")).collect();
    let apart = before.replace("l2\n", "x\n").replace("l25\n", "y\n");
    assert_eq!(
        unified_diff(&before, &apart, "p").matches("@@ -").count(),
        2
    );
    let near = before.replace("l10\n", "x\n").replace("l16\n", "y\n");
    assert_eq!(unified_diff(&before, &near, "p").matches("@@ -").count(), 1);
}

#[test]
fn a_missing_final_newline_is_marked() {
    let diff = unified_diff("a\nb", "a\nc", "p");
    assert!(diff.contains("-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"));
}

#[test]
fn equal_texts_have_no_diff_and_unicode_separators_stay_in_their_line() {
    assert_eq!(unified_diff("a\n", "a\n", "p"), "");
    let diff = unified_diff("\"a\u{2028}b\": 1\n", "\"a\u{2028}b\": 2\n", "p");
    assert!(diff.contains("@@ -1 +1 @@"));
}
