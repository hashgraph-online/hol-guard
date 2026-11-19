//! A parenthesized choice of names in a `find` walk:
//! `\( -name '*.py' -o -name '*.rst' \)`.
//!
//! Agents write this to search two kinds of file in one walk. The flat shape
//! refused every parenthesis outside a pruned branch, so `find . -type f \(
//! -name '*.py' -o -name '*.rst' \) -exec grep -l x {} \;` held while the same
//! walk over one extension ran.
//!
//! A group only removes files from the walk, so the shape it sits in hands
//! the child no more than it would without the group. Its names are kept
//! apart from the walk's other name tests: those all have to match, while a
//! file passes the group by matching any one of its names. A group bounds a
//! content-reading child only when every one of its names does
//! (`pretool::fanout_reads`).

use super::bounded_test_pattern;

/// Most names one group may offer.
const MAX_ALTERNATIVES: usize = 16;

/// The names of the group that opened just before `index`, and where the
/// expression resumes after its closing parenthesis. Only `-name` and
/// `-iname` tests joined by `-o` are read; anything else in the group leaves
/// the walk to the uncertain model.
pub(super) fn name_group(expression: &[String], index: usize) -> Option<(Vec<&str>, usize)> {
    let mut names = Vec::new();
    let mut index = index;
    loop {
        if !matches!(
            expression.get(index).map(String::as_str),
            Some("-name" | "-iname")
        ) {
            return None;
        }
        let pattern = expression.get(index + 1)?;
        if !bounded_test_pattern(pattern) || names.len() == MAX_ALTERNATIVES {
            return None;
        }
        names.push(pattern.as_str());
        index += 2;
        match expression.get(index).map(String::as_str) {
            Some("-o" | "-or") => index += 1,
            Some(")") => return Some((names, index + 1)),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::name_group;

    fn words(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn names_joined_by_or_are_read() {
        let expression = words(&["-name", "*.py", "-o", "-iname", "*.RST", ")", "-print"]);
        assert_eq!(name_group(&expression, 0), Some((vec!["*.py", "*.RST"], 6)));
        let single = words(&["-name", "*.py", ")"]);
        assert_eq!(name_group(&single, 0), Some((vec!["*.py"], 3)));
    }

    #[test]
    fn other_tests_operators_or_open_groups_are_refused() {
        for case in [
            &["-name", "*.py", "-o", "-path", "./x/*", ")"][..],
            &["-name", "*.py", "-o", "-newer", "x", ")"],
            &["-name", "*.py", "-a", "-name", "*.rs", ")"],
            &["-name", "*.py", "-name", "*.rs", ")"],
            &["-name", "*.py", "-o", "-exec", "rm", "{}", ";", ")"],
            &["-name", "*.py", "-o", "(", "-name", "*.rs", ")", ")"],
            &["!", "-name", "*.py", ")"],
            &["-name", "*.py", "-o", ")"],
            &["-name", "*.py", "-o", "-name", "*.rs"],
            &["-name"],
            &[")"],
        ] {
            assert_eq!(name_group(&words(case), 0), None, "{case:?}");
        }
        let mut many = Vec::new();
        for _ in 0..17 {
            many.extend(["-name", "*.py", "-o"]);
        }
        many.pop();
        many.push(")");
        assert_eq!(name_group(&words(&many), 0), None);
    }

    #[test]
    fn find_exec_keeps_group_names_apart_from_the_walk_names() {
        let arguments = words(&[
            ".", "-type", "f", "(", "-name", "*.py", "-o", "-name", "*.rst", ")", "!", "-path",
            "./.git/*", "-exec", "grep", "-l", "x", "{}", ";",
        ]);
        let parsed = crate::read_only_fanout::find_exec(&arguments).unwrap();
        assert!(parsed.shape.patterns.is_empty());
        assert_eq!(parsed.shape.name_groups, [vec!["*.py", "*.rst"]]);
        for case in [
            &[".", "!", "(", "-name", "*.py", "-o", "-name", "*.rs", ")"][..],
            &[".", "(", "-name", "*.py", "-o", "-path", "./x", ")"],
            &[".", "-name", "*.py", "-o", "-name", "*.rs"],
        ] {
            let mut arguments = words(case);
            arguments.extend(words(&["-exec", "cat", "{}", "+"]));
            assert!(
                crate::read_only_fanout::find_exec(&arguments).is_none(),
                "{case:?}"
            );
        }
    }
}
