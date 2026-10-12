//! Read-only `find` expressions.
//!
//! `find` only prints names unless an action predicate runs a program, writes
//! a file, or deletes. Every operand before the expression must be a bounded
//! directory, and the expression may use only matching, depth and print
//! predicates. Actions (`-exec*`, `-ok*`, `-delete`, `-fprint*`, `-fls`,
//! `-printf`), link-following options (`-L`, `-H`, `-follow`) and anything
//! unrecognised keep review.

use super::safe_reads::{bounded_read_target, verified_path_context};

const MAX_FIND_DEPTH: u8 = 32;
const MAX_FIND_ROOTS: usize = 8;
const MAX_PATTERN_BYTES: usize = 256;

pub(super) fn safe_find_listing_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let arguments = arguments
        .strip_prefix(&["-P".to_owned()])
        .unwrap_or(arguments);
    let roots_end = arguments
        .iter()
        .position(|argument| argument.starts_with('-') || matches!(argument.as_str(), "!" | "("))
        .unwrap_or(arguments.len());
    let (roots, expression) = arguments.split_at(roots_end);
    if roots.is_empty() || roots.len() > MAX_FIND_ROOTS {
        return false;
    }
    verified_path_context(context.home_dir, context.cwd)
        && roots
            .iter()
            .all(|root| bounded_read_target(root, context.home_dir, context.cwd, true))
        && safe_expression(expression)
}

fn safe_expression(expression: &[String]) -> bool {
    let mut depth = 0_usize;
    let mut index = 0;
    while index < expression.len() {
        let token = expression[index].as_str();
        index += 1;
        match token {
            "(" => depth += 1,
            ")" => {
                let Some(next) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
            }
            "!" | "-not" | "-a" | "-and" | "-o" | "-or" | "-print" | "-print0" | "-prune" => {}
            "-name" | "-iname" | "-path" | "-ipath" | "-wholename" | "-iwholename" => {
                let Some(pattern) = expression.get(index) else {
                    return false;
                };
                if pattern.len() > MAX_PATTERN_BYTES || pattern.contains(['\n', '\r', '\0']) {
                    return false;
                }
                index += 1;
            }
            "-type" => {
                let Some(kind) = expression.get(index) else {
                    return false;
                };
                if !matches!(kind.as_str(), "d" | "f" | "l") {
                    return false;
                }
                index += 1;
            }
            "-maxdepth" | "-mindepth" => {
                let Some(value) = expression.get(index) else {
                    return false;
                };
                if !value.bytes().all(|byte| byte.is_ascii_digit())
                    || !value
                        .parse::<u8>()
                        .is_ok_and(|count| count <= MAX_FIND_DEPTH)
                {
                    return false;
                }
                index += 1;
            }
            _ => return false,
        }
    }
    depth == 0
}
