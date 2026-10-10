//! `fnmatch.fnmatchcase` for git config include conditions.
//!
//! `*` matches any run (slashes included), `?` one character, `[seq]` and
//! `[!seq]` a class with ranges; an unclosed `[` is a literal.

#[derive(Clone, Debug)]
enum Token {
    Literal(char),
    Any,
    Star,
    Class {
        negate: bool,
        items: Vec<(char, char)>,
    },
}

fn tokenize(pattern: &[char]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < pattern.len() {
        let c = pattern[index];
        index += 1;
        match c {
            '*' => {
                if !matches!(tokens.last(), Some(Token::Star)) {
                    tokens.push(Token::Star);
                }
            }
            '?' => tokens.push(Token::Any),
            '[' => {
                let mut end = index;
                if end < pattern.len() && pattern[end] == '!' {
                    end += 1;
                }
                if end < pattern.len() && pattern[end] == ']' {
                    end += 1;
                }
                while end < pattern.len() && pattern[end] != ']' {
                    end += 1;
                }
                if end >= pattern.len() {
                    tokens.push(Token::Literal('['));
                    continue;
                }
                let mut body = &pattern[index..end];
                let negate = body.first() == Some(&'!');
                if negate {
                    body = &body[1..];
                }
                let mut items = Vec::new();
                let mut at = 0;
                while at < body.len() {
                    if at + 2 < body.len() && body[at + 1] == '-' {
                        items.push((body[at], body[at + 2]));
                        at += 3;
                    } else {
                        items.push((body[at], body[at]));
                        at += 1;
                    }
                }
                tokens.push(Token::Class { negate, items });
                index = end + 1;
            }
            other => tokens.push(Token::Literal(other)),
        }
    }
    tokens
}

fn token_matches(token: &Token, c: char) -> bool {
    match token {
        Token::Literal(expected) => *expected == c,
        Token::Any => true,
        Token::Star => false,
        Token::Class { negate, items } => {
            let hit = items.iter().any(|(low, high)| *low <= c && c <= *high);
            hit != *negate
        }
    }
}

/// `fnmatch.fnmatchcase(name, pattern)`.
pub(crate) fn fnmatchcase(name: &str, pattern: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    let tokens = tokenize(&pattern);
    let (mut n, mut t) = (0usize, 0usize);
    let mut backtrack: Option<(usize, usize)> = None;
    while n < name.len() {
        match tokens.get(t) {
            Some(Token::Star) => {
                backtrack = Some((t, n));
                t += 1;
            }
            Some(token) if token_matches(token, name[n]) => {
                t += 1;
                n += 1;
            }
            _ => match backtrack {
                Some((star, matched)) => {
                    backtrack = Some((star, matched + 1));
                    t = star + 1;
                    n = matched + 1;
                }
                None => return false,
            },
        }
    }
    while matches!(tokens.get(t), Some(Token::Star)) {
        t += 1;
    }
    t == tokens.len()
}

#[cfg(test)]
mod tests {
    use super::fnmatchcase;

    #[test]
    fn matches_like_python() {
        assert!(fnmatchcase("/a/b/c/", "**/c/"));
        assert!(fnmatchcase("/a/b/c/", "/a/*/c/**"));
        assert!(fnmatchcase("feature/x", "feature/*"));
        assert!(!fnmatchcase("main", "feature/*"));
        assert!(fnmatchcase("ab", "a[bc]"));
        assert!(fnmatchcase("ad", "a[!bc]"));
        assert!(fnmatchcase("a[", "a["));
        assert!(fnmatchcase("a]", "a[]]"));
        assert!(fnmatchcase("", "*"));
        assert!(!fnmatchcase("", "?"));
    }
}
