use super::glob_class::glob_class_matches as class_matches;


fn constrained_token(pattern: &[u8], index: usize, value: u8) -> (usize, bool, bool) {
    if matches!(pattern[index], b'*' | b'?') {
        return (index + 1, false, false);
    }
    if pattern[index] == b'[' {
        if let Some(relative_end) = pattern[index..]
            .iter()
            .position(|character| *character == b']')
        {
            let class_end = index + relative_end;
            return (
                class_end + 1,
                true,
                class_matches(&pattern[index + 1..class_end], value),
            );
        }
    }
    if pattern[index] == b'\\' && index + 1 < pattern.len() {
        return (index + 2, true, pattern[index + 1] == value);
    }
    (index + 1, true, pattern[index] == value)
}

pub(super) fn glob_constrained_lcs(pattern: &[u8], family: &[u8]) -> usize {
    let mut previous = vec![0_usize; family.len() + 1];
    let mut index = 0;
    while index < pattern.len() {
        let (next_index, constrained, _) = constrained_token(pattern, index, 0);
        if constrained {
            let mut current = previous.clone();
            for family_index in 1..=family.len() {
                let (_, _, matches) = constrained_token(pattern, index, family[family_index - 1]);
                current[family_index] = current[family_index].max(current[family_index - 1]);
                if matches {
                    current[family_index] =
                        current[family_index].max(previous[family_index - 1] + 1);
                }
            }
            previous = current;
        }
        index = next_index;
    }
    previous[family.len()]
}
