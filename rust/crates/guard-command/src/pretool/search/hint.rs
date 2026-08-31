fn class_matches(class: &[u8], value: u8) -> bool {
    let (negated, members) = match class.first() {
        Some(b'!' | b'^') => (true, &class[1..]),
        _ => (false, class),
    };
    let mut matched = false;
    let mut index = 0;
    while index < members.len() {
        if index + 2 < members.len() && members[index + 1] == b'-' {
            matched |= members[index] <= value && value <= members[index + 2];
            index += 3;
        } else {
            matched |= members[index] == value;
            index += 1;
        }
    }
    matched != negated
}

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
