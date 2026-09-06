pub(super) fn glob_class_matches(class: &[u8], value: u8) -> bool {
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
