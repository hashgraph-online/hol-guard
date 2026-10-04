pub(super) fn safe_arguments(tool: &str, arguments: &[String]) -> bool {
    match tool {
        "sort" => arguments
            .iter()
            .all(|argument| short_flags(argument, "bnrufdMVs")),
        "uniq" => arguments
            .iter()
            .all(|argument| short_flags(argument, "cdui")),
        "cut" => safe_cut_arguments(arguments),
        _ => false,
    }
}

fn short_flags(value: &str, allowed: &str) -> bool {
    value
        .strip_prefix('-')
        .is_some_and(|flags| !flags.is_empty() && flags.chars().all(|flag| allowed.contains(flag)))
}

fn safe_cut_arguments(arguments: &[String]) -> bool {
    let mut selection = None;
    let mut delimiter = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if matches!(argument.as_str(), "-s" | "-n") {
            index += 1;
            continue;
        }
        let Some(option) = argument.strip_prefix('-') else {
            return false;
        };
        let mut chars = option.chars();
        let Some(flag) = chars.next() else {
            return false;
        };
        if !matches!(flag, 'b' | 'c' | 'f' | 'd') {
            return false;
        }
        let attached = chars.as_str();
        let value = if attached.is_empty() {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return false;
            };
            value.as_str()
        } else {
            attached
        };
        if flag == 'd' {
            if delimiter || value.chars().count() != 1 || value.chars().any(char::is_control) {
                return false;
            }
            delimiter = true;
        } else {
            if selection.is_some() || !bounded_selection(value) {
                return false;
            }
            selection = Some(flag);
        }
        index += 1;
    }
    selection.is_some() && (!delimiter || selection == Some('f'))
}

fn bounded_selection(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let number = |text: &str| {
        (!text.is_empty() && text.len() <= 6 && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse::<u32>().ok())
            .flatten()
            .filter(|number| *number > 0)
    };
    value.split(',').all(|part| {
        if let Some((start, end)) = part.split_once('-') {
            if start.is_empty() && end.is_empty() {
                return false;
            }
            let start = if start.is_empty() {
                Some(1)
            } else {
                number(start)
            };
            let end = if end.is_empty() {
                Some(u32::MAX)
            } else {
                number(end)
            };
            matches!((start, end), (Some(start), Some(end)) if start <= end)
        } else {
            number(part).is_some()
        }
    })
}
