//! HTTP clients: whether a request sends a body, a file or a write method.

/// curl short options whose value follows them, attached or in the next word.
const CURL_VALUE_FLAGS: &str = "AbcCDeEHKmoQrUuwxYyz";

/// curl long options that take the next word as their value.
const CURL_LONG_VALUE_FLAGS: [&str; 24] = [
    "--output",
    "--header",
    "--user",
    "--user-agent",
    "--referer",
    "--cookie",
    "--cookie-jar",
    "--config",
    "--cacert",
    "--cert",
    "--key",
    "--proxy",
    "--max-time",
    "--connect-timeout",
    "--retry",
    "--write-out",
    "--range",
    "--resolve",
    "--interface",
    "--dump-header",
    "--output-dir",
    "--url",
    "--oauth2-bearer",
    "--limit-rate",
];

/// HTTPie and xh options that take the next word as their value.
const HTTPIE_VALUE_FLAGS: [&str; 19] = [
    "--auth",
    "--auth-type",
    "--session",
    "--session-read-only",
    "--output",
    "--proxy",
    "--verify",
    "--cert",
    "--cert-key",
    "--cert-key-pass",
    "--timeout",
    "--max-redirects",
    "--pretty",
    "--style",
    "--print",
    "--format-options",
    "--default-scheme",
    "--boundary",
    "--ssl",
];

/// HTTPie and xh short options whose value follows them.
const HTTPIE_SHORT_VALUE_FLAGS: &str = "aAoPps";

/// HTTP-client long options that send a body or a file.
const SEND_LONG_OPTIONS: [&str; 8] = [
    "--data",
    "--form",
    "--json",
    "--upload-file",
    "--post-data",
    "--post-file",
    "--body-data",
    "--body-file",
];

fn is_write_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

/// Whether an HTTP client sends a body, a file or a write request.
/// `raw_args` keep their case: curl's `-F` uploads a form, `-f` fails quietly.
pub(super) fn http_sends(name: &str, raw_args: &[String]) -> bool {
    if name == "curl" {
        return curl_sends(raw_args);
    }
    let long_option = raw_args.iter().any(|arg| {
        SEND_LONG_OPTIONS
            .iter()
            .any(|prefix| arg.starts_with(prefix))
            || ["--request=", "--method="]
                .iter()
                .any(|prefix| arg.strip_prefix(prefix).is_some_and(is_write_method))
    });
    let method_option = raw_args.windows(2).any(|pair| {
        matches!(pair[0].as_str(), "--request" | "--method") && is_write_method(&pair[1])
    });
    let httpie = matches!(name, "http" | "https" | "xh") && httpie_sends(raw_args);
    long_option || method_option || httpie
}

/// curl, read left to right so an option's value (`-o -Tname`) is never read
/// as an option of its own. Form fields, uploads and write methods send;
/// `-d` data sends unless `-G` moves it into a GET request's URL.
fn curl_sends(args: &[String]) -> bool {
    let mut data = false;
    let mut get = false;
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        index += 1;
        if arg == "--" {
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (option, attached) = match long.split_once('=') {
                Some((option, value)) => (option, Some(value)),
                None => (long, None),
            };
            let option = format!("--{option}");
            if option.starts_with("--data") {
                data = true;
                if attached.is_none() {
                    index += 1;
                }
                continue;
            }
            if option == "--get" {
                get = true;
            } else if SEND_LONG_OPTIONS
                .iter()
                .any(|send| option.starts_with(send))
            {
                return true;
            }
            if option == "--request" {
                let method = attached.or_else(|| args.get(index).map(String::as_str));
                if method.is_some_and(is_write_method) {
                    return true;
                }
            }
            if attached.is_none()
                && (option == "--request" || CURL_LONG_VALUE_FLAGS.contains(&option.as_str()))
            {
                index += 1;
            }
            continue;
        }
        let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
            continue;
        };
        for (at, flag) in flags.char_indices() {
            match flag {
                'F' | 'T' => return true,
                'G' => get = true,
                'd' => {
                    data = true;
                    if at + 1 == flags.len() {
                        index += 1;
                    }
                    break;
                }
                'X' => {
                    let attached = &flags[at + 1..];
                    let method = if attached.is_empty() {
                        index += 1;
                        args.get(index - 1).map_or("", String::as_str)
                    } else {
                        attached
                    };
                    if is_write_method(method) {
                        return true;
                    }
                    break;
                }
                _ if CURL_VALUE_FLAGS.contains(flag) => {
                    if at + flag.len_utf8() == flags.len() {
                        index += 1;
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    data && !get
}

/// HTTPie: a write method word, or `name=value`, `name:=json` or `name@file`
/// body items after the URL.
fn httpie_sends(args: &[String]) -> bool {
    let mut words: Vec<&str> = Vec::new();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        index += 1;
        if let Some(long) = arg.strip_prefix("--") {
            if !long.contains('=') && HTTPIE_VALUE_FLAGS.contains(&arg.as_str()) {
                index += 1;
            }
        } else if let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) {
            // `-a user:pass` and `-va user:pass`; `-auser:pass` keeps its value.
            if let Some(at) = flags.find(|flag| HTTPIE_SHORT_VALUE_FLAGS.contains(flag)) {
                if at + 1 == flags.len() {
                    index += 1;
                }
            }
        } else {
            words.push(arg);
        }
    }
    let Some(first) = words.first() else {
        return false;
    };
    if is_write_method(first) {
        return true;
    }
    let names_method = first.chars().all(|c| c.is_ascii_uppercase());
    words
        .iter()
        .skip(if names_method { 2 } else { 1 })
        .any(|item| (item.contains('=') && !item.contains("==")) || item.contains('@'))
}
