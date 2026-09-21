//! Benchmark-only ASCII candidate extraction. Python retains finding semantics.
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

const SCHEMA: &str = "guard-offline-regex-pilot.v1";
const MAX_FRAME: usize = 64 * 1024 * 1024;
const MAX_TEXT: usize = 4 * 1024 * 1024;
const MAX_MATCHES: usize = 100_000;
const MAX_RULES: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternSpec {
    id: String,
    pattern: String,
    ignore_case: bool,
    multiline: bool,
    assignment: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Init {
    schema: String,
    catalog: String,
    patterns: Vec<PatternSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    id: u64,
    text: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Capture {
    whole: [usize; 2],
    secret: [usize; 2],
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<[usize; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quote: Option<[usize; 2]>,
}

#[derive(Serialize)]
struct RuleMatches {
    id: String,
    captures: Vec<Capture>,
}

#[derive(Serialize)]
struct Response<'a> {
    schema: &'a str,
    catalog: &'a str,
    id: u64,
    complete: bool,
    rules: Vec<RuleMatches>,
}

struct Compiled {
    id: String,
    pattern: Regex,
    assignment: bool,
}

fn compile(init: Init) -> Result<(String, Vec<Compiled>), &'static str> {
    if init.schema != SCHEMA
        || init.catalog.len() != 64
        || !init.catalog.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid initialization identity");
    }
    if init.patterns.is_empty() || init.patterns.len() > MAX_RULES {
        return Err("invalid rule count");
    }
    let mut rules: Vec<Compiled> = Vec::new();
    for spec in init.patterns {
        if spec.id.is_empty()
            || spec.id.len() > 80
            || spec.pattern.len() > 4096
            || rules.iter().any(|rule| rule.id == spec.id)
        {
            return Err("invalid rule specification");
        }
        let pattern = RegexBuilder::new(&spec.pattern)
            .case_insensitive(spec.ignore_case)
            .multi_line(spec.multiline)
            .size_limit(8 * 1024 * 1024)
            .dfa_size_limit(2 * 1024 * 1024)
            .build()
            .map_err(|_| "unsupported pattern")?;
        let names: Vec<_> = pattern.capture_names().flatten().collect();
        let required: &[&str] = if spec.assignment {
            &[
                "name",
                "secret_double",
                "secret_single",
                "secret_plain",
                "quote_double",
                "quote_single",
            ]
        } else {
            &["secret"]
        };
        if required.iter().any(|name| !names.contains(name)) {
            return Err("missing capture group");
        }
        rules.push(Compiled {
            id: spec.id,
            pattern,
            assignment: spec.assignment,
        });
    }
    Ok((init.catalog, rules))
}

fn span(matched: regex::Match<'_>) -> [usize; 2] {
    [matched.start(), matched.end()]
}

fn extract<'a>(
    catalog: &'a str,
    rules: &[Compiled],
    request: &Request,
) -> Result<Response<'a>, &'static str> {
    if request.schema != SCHEMA || request.text.len() > MAX_TEXT || !request.text.is_ascii() {
        return Err("unsupported input");
    }
    let mut total = 0;
    let mut output = Vec::with_capacity(rules.len());
    for rule in rules {
        let mut captures = Vec::new();
        for matched in rule.pattern.captures_iter(&request.text) {
            total += 1;
            if total > MAX_MATCHES {
                return Err("candidate budget exceeded");
            }
            let whole = span(matched.get(0).ok_or("missing whole capture")?);
            let (secret, name, quote) = if rule.assignment {
                let secret = matched
                    .name("secret_double")
                    .or_else(|| matched.name("secret_single"))
                    .or_else(|| matched.name("secret_plain"))
                    .ok_or("missing assignment secret")?;
                let quote = matched
                    .name("quote_double")
                    .or_else(|| matched.name("quote_single"))
                    .map(span)
                    .unwrap_or([secret.start(), secret.start()]);
                (
                    span(secret),
                    Some(span(matched.name("name").ok_or("missing assignment name")?)),
                    Some(quote),
                )
            } else {
                (
                    span(matched.name("secret").ok_or("missing provider secret")?),
                    None,
                    None,
                )
            };
            captures.push(Capture {
                whole,
                secret,
                name,
                quote,
            });
        }
        output.push(RuleMatches {
            id: rule.id.clone(),
            captures,
        });
    }
    Ok(Response {
        schema: SCHEMA,
        catalog,
        id: request.id,
        complete: true,
        rules: output,
    })
}

fn frame(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, &'static str> {
    let mut output = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|_| "input read failed")?;
        if available.is_empty() {
            return if output.is_empty() {
                Ok(None)
            } else {
                Err("unterminated frame")
            };
        }
        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1);
        let length = end.unwrap_or(available.len());
        if output.len() + length > MAX_FRAME {
            return Err("input frame budget exceeded");
        }
        output.extend_from_slice(&available[..length]);
        reader.consume(length);
        if end.is_some() {
            return Ok(Some(output));
        }
    }
}

fn write_json(writer: &mut impl Write, value: &impl Serialize) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "response encoding failed")?;
    if bytes.len() >= MAX_FRAME {
        return Err("response frame budget exceeded");
    }
    writer
        .write_all(&bytes)
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(|_| "response write failed")
}

fn run() -> Result<(), &'static str> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let init: Init = serde_json::from_slice(&frame(&mut input)?.ok_or("missing initialization")?)
        .map_err(|_| "invalid initialization JSON")?;
    let (catalog, rules) = compile(init)?;
    write_json(
        &mut output,
        &serde_json::json!({"schema": SCHEMA, "catalog": catalog, "ready": true}),
    )?;
    while let Some(bytes) = frame(&mut input)? {
        let request: Request =
            serde_json::from_slice(&bytes).map_err(|_| "invalid request JSON")?;
        write_json(&mut output, &extract(&catalog, &rules, &request)?)?;
    }
    Ok(())
}

fn main() {
    if let Err(reason) = run() {
        // Reasons are fixed labels. Never include candidate text or regex input.
        eprintln!("offline regex pilot: {reason}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn eof_and_unterminated_frames_differ() {
        assert!(frame(&mut Cursor::new(b"")).unwrap().is_none());
        assert!(frame(&mut Cursor::new(b"{}")).is_err());
        assert_eq!(
            frame(&mut Cursor::new(b"{}\n")).unwrap(),
            Some(b"{}\n".to_vec())
        );
    }

    #[test]
    fn separate_documents_never_complete_split_candidates() {
        let rule = Compiled {
            id: "local".into(),
            pattern: Regex::new(r"(?P<secret>abc123)").unwrap(),
            assignment: false,
        };
        let rules = vec![rule];
        for (id, text) in ["abc", "123", "abc123", ""].into_iter().enumerate() {
            let request = Request {
                schema: SCHEMA.into(),
                id: id as u64,
                text: text.into(),
            };
            let response = extract("catalog", &rules, &request).unwrap();
            assert_eq!(
                response.rules[0].captures.len(),
                usize::from(text == "abc123")
            );
        }
    }

    #[test]
    fn unsupported_inputs_and_candidate_overflow_are_errors() {
        let rules = vec![Compiled {
            id: "local".into(),
            pattern: Regex::new(r"(?P<secret>a)").unwrap(),
            assignment: false,
        }];
        for text in [
            "雪".into(),
            "a".repeat(MAX_TEXT + 1),
            "a".repeat(MAX_MATCHES + 1),
        ] {
            let request = Request {
                schema: SCHEMA.into(),
                id: 1,
                text,
            };
            assert!(extract("catalog", &rules, &request).is_err());
        }
    }

    #[test]
    fn protocol_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<Request>(r#"{"schema":"v1","id":1,"text":"","extra":0}"#)
                .is_err()
        );
    }
}
