//! Value-free metadata diagnostics after portable source schema validation.

use std::collections::BTreeSet;
use std::time::Instant;

use serde_json::{json, Value};

pub(super) fn validate(
    query: &str,
    value: &Value,
    deadline: Instant,
) -> Result<Value, &'static str> {
    let Some(rules) = value["spec"]["rules"].as_array() else {
        return Ok(Value::Null);
    };
    let mut ids = BTreeSet::new();
    for (index, rule) in rules.iter().enumerate() {
        if Instant::now() >= deadline {
            return Err("policy_document_deadline");
        }
        if query == "validate_ids" {
            if let Some(id) = rule["id"].as_str() {
                if !ids.insert(id) {
                    return Ok(
                        json!({"code":"duplicate_rule_id","path":["spec","rules",index,"id"]}),
                    );
                }
            }
        } else {
            for (parent, field) in [("lifetime", "expiresAt"), ("provenance", "createdAt")] {
                if let Some(stamp) = rule[parent][field].as_str() {
                    if !valid_calendar_prefix(stamp) {
                        return Ok(
                            json!({"code":"invalid_timestamp","path":["spec","rules",index,parent,field]}),
                        );
                    }
                }
            }
        }
    }
    Ok(Value::Null)
}

fn valid_calendar_prefix(value: &str) -> bool {
    let prefix = value.chars().take(19).collect::<Vec<_>>();
    if !matches!(prefix.len(), 10 | 19) || prefix[4] != '-' || prefix[7] != '-' {
        return false;
    }
    let number = |start, end| {
        prefix[start..end]
            .iter()
            .try_fold(0u32, |value, character| {
                character.to_digit(10).map(|digit| value * 10 + digit)
            })
    };
    let (Some(year), Some(month), Some(day)) = (number(0, 4), number(5, 7), number(8, 10)) else {
        return false;
    };
    if year == 0 {
        return false;
    }
    let days = match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => return false,
    };
    if day == 0 || day > days {
        return false;
    }
    if prefix.len() == 10 {
        return true;
    }
    if prefix[13] != ':' || prefix[16] != ':' {
        return false;
    }
    let (Some(hour), Some(minute), Some(second)) = (number(11, 13), number(14, 16), number(17, 19))
    else {
        return false;
    };
    hour < 24 && minute < 60 && second < 60
}
