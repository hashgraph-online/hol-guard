use super::*;

// ---------------------------------------------------------------------------
// `_normalize_inventory_datetime` — local mirror of the inventory_contract
// helper (UTC `Z` ISO-8601 emission, verbatim fallback on parse failure).
// ---------------------------------------------------------------------------

pub fn normalize_inventory_datetime(value: &Value) -> Value {
    let text = match value.as_str() {
        Some(t) if !t.trim().is_empty() => t,
        _ => return value.clone(),
    };
    parse_iso8601(text).map_or_else(|| value.clone(), Value::String)
}

pub(super) fn parse_iso8601(value: &str) -> Option<String> {
    let text = value.trim().replace(['Z', 'z'], "+00:00");
    let (date_part, time_part) = match text.split_once('T').or_else(|| text.split_once(' ')) {
        Some((d, t)) => (d, t),
        None => (text.as_str(), ""),
    };
    let mut date_seg = date_part.split('-');
    let year: i32 = date_seg.next()?.parse().ok()?;
    let month: i32 = date_seg.next()?.parse().ok()?;
    let day: i32 = date_seg.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if time_part.is_empty() {
        return Some(format!("{year:04}-{month:02}-{day:02}T00:00:00Z"));
    }
    let (time_core, tz) = split_iso8601_tz(time_part);
    let mut time_seg = time_core.split(':');
    let hour: i32 = time_seg.next()?.parse().ok()?;
    let minute: i32 = time_seg.next()?.parse().ok()?;
    let sec_raw = time_seg.next().unwrap_or("0");
    let (sec_s, frac_s) = sec_raw
        .split_once('.')
        .map_or((sec_raw, ""), |(s, f)| (s, f));
    let second: i32 = sec_s.parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let offset_minutes = match tz {
        Some(tz_raw) => {
            let sign = if tz_raw.starts_with('-') { -1 } else { 1 };
            let digits: String = tz_raw
                .chars()
                .skip(1)
                .filter(|c| c.is_ascii_digit())
                .collect();
            let (oh, om) = if digits.len() >= 4 {
                (
                    digits[..2].parse::<i32>().ok()?,
                    digits[2..4].parse::<i32>().ok()?,
                )
            } else if digits.len() == 2 {
                (digits.parse::<i32>().ok()?, 0)
            } else {
                (0, 0)
            };
            sign * (oh * 60 + om)
        }
        None => 0,
    };
    let total = hour * 3600 + minute * 60 + second - offset_minutes * 60;
    let (day_shift, secs) = if total < 0 {
        (-1, total + 86400)
    } else if total >= 86400 {
        (1, total - 86400)
    } else {
        (0, total)
    };
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (mut y, mut mo, mut d) = (year, month, day);
    if day_shift != 0 {
        let jd = days_from_civil(y, mo, d) + day_shift;
        let (ny, nmo, nd) = civil_from_days(jd);
        y = ny;
        mo = nmo;
        d = nd;
    }
    let frac = if frac_s.is_empty() {
        String::new()
    } else {
        let padded: String = frac_s
            .chars()
            .chain(std::iter::repeat('0'))
            .take(6)
            .collect();
        let micros: u32 = padded.parse().unwrap_or(0);
        if micros == 0 {
            String::new()
        } else {
            format!(".{micros:06}")
        }
    };
    Some(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}{frac}Z"))
}

pub(super) fn days_from_civil(y: i32, m: i32, d: i32) -> i32 {
    let ya = if m <= 2 { y - 1 } else { y };
    let era = if ya >= 0 { ya } else { ya - 399 } / 400;
    let yoe = ya - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub(super) fn civil_from_days(z: i32) -> (i32, i32, i32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub(super) fn split_iso8601_tz(time_part: &str) -> (&str, Option<&str>) {
    for (idx, ch) in time_part.char_indices() {
        if (ch == '+' || ch == '-') && idx > 0 {
            return (&time_part[..idx], Some(&time_part[idx..]));
        }
    }
    (time_part, None)
}
