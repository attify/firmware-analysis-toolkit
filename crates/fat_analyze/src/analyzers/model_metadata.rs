use std::collections::{BTreeMap, BTreeSet};

pub(crate) type ModelMetadata = BTreeMap<String, String>;

pub(crate) fn metadata(entries: impl IntoIterator<Item = (&'static str, String)>) -> ModelMetadata {
    entries
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

pub(crate) fn insert_if_present(
    metadata: &mut ModelMetadata,
    key: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        if !value.is_empty() {
            metadata.insert(key.to_string(), value);
        }
    }
}

pub(crate) fn join_limited(values: &[String], limit: usize) -> String {
    values
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn unique_limited(
    values: impl IntoIterator<Item = String>,
    limit: usize,
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        if value.is_empty() || !seen.insert(value.clone()) {
            continue;
        }
        out.push(value);
        if out.len() >= limit {
            break;
        }
    }
    out
}

pub(crate) fn printable_strings(data: &[u8], min_len: usize, limit: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for byte in data.iter().copied() {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'_' || byte == b'-' || byte == b'.' {
            current.push(byte);
            continue;
        }

        if current.len() >= min_len {
            if let Ok(value) = String::from_utf8(current.clone()) {
                strings.push(value);
                if strings.len() >= limit {
                    return strings;
                }
            }
        }
        current.clear();
    }

    if current.len() >= min_len {
        if let Ok(value) = String::from_utf8(current) {
            strings.push(value);
        }
    }

    strings
}

pub(crate) fn first_assignment_value(strings: &[String], key: &str) -> Option<String> {
    let prefixes = [format!("{key}="), format!("{key}:")];
    for value in strings {
        let trimmed = value.trim();
        for prefix in &prefixes {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                return Some(
                    rest.trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
        }
    }
    None
}
