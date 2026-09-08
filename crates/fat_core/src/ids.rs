/// Maximum length of the human-readable slug portion of an id. The full set of
/// components is always folded into the trailing hash (so uniqueness and
/// stability are preserved regardless of truncation); the slug is only a
/// readability aid and is capped so ids stay short and copyable even when a
/// component embeds a large descriptor (e.g. a full signal set).
const MAX_SLUG_CHARS: usize = 48;

/// Build a stable, collision-resistant id of the form
/// `{prefix}-{bounded-slug}-{hash}`. The hash is computed over *all* components,
/// so two different component sets always produce different ids even if their
/// truncated slugs coincide.
pub fn stable_prefixed_id<I, S>(prefix: &str, components: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut hasher = Fnv1a64::new();
    let mut parts = Vec::new();
    for component in components {
        let component = component.as_ref();
        hasher.update(component.as_bytes());
        hasher.update(&[0xff]);

        let slug = slug_component(component);
        if !slug.is_empty() {
            parts.push(slug);
        }
    }

    let hash = hasher.finish();
    let hash_suffix = format!("{hash:016x}");

    let slug = bounded_slug(&parts.join("-"));
    if slug.is_empty() {
        format!("{prefix}-{hash_suffix}")
    } else {
        format!("{prefix}-{slug}-{hash_suffix}")
    }
}

/// Truncate a slug to `MAX_SLUG_CHARS`, preferring a segment boundary so the id
/// doesn't end mid-token. Slugs are ASCII, so byte truncation is char-safe.
fn bounded_slug(slug: &str) -> String {
    if slug.len() <= MAX_SLUG_CHARS {
        return slug.to_string();
    }
    let mut cut = slug[..MAX_SLUG_CHARS].to_string();
    if let Some(idx) = cut.rfind('-') {
        if idx >= MAX_SLUG_CHARS / 2 {
            cut.truncate(idx);
        }
    }
    while cut.ends_with('-') {
        cut.pop();
    }
    cut
}

struct Fnv1a64(u64);

impl Fnv1a64 {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

fn slug_component(value: &str) -> String {
    let mut slug = String::new();
    let mut saw_separator = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            saw_separator = false;
        } else if !saw_separator && !slug.is_empty() {
            slug.push('-');
            saw_separator = true;
        }
    }

    while slug.ends_with('-') {
        slug.pop();
    }

    slug
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal_heavy() -> Vec<String> {
        (0..40)
            .map(|i| format!("uimage:name:some-long-signal-token-{i}"))
            .collect()
    }

    #[test]
    fn id_is_bounded_even_with_huge_components() {
        let signature = signal_heavy().join("|");
        let id = stable_prefixed_id("run", ["emulation-project", signature.as_str()]);
        // prefix (3) + '-' + slug (<=48) + '-' + 16 hex + separators.
        assert!(
            id.len() <= 3 + 1 + MAX_SLUG_CHARS + 1 + 16,
            "id too long: {id}"
        );
        assert!(id.starts_with("run-"));
    }

    #[test]
    fn id_is_stable_and_prefixed() {
        let a = stable_prefixed_id("recipe", ["p", "t", "armel"]);
        let b = stable_prefixed_id("recipe", ["p", "t", "armel"]);
        assert_eq!(a, b);
        assert!(a.starts_with("recipe-"));
        assert!(a.ends_with(&format!("{:016x}", {
            let mut h = Fnv1a64::new();
            for c in ["p", "t", "armel"] {
                h.update(c.as_bytes());
                h.update(&[0xff]);
            }
            h.finish()
        })));
    }

    #[test]
    fn different_components_differ_despite_truncated_slug() {
        // Two ids whose visible slug truncates to the same prefix must still
        // differ because the hash covers the full component set.
        let long_a = vec!["alpha"; 30].join("-");
        let long_b = format!("{long_a}-distinct-tail");
        let a = stable_prefixed_id("x", [long_a.as_str()]);
        let b = stable_prefixed_id("x", [long_b.as_str()]);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_components_still_produce_hashed_id() {
        let id = stable_prefixed_id("sess", Vec::<String>::new());
        assert!(id.starts_with("sess-"));
        assert_eq!(id.len(), "sess-".len() + 16);
    }
}
